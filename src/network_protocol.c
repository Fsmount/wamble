#include "../include/wamble/wamble.h"
void crypto_blake2b(uint8_t *hash, size_t hash_size, const uint8_t *msg,
                    size_t msg_size);
int ws_gateway_queue_packet(const struct sockaddr_in *cliaddr,
                            const uint8_t *packet, size_t packet_len);
int ws_gateway_is_ws_client(const struct sockaddr_in *cliaddr);

#if !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 201112L)
#ifndef HAVE_STRNLEN_DECL
#include <string.h>
static size_t wamble_local_strnlen(const char *s, size_t max) {
  size_t i = 0;
  if (!s)
    return 0;
  for (; i < max && s[i]; i++) {
  }
  return i;
}
#define strnlen wamble_local_strnlen
#endif
#endif

#pragma pack(push, 1)
typedef struct WambleHeader {
  uint8_t ctrl;
  uint8_t flags;
  uint8_t version;
  uint8_t reserved;
  uint8_t token[TOKEN_LENGTH];
  uint64_t board_id;
  uint32_t seq_num;
  uint16_t payload_len;
} WambleHeader;
#pragma pack(pop)

#define WAMBLE_HEADER_SIZE (sizeof(WambleHeader))
#define WAMBLE_PREDICTION_ENTRY_WIRE_SIZE                                      \
  (8 + 8 + TOKEN_LENGTH + 8 + 2 + 1 + 1 + 1 + MAX_UCI_LENGTH)
#define WAMBLE_PENDING_PACKET_CAP 64
#define WAMBLE_EXT_MAGIC_0 0x57
#define WAMBLE_EXT_MAGIC_1 0x58
#define WAMBLE_EXT_VERSION 1

typedef struct WambleClientSession {
  struct sockaddr_in addr;
  uint8_t token[TOKEN_LENGTH];
  uint32_t last_seq_num;
  time_t last_seen;
  uint32_t next_seq_num;
  char treatment_group_key[128];
} WambleClientSession;

static WAMBLE_THREAD_LOCAL WambleClientSession *client_sessions;
static WAMBLE_THREAD_LOCAL int num_sessions = 0;
static WAMBLE_THREAD_LOCAL uint32_t global_seq_num = 1;
static WAMBLE_THREAD_LOCAL uint32_t global_fragment_transfer_id = 1;

#define SESSION_MAP_SIZE (get_config()->max_client_sessions * 2)
static WAMBLE_THREAD_LOCAL int *session_index_map;

typedef struct PendingPacket {
  struct sockaddr_in addr;
  size_t len;
  uint8_t data[WAMBLE_MAX_PACKET_SIZE];
} PendingPacket;

static WAMBLE_THREAD_LOCAL PendingPacket *pending_packets = NULL;
static WAMBLE_THREAD_LOCAL int pending_packet_cap = 0;
static WAMBLE_THREAD_LOCAL int pending_packet_head = 0;
static WAMBLE_THREAD_LOCAL int pending_packet_count = 0;

static inline uint64_t mix64_s(uint64_t x) {
  x ^= x >> 33;
  x *= 0xff51afd7ed558ccdULL;
  x ^= x >> 33;
  x *= 0xc4ceb9fe1a85ec53ULL;
  x ^= x >> 33;
  return x;
}

static inline uint64_t addr_hash_key(const struct sockaddr_in *addr) {
  uint64_t ip = (uint64_t)addr->sin_addr.s_addr;
  uint64_t port = (uint64_t)addr->sin_port;
  return mix64_s((ip << 16) ^ port);
}

static int sockaddr_in_equal(const struct sockaddr_in *a,
                             const struct sockaddr_in *b) {
  if (!a || !b)
    return 0;
  return a->sin_addr.s_addr == b->sin_addr.s_addr && a->sin_port == b->sin_port;
}

static int session_map_capacity(void) {
  int cap = SESSION_MAP_SIZE;
  return cap > 0 ? cap : 0;
}

static int session_map_next(int idx, int cap) {
  idx++;
  if (idx >= cap)
    idx = 0;
  return idx;
}

static void session_map_init(void) {
  int cap = session_map_capacity();
  if (!session_index_map || cap <= 0)
    return;
  for (int i = 0; i < cap; i++)
    session_index_map[i] = -1;
}

static void session_map_put(const struct sockaddr_in *addr, int index) {
  int cap = session_map_capacity();
  if (!addr || !session_index_map || cap <= 0)
    return;
  uint64_t h = addr_hash_key(addr);
  int i = (int)(h % (uint64_t)cap);
  for (int probe = 0; probe < cap; probe++) {
    if (session_index_map[i] == -1) {
      session_index_map[i] = index;
      return;
    }
    int cur = session_index_map[i];
    if (cur >= 0) {
      const struct sockaddr_in *saddr = &client_sessions[cur].addr;
      if (sockaddr_in_equal(saddr, addr)) {
        session_index_map[i] = index;
        return;
      }
    }
    i = session_map_next(i, cap);
  }
}

static int session_map_get(const struct sockaddr_in *addr) {
  int cap = session_map_capacity();
  if (!addr || !session_index_map || cap <= 0)
    return -1;
  uint64_t h = addr_hash_key(addr);
  int i = (int)(h % (uint64_t)cap);
  for (int probe = 0; probe < cap; probe++) {
    int cur = session_index_map[i];
    if (cur == -1)
      return -1;
    if (cur >= 0) {
      const struct sockaddr_in *saddr = &client_sessions[cur].addr;
      if (sockaddr_in_equal(saddr, addr))
        return cur;
    }
    i = session_map_next(i, cap);
  }
  return -1;
}

static void pending_packets_release(void) {
  free(pending_packets);
  pending_packets = NULL;
  pending_packet_cap = 0;
  pending_packet_head = 0;
  pending_packet_count = 0;
}

static void pending_packets_reset(void) {
  if (pending_packet_cap > WAMBLE_PENDING_PACKET_CAP) {
    pending_packets_release();
    return;
  }
  pending_packet_head = 0;
  pending_packet_count = 0;
}

static int pending_packets_ensure_capacity(int need) {
  if (need <= 0)
    return 0;
  if (pending_packet_cap >= need && pending_packets)
    return 0;
  int new_cap =
      pending_packet_cap > 0 ? pending_packet_cap : WAMBLE_PENDING_PACKET_CAP;
  while (new_cap < need)
    new_cap *= 2;
  PendingPacket *new_packets =
      (PendingPacket *)calloc((size_t)new_cap, sizeof(*new_packets));
  if (!new_packets)
    return -1;
  for (int i = 0; i < pending_packet_count; i++) {
    int src = (pending_packet_head + i) % pending_packet_cap;
    new_packets[i] = pending_packets[src];
  }
  free(pending_packets);
  pending_packets = new_packets;
  pending_packet_cap = new_cap;
  pending_packet_head = 0;
  return 0;
}

static void pending_packet_push(const uint8_t *data, size_t len,
                                const struct sockaddr_in *addr) {
  if (!data || !addr || len == 0 || len > WAMBLE_MAX_PACKET_SIZE)
    return;
  if (pending_packets_ensure_capacity(pending_packet_count + 1) != 0)
    return;
  int slot = (pending_packet_head + pending_packet_count) % pending_packet_cap;
  pending_packets[slot].addr = *addr;
  pending_packets[slot].len = len;
  memcpy(pending_packets[slot].data, data, len);
  pending_packet_count++;
}

static int pending_packet_pop(uint8_t *data, size_t cap, size_t *out_len,
                              struct sockaddr_in *addr) {
  if (!data || !out_len || !addr || pending_packet_count <= 0)
    return 0;
  PendingPacket *pkt = &pending_packets[pending_packet_head];
  if (pkt->len > cap)
    return -1;
  memcpy(data, pkt->data, pkt->len);
  *out_len = pkt->len;
  *addr = pkt->addr;
  pending_packet_head = (pending_packet_head + 1) % pending_packet_cap;
  pending_packet_count--;
  if (pending_packet_count == 0 &&
      pending_packet_cap > WAMBLE_PENDING_PACKET_CAP)
    pending_packets_release();
  return 1;
}

static int ctrl_is_supported(uint8_t ctrl) {
  switch (ctrl) {
  case WAMBLE_CTRL_CLIENT_HELLO:
  case WAMBLE_CTRL_SERVER_HELLO:
  case WAMBLE_CTRL_PLAYER_MOVE:
  case WAMBLE_CTRL_BOARD_UPDATE:
  case WAMBLE_CTRL_ACK:
  case WAMBLE_CTRL_LIST_PROFILES:
  case WAMBLE_CTRL_GET_PREDICTIONS:
  case WAMBLE_CTRL_SUBMIT_PREDICTION:
  case WAMBLE_CTRL_PREDICTION_DATA:
  case WAMBLE_CTRL_PROFILE_INFO:
  case WAMBLE_CTRL_GET_PROFILE_INFO:
  case WAMBLE_CTRL_PROFILES_LIST:
  case WAMBLE_CTRL_ERROR:
  case WAMBLE_CTRL_SERVER_NOTIFICATION:
  case WAMBLE_CTRL_CLIENT_GOODBYE:
  case WAMBLE_CTRL_SPECTATE_GAME:
  case WAMBLE_CTRL_SPECTATE_STOP:
  case WAMBLE_CTRL_SPECTATE_UPDATE:
  case WAMBLE_CTRL_LOGIN_REQUEST:
  case WAMBLE_CTRL_LOGOUT:
  case WAMBLE_CTRL_LOGIN_SUCCESS:
  case WAMBLE_CTRL_LOGIN_FAILED:
  case WAMBLE_CTRL_LOGIN_CHALLENGE:
  case WAMBLE_CTRL_GET_PLAYER_STATS:
  case WAMBLE_CTRL_PLAYER_STATS_DATA:
  case WAMBLE_CTRL_GET_LEGAL_MOVES:
  case WAMBLE_CTRL_LEGAL_MOVES:
  case WAMBLE_CTRL_GET_LEADERBOARD:
  case WAMBLE_CTRL_LEADERBOARD_DATA:
  case WAMBLE_CTRL_GET_PROFILE_TOS:
  case WAMBLE_CTRL_PROFILE_TOS_DATA:
    return 1;
  default:
    return 0;
  }
}

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
static inline uint64_t host_to_net64(uint64_t x) { return x; }
static inline uint64_t net_to_host64(uint64_t x) { return x; }
#else
static inline uint64_t host_to_net64(uint64_t x) {
  uint32_t hi = (uint32_t)(x >> 32);
  uint32_t lo = (uint32_t)(x & 0xffffffffu);
  uint64_t n = ((uint64_t)htonl(lo) << 32) | htonl(hi);
  return n;
}
static inline uint64_t net_to_host64(uint64_t x) {
  uint32_t hi = (uint32_t)(x >> 32);
  uint32_t lo = (uint32_t)(x & 0xffffffffu);
  uint64_t h = ((uint64_t)ntohl(lo) << 32) | ntohl(hi);
  return h;
}
#endif

static NetworkStatus encode_msg_extensions(const struct WambleMsg *msg,
                                           uint8_t *dst, size_t cap,
                                           size_t *out_len) {
  if (!dst || !out_len)
    return NET_ERR_INVALID;
  *out_len = 0;
  if (!msg || msg->ext_count == 0)
    return NET_OK;

  size_t off = 0;
  if (cap < 2)
    return NET_ERR_TRUNCATED;
  dst[off++] = WAMBLE_EXT_VERSION;
  size_t count_pos = off++;
  uint8_t written = 0;

  for (uint8_t i = 0; i < msg->ext_count; i++) {
    const WambleMessageExtField *field = &msg->ext[i];
    size_t key_len = strnlen(field->key, WAMBLE_MESSAGE_EXT_KEY_MAX);
    if (key_len == 0 || key_len > 255)
      continue;
    if (field->value_type != WAMBLE_TREATMENT_VALUE_STRING &&
        field->value_type != WAMBLE_TREATMENT_VALUE_INT &&
        field->value_type != WAMBLE_TREATMENT_VALUE_DOUBLE &&
        field->value_type != WAMBLE_TREATMENT_VALUE_BOOL) {
      continue;
    }

    if (off + 1 + key_len + 1 > cap)
      return NET_ERR_TRUNCATED;
    dst[off++] = (uint8_t)key_len;
    memcpy(dst + off, field->key, key_len);
    off += key_len;
    dst[off++] = (uint8_t)field->value_type;

    if (field->value_type == WAMBLE_TREATMENT_VALUE_STRING) {
      size_t slen =
          strnlen(field->string_value, WAMBLE_MESSAGE_EXT_STRING_MAX - 1);
      if (off + 2 + slen > cap)
        return NET_ERR_TRUNCATED;
      uint16_t sbe = htons((uint16_t)slen);
      memcpy(dst + off, &sbe, 2);
      off += 2;
      if (slen) {
        memcpy(dst + off, field->string_value, slen);
        off += slen;
      }
    } else if (field->value_type == WAMBLE_TREATMENT_VALUE_INT) {
      if (off + 8 > cap)
        return NET_ERR_TRUNCATED;
      uint64_t ibe = host_to_net64((uint64_t)field->int_value);
      memcpy(dst + off, &ibe, 8);
      off += 8;
    } else if (field->value_type == WAMBLE_TREATMENT_VALUE_DOUBLE) {
      if (off + 8 > cap)
        return NET_ERR_TRUNCATED;
      uint64_t bits = 0;
      memcpy(&bits, &field->double_value, sizeof(bits));
      bits = host_to_net64(bits);
      memcpy(dst + off, &bits, 8);
      off += 8;
    } else if (field->value_type == WAMBLE_TREATMENT_VALUE_BOOL) {
      if (off + 1 > cap)
        return NET_ERR_TRUNCATED;
      dst[off++] = (uint8_t)(field->bool_value ? 1 : 0);
    }
    written++;
  }

  if (written == 0)
    return NET_OK;
  dst[count_pos] = written;
  size_t body_len = off;
  if (off + 4 > cap)
    return NET_ERR_TRUNCATED;
  dst[off++] = WAMBLE_EXT_MAGIC_0;
  dst[off++] = WAMBLE_EXT_MAGIC_1;
  uint16_t body_be = htons((uint16_t)body_len);
  memcpy(dst + off, &body_be, 2);
  off += 2;
  *out_len = off;
  return NET_OK;
}

static NetworkStatus decode_msg_extensions(const uint8_t *payload,
                                           size_t payload_len,
                                           struct WambleMsg *msg,
                                           size_t *out_base_len) {
  if (!payload || !msg || !out_base_len)
    return NET_ERR_INVALID;
  msg->ext_count = 0;
  *out_base_len = payload_len;
  if (payload_len < 4)
    return NET_ERR_INVALID;
  if (payload[payload_len - 4] != WAMBLE_EXT_MAGIC_0 ||
      payload[payload_len - 3] != WAMBLE_EXT_MAGIC_1) {
    return NET_ERR_INVALID;
  }

  uint16_t body_be = 0;
  memcpy(&body_be, payload + payload_len - 2, 2);
  size_t body_len = (size_t)ntohs(body_be);
  if (body_len < 2 || body_len > payload_len - 4)
    return NET_ERR_INVALID;
  size_t body_start = payload_len - 4 - body_len;
  const uint8_t *p = payload + body_start;
  const uint8_t *end = p + body_len;

  if (p[0] != WAMBLE_EXT_VERSION)
    return NET_ERR_INVALID;
  uint8_t count = p[1];
  p += 2;

  uint8_t parsed = 0;
  while (p < end && parsed < count && parsed < WAMBLE_MAX_MESSAGE_EXT_FIELDS) {
    if ((size_t)(end - p) < 2)
      return NET_ERR_INVALID;
    uint8_t key_len = *p++;
    if (key_len == 0 || (size_t)(end - p) < (size_t)key_len + 1)
      return NET_ERR_INVALID;
    WambleMessageExtField *field = &msg->ext[parsed];
    memset(field, 0, sizeof(*field));
    memcpy(field->key, p, key_len);
    field->key[key_len] = '\0';
    p += key_len;
    field->value_type = (WambleTreatmentValueType)(*p++);

    if (field->value_type == WAMBLE_TREATMENT_VALUE_STRING) {
      if ((size_t)(end - p) < 2)
        return NET_ERR_INVALID;
      uint16_t slen_be = 0;
      memcpy(&slen_be, p, 2);
      p += 2;
      size_t slen = (size_t)ntohs(slen_be);
      if ((size_t)(end - p) < slen)
        return NET_ERR_INVALID;
      size_t copy = slen;
      if (copy > WAMBLE_MESSAGE_EXT_STRING_MAX - 1)
        copy = WAMBLE_MESSAGE_EXT_STRING_MAX - 1;
      if (copy)
        memcpy(field->string_value, p, copy);
      field->string_value[copy] = '\0';
      p += slen;
    } else if (field->value_type == WAMBLE_TREATMENT_VALUE_INT) {
      if ((size_t)(end - p) < 8)
        return NET_ERR_INVALID;
      uint64_t ibe = 0;
      memcpy(&ibe, p, 8);
      p += 8;
      field->int_value = (int64_t)net_to_host64(ibe);
    } else if (field->value_type == WAMBLE_TREATMENT_VALUE_DOUBLE) {
      if ((size_t)(end - p) < 8)
        return NET_ERR_INVALID;
      uint64_t bits = 0;
      memcpy(&bits, p, 8);
      p += 8;
      bits = net_to_host64(bits);
      memcpy(&field->double_value, &bits, sizeof(bits));
    } else if (field->value_type == WAMBLE_TREATMENT_VALUE_BOOL) {
      if ((size_t)(end - p) < 1)
        return NET_ERR_INVALID;
      field->bool_value = (*p++ != 0) ? 1 : 0;
    } else {
      return NET_ERR_INVALID;
    }
    parsed++;
  }

  if (parsed != count || p != end)
    return NET_ERR_INVALID;
  msg->ext_count = parsed;
  *out_base_len = body_start;
  return NET_OK;
}

static int ctrl_supports_fragment_payload(uint8_t ctrl) {
  switch (ctrl) {
  case WAMBLE_CTRL_SERVER_HELLO:
  case WAMBLE_CTRL_BOARD_UPDATE:
  case WAMBLE_CTRL_PROFILE_INFO:
  case WAMBLE_CTRL_ERROR:
  case WAMBLE_CTRL_SERVER_NOTIFICATION:
  case WAMBLE_CTRL_SPECTATE_UPDATE:
  case WAMBLE_CTRL_LOGIN_CHALLENGE:
  case WAMBLE_CTRL_LOGIN_FAILED:
  case WAMBLE_CTRL_PLAYER_STATS_DATA:
  case WAMBLE_CTRL_PROFILES_LIST:
  case WAMBLE_CTRL_LEGAL_MOVES:
  case WAMBLE_CTRL_LEADERBOARD_DATA:
  case WAMBLE_CTRL_PREDICTION_DATA:
  case WAMBLE_CTRL_PROFILE_TOS_DATA:
    return 1;
  default:
    return 0;
  }
}

static uint32_t next_fragment_transfer_id(void) {
  uint32_t id = global_fragment_transfer_id++;
  if (id == 0) {
    global_fragment_transfer_id = 2;
    id = 1;
  }
  return id;
}

static int msg_uses_fragment_payload(const struct WambleMsg *msg) {
  if (!msg)
    return 0;
  return (msg->fragment_version == WAMBLE_FRAGMENT_VERSION) ||
         (msg->fragment_chunk_count > 0) || (msg->fragment_total_len > 0) ||
         (msg->fragment_data_len > 0);
}

static NetworkStatus encode_fragment_payload(const struct WambleMsg *msg,
                                             uint8_t *payload,
                                             size_t payload_capacity,
                                             size_t *payload_len) {
  if (!msg || !payload || !payload_len)
    return NET_ERR_INVALID;
  if (msg->fragment_version != WAMBLE_FRAGMENT_VERSION)
    return NET_ERR_INVALID;
  if (msg->fragment_hash_algo != WAMBLE_FRAGMENT_HASH_BLAKE2B_256)
    return NET_ERR_INVALID;
  if (msg->fragment_chunk_count == 0 ||
      msg->fragment_chunk_index >= msg->fragment_chunk_count)
    return NET_ERR_INVALID;
  if (msg->fragment_data_len > WAMBLE_FRAGMENT_DATA_MAX)
    return NET_ERR_INVALID;
  size_t chunk_len = (size_t)msg->fragment_data_len;
  size_t need = WAMBLE_FRAGMENT_WIRE_HEADER_LENGTH + chunk_len;
  if (need > payload_capacity)
    return NET_ERR_TRUNCATED;

  payload[0] = WAMBLE_FRAGMENT_VERSION;
  payload[1] = WAMBLE_FRAGMENT_HASH_BLAKE2B_256;
  uint16_t idx_be = htons(msg->fragment_chunk_index);
  uint16_t count_be = htons(msg->fragment_chunk_count);
  uint32_t total_be = htonl(msg->fragment_total_len);
  uint32_t transfer_id_be = htonl(msg->fragment_transfer_id);
  uint16_t len_be = htons(msg->fragment_data_len);
  memcpy(payload + 2, &idx_be, 2);
  memcpy(payload + 4, &count_be, 2);
  memcpy(payload + 6, &total_be, 4);
  memcpy(payload + 10, &transfer_id_be, 4);
  memcpy(payload + 14, msg->fragment_hash, WAMBLE_FRAGMENT_HASH_LENGTH);
  memcpy(payload + 14 + WAMBLE_FRAGMENT_HASH_LENGTH, &len_be, 2);
  if (chunk_len)
    memcpy(payload + WAMBLE_FRAGMENT_WIRE_HEADER_LENGTH, msg->fragment_data,
           chunk_len);
  *payload_len = need;
  return NET_OK;
}

static NetworkStatus decode_fragment_payload(const uint8_t *payload,
                                             size_t payload_len,
                                             struct WambleMsg *msg,
                                             int *is_fragmented) {
  if (!payload || !msg || !is_fragmented)
    return NET_ERR_INVALID;
  *is_fragmented = 0;
  if (payload_len < WAMBLE_FRAGMENT_WIRE_HEADER_LENGTH ||
      payload[0] != WAMBLE_FRAGMENT_VERSION) {
    return NET_OK;
  }

  uint8_t hash_algo = payload[1];
  uint16_t chunk_index_be = 0;
  uint16_t chunk_count_be = 0;
  uint32_t total_be = 0;
  uint32_t transfer_id_be = 0;
  uint16_t chunk_len_be = 0;
  memcpy(&chunk_index_be, payload + 2, 2);
  memcpy(&chunk_count_be, payload + 4, 2);
  memcpy(&total_be, payload + 6, 4);
  memcpy(&transfer_id_be, payload + 10, 4);
  memcpy(msg->fragment_hash, payload + 14, WAMBLE_FRAGMENT_HASH_LENGTH);
  memcpy(&chunk_len_be, payload + 14 + WAMBLE_FRAGMENT_HASH_LENGTH, 2);
  msg->fragment_version = WAMBLE_FRAGMENT_VERSION;
  msg->fragment_hash_algo = hash_algo;
  msg->fragment_chunk_index = ntohs(chunk_index_be);
  msg->fragment_chunk_count = ntohs(chunk_count_be);
  msg->fragment_total_len = ntohl(total_be);
  msg->fragment_transfer_id = ntohl(transfer_id_be);
  if (msg->fragment_hash_algo != WAMBLE_FRAGMENT_HASH_BLAKE2B_256)
    return NET_ERR_INVALID;
  size_t chunk_len = (size_t)ntohs(chunk_len_be);
  if (msg->fragment_chunk_count == 0 ||
      msg->fragment_chunk_index >= msg->fragment_chunk_count)
    return NET_ERR_INVALID;
  if (chunk_len > WAMBLE_FRAGMENT_DATA_MAX)
    return NET_ERR_INVALID;
  if (payload_len != WAMBLE_FRAGMENT_WIRE_HEADER_LENGTH + chunk_len)
    return NET_ERR_INVALID;
  if (chunk_len) {
    memcpy(msg->fragment_data, payload + WAMBLE_FRAGMENT_WIRE_HEADER_LENGTH,
           chunk_len);
  }
  msg->fragment_data_len = (uint16_t)chunk_len;
  *is_fragmented = 1;
  return NET_OK;
}

void wamble_fragment_reassembly_init(WambleFragmentReassembly *reassembly) {
  if (!reassembly)
    return;
  memset(reassembly, 0, sizeof(*reassembly));
  reassembly->integrity = WAMBLE_FRAGMENT_INTEGRITY_UNKNOWN;
}

void wamble_fragment_reassembly_reset(WambleFragmentReassembly *reassembly) {
  if (!reassembly)
    return;
  reassembly->active = 0;
  reassembly->ctrl = 0;
  reassembly->hash_algo = 0;
  reassembly->chunk_count = 0;
  reassembly->received_chunks = 0;
  reassembly->total_len = 0;
  reassembly->transfer_id = 0;
  memset(reassembly->expected_hash, 0, WAMBLE_FRAGMENT_HASH_LENGTH);
  reassembly->integrity = WAMBLE_FRAGMENT_INTEGRITY_UNKNOWN;
  if (reassembly->chunk_seen && reassembly->chunk_seen_capacity > 0)
    memset(reassembly->chunk_seen, 0, reassembly->chunk_seen_capacity);
}

void wamble_fragment_reassembly_free(WambleFragmentReassembly *reassembly) {
  if (!reassembly)
    return;
  free(reassembly->data);
  free(reassembly->chunk_seen);
  wamble_fragment_reassembly_init(reassembly);
}

static int reassembly_ensure_capacity(uint8_t **buf, size_t *capacity,
                                      size_t needed, int zero_new_region) {
  if (!buf || !capacity)
    return -1;
  if (needed <= *capacity)
    return 0;
  size_t next_capacity = (*capacity > 0) ? *capacity : 64;
  while (next_capacity < needed) {
    if (next_capacity > (SIZE_MAX / 2)) {
      next_capacity = needed;
      break;
    }
    next_capacity *= 2;
  }
  uint8_t *next = (uint8_t *)realloc(*buf, next_capacity);
  if (!next)
    return -1;
  if (zero_new_region && next_capacity > *capacity)
    memset(next + *capacity, 0, next_capacity - *capacity);
  *buf = next;
  *capacity = next_capacity;
  return 0;
}

static int reassembly_fragment_shape_valid(const struct WambleMsg *msg,
                                           size_t *out_offset,
                                           size_t *out_len) {
  if (!msg || !out_offset || !out_len)
    return 0;
  if (msg->fragment_chunk_count == 0 ||
      msg->fragment_chunk_index >= msg->fragment_chunk_count)
    return 0;
  if (msg->fragment_data_len > WAMBLE_FRAGMENT_DATA_MAX)
    return 0;
  size_t total_len = (size_t)msg->fragment_total_len;
  size_t offset =
      (size_t)msg->fragment_chunk_index * (size_t)WAMBLE_FRAGMENT_DATA_MAX;
  size_t len = (size_t)msg->fragment_data_len;
  if (offset > total_len)
    return 0;
  if (len > total_len - offset)
    return 0;
  size_t expected_len = total_len - offset;
  if (expected_len > (size_t)WAMBLE_FRAGMENT_DATA_MAX)
    expected_len = (size_t)WAMBLE_FRAGMENT_DATA_MAX;
  if (len != expected_len)
    return 0;
  *out_offset = offset;
  *out_len = len;
  return 1;
}

static int reassembly_begin_transfer(WambleFragmentReassembly *reassembly,
                                     const struct WambleMsg *msg) {
  if (!reassembly || !msg)
    return -1;
  size_t total_len = (size_t)msg->fragment_total_len;
  size_t chunk_count = (size_t)msg->fragment_chunk_count;
  if (reassembly_ensure_capacity(&reassembly->data, &reassembly->data_capacity,
                                 total_len, 0) != 0) {
    return -1;
  }
  if (reassembly_ensure_capacity(&reassembly->chunk_seen,
                                 &reassembly->chunk_seen_capacity, chunk_count,
                                 1) != 0) {
    return -1;
  }

  memset(reassembly->chunk_seen, 0, chunk_count);
  reassembly->active = 1;
  reassembly->ctrl = msg->ctrl;
  reassembly->hash_algo = msg->fragment_hash_algo;
  reassembly->chunk_count = msg->fragment_chunk_count;
  reassembly->received_chunks = 0;
  reassembly->total_len = msg->fragment_total_len;
  reassembly->transfer_id = msg->fragment_transfer_id;
  memcpy(reassembly->expected_hash, msg->fragment_hash,
         WAMBLE_FRAGMENT_HASH_LENGTH);
  reassembly->integrity = WAMBLE_FRAGMENT_INTEGRITY_UNKNOWN;
  return 0;
}

WambleFragmentReassemblyResult
wamble_fragment_reassembly_push(WambleFragmentReassembly *reassembly,
                                const struct WambleMsg *msg) {
  if (!reassembly || !msg)
    return WAMBLE_FRAGMENT_REASSEMBLY_ERR_INVALID;
  if (!ctrl_supports_fragment_payload(msg->ctrl))
    return WAMBLE_FRAGMENT_REASSEMBLY_IGNORED;
  if (msg->fragment_version != WAMBLE_FRAGMENT_VERSION)
    return WAMBLE_FRAGMENT_REASSEMBLY_IGNORED;
  if (msg->fragment_hash_algo != WAMBLE_FRAGMENT_HASH_BLAKE2B_256)
    return WAMBLE_FRAGMENT_REASSEMBLY_ERR_INVALID;

  size_t offset = 0;
  size_t len = 0;
  if (!reassembly_fragment_shape_valid(msg, &offset, &len))
    return WAMBLE_FRAGMENT_REASSEMBLY_ERR_INVALID;

  int same_transfer = reassembly->active && reassembly->ctrl == msg->ctrl &&
                      reassembly->hash_algo == msg->fragment_hash_algo &&
                      reassembly->chunk_count == msg->fragment_chunk_count &&
                      reassembly->total_len == msg->fragment_total_len &&
                      reassembly->transfer_id == msg->fragment_transfer_id &&
                      memcmp(reassembly->expected_hash, msg->fragment_hash,
                             WAMBLE_FRAGMENT_HASH_LENGTH) == 0;
  if (!same_transfer) {
    if (reassembly_begin_transfer(reassembly, msg) != 0)
      return WAMBLE_FRAGMENT_REASSEMBLY_ERR_NOMEM;
  }

  uint16_t idx = msg->fragment_chunk_index;
  if (reassembly->chunk_seen[idx]) {
    if (len &&
        memcmp(reassembly->data + offset, msg->fragment_data, len) != 0) {
      return WAMBLE_FRAGMENT_REASSEMBLY_ERR_INVALID;
    }
  } else {
    if (len)
      memcpy(reassembly->data + offset, msg->fragment_data, len);
    reassembly->chunk_seen[idx] = 1;
    reassembly->received_chunks++;
  }

  if (reassembly->received_chunks < reassembly->chunk_count)
    return WAMBLE_FRAGMENT_REASSEMBLY_IN_PROGRESS;

  uint8_t computed_hash[WAMBLE_FRAGMENT_HASH_LENGTH] = {0};
  static const uint8_t empty_payload[1] = {0};
  const uint8_t *hash_input =
      reassembly->data ? reassembly->data : empty_payload;
  crypto_blake2b(computed_hash, WAMBLE_FRAGMENT_HASH_LENGTH, hash_input,
                 (size_t)reassembly->total_len);
  if (memcmp(computed_hash, reassembly->expected_hash,
             WAMBLE_FRAGMENT_HASH_LENGTH) == 0) {
    reassembly->integrity = WAMBLE_FRAGMENT_INTEGRITY_OK;
    return WAMBLE_FRAGMENT_REASSEMBLY_COMPLETE;
  }
  reassembly->integrity = WAMBLE_FRAGMENT_INTEGRITY_MISMATCH;
  return WAMBLE_FRAGMENT_REASSEMBLY_COMPLETE_BAD_HASH;
}

static NetworkStatus encode_message_payload(const struct WambleMsg *msg,
                                            uint8_t *payload,
                                            size_t payload_capacity,
                                            size_t *payload_len,
                                            int *out_has_ext) {
  if (!msg || !payload || !payload_len)
    return NET_ERR_INVALID;
  if (ctrl_supports_fragment_payload(msg->ctrl) &&
      msg_uses_fragment_payload(msg)) {
    if (msg->ext_count > 0)
      return NET_ERR_INVALID;
    size_t fragment_len = 0;
    NetworkStatus frag_status =
        encode_fragment_payload(msg, payload, payload_capacity, &fragment_len);
    if (frag_status != NET_OK)
      return frag_status;
    *payload_len = fragment_len;
    if (out_has_ext)
      *out_has_ext = 0;
    return NET_OK;
  }
  size_t body_len = 0;
  switch (msg->ctrl) {
  case WAMBLE_CTRL_CLIENT_HELLO:
  case WAMBLE_CTRL_ACK:
  case WAMBLE_CTRL_LIST_PROFILES:
  case WAMBLE_CTRL_CLIENT_GOODBYE:
  case WAMBLE_CTRL_LOGOUT:
  case WAMBLE_CTRL_GET_PLAYER_STATS:
  case WAMBLE_CTRL_SPECTATE_STOP:
  case WAMBLE_CTRL_SPECTATE_GAME:
    body_len = 0;
    break;
  case WAMBLE_CTRL_GET_LEADERBOARD:
    if (payload_capacity < 2)
      return NET_ERR_TRUNCATED;
    payload[0] = msg->leaderboard_type ? msg->leaderboard_type
                                       : WAMBLE_LEADERBOARD_SCORE;
    payload[1] = msg->leaderboard_limit ? msg->leaderboard_limit : 10;
    body_len = 2;
    break;
  case WAMBLE_CTRL_GET_PREDICTIONS:
    if (payload_capacity < 2)
      return NET_ERR_TRUNCATED;
    payload[0] = msg->prediction_depth;
    payload[1] = msg->prediction_limit;
    body_len = 2;
    break;
  case WAMBLE_CTRL_PLAYER_MOVE: {
    size_t need = 1 + (size_t)msg->uci_len;
    if (need > payload_capacity)
      return NET_ERR_TRUNCATED;
    payload[0] = msg->uci_len;
    if (msg->uci_len)
      memcpy(&payload[1], msg->uci, msg->uci_len);
    body_len = need;
    break;
  }
  case WAMBLE_CTRL_SUBMIT_PREDICTION: {
    size_t need = 1 + (size_t)msg->uci_len + 8;
    if (need > payload_capacity)
      return NET_ERR_TRUNCATED;
    payload[0] = msg->uci_len;
    if (msg->uci_len)
      memcpy(&payload[1], msg->uci, msg->uci_len);
    uint64_t parent_be = host_to_net64(msg->prediction_parent_id);
    memcpy(&payload[1 + msg->uci_len], &parent_be, 8);
    body_len = need;
    break;
  }
  case WAMBLE_CTRL_SERVER_HELLO:
  case WAMBLE_CTRL_BOARD_UPDATE:
  case WAMBLE_CTRL_SERVER_NOTIFICATION:
  case WAMBLE_CTRL_SPECTATE_UPDATE: {
    size_t len = strnlen(msg->fen, FEN_MAX_LENGTH);
    if (len > payload_capacity)
      return NET_ERR_TRUNCATED;
    if (len)
      memcpy(payload, msg->fen, len);
    body_len = len;
    break;
  }
  case WAMBLE_CTRL_PROFILE_INFO: {
    size_t len = msg->profile_info_len
                     ? (size_t)msg->profile_info_len
                     : strnlen(msg->profile_info, FEN_MAX_LENGTH);
    if (len > FEN_MAX_LENGTH - 1)
      return NET_ERR_INVALID;
    if (len > payload_capacity)
      return NET_ERR_TRUNCATED;
    if (len)
      memcpy(payload, msg->profile_info, len);
    body_len = len;
    break;
  }
  case WAMBLE_CTRL_PROFILE_TOS_DATA: {
    size_t len = msg->profile_info_len
                     ? (size_t)msg->profile_info_len
                     : strnlen(msg->profile_info, FEN_MAX_LENGTH);
    if (len > FEN_MAX_LENGTH - 1)
      return NET_ERR_INVALID;
    if (len > payload_capacity)
      return NET_ERR_TRUNCATED;
    if (len)
      memcpy(payload, msg->profile_info, len);
    body_len = len;
    break;
  }
  case WAMBLE_CTRL_GET_PROFILE_INFO:
  case WAMBLE_CTRL_GET_PROFILE_TOS: {
    size_t name_len =
        msg->profile_name_len
            ? (size_t)msg->profile_name_len
            : strnlen(msg->profile_name, PROFILE_NAME_MAX_LENGTH - 1);
    if (name_len > 255)
      return NET_ERR_INVALID;
    size_t need = 1 + name_len;
    if (need > payload_capacity)
      return NET_ERR_TRUNCATED;
    payload[0] = (uint8_t)name_len;
    if (name_len)
      memcpy(&payload[1], msg->profile_name, name_len);
    body_len = need;
    break;
  }
  case WAMBLE_CTRL_GET_LEGAL_MOVES:
    if (payload_capacity < 1)
      return NET_ERR_TRUNCATED;
    payload[0] = msg->move_square;
    body_len = 1;
    break;
  case WAMBLE_CTRL_PROFILES_LIST: {
    size_t len = msg->profiles_list_len
                     ? (size_t)msg->profiles_list_len
                     : strnlen(msg->profiles_list, FEN_MAX_LENGTH);
    if (len > FEN_MAX_LENGTH - 1)
      return NET_ERR_INVALID;
    if (len > payload_capacity)
      return NET_ERR_TRUNCATED;
    if (len)
      memcpy(payload, msg->profiles_list, len);
    body_len = len;
    break;
  }
  case WAMBLE_CTRL_LEGAL_MOVES: {
    if (msg->move_count > WAMBLE_MAX_LEGAL_MOVES)
      return NET_ERR_INVALID;
    size_t need = 2 + (size_t)msg->move_count * 3;
    if (need > payload_capacity)
      return NET_ERR_TRUNCATED;
    payload[0] = msg->move_square;
    payload[1] = msg->move_count;
    size_t offset = 2;
    for (uint8_t i = 0; i < msg->move_count; i++) {
      payload[offset++] = msg->moves[i].from;
      payload[offset++] = msg->moves[i].to;
      payload[offset++] = (uint8_t)msg->moves[i].promotion;
    }
    body_len = need;
    break;
  }
  case WAMBLE_CTRL_ERROR:
  case WAMBLE_CTRL_LOGIN_FAILED: {
    uint16_t code_net = htons(msg->error_code);
    size_t reason_len = strnlen(msg->error_reason, FEN_MAX_LENGTH);
    if (reason_len > 255)
      reason_len = 255;
    size_t need = 3 + reason_len;
    if (need > payload_capacity)
      return NET_ERR_TRUNCATED;
    payload[0] = (uint8_t)(code_net >> 8);
    payload[1] = (uint8_t)(code_net & 0xFF);
    payload[2] = (uint8_t)reason_len;
    if (reason_len)
      memcpy(&payload[3], msg->error_reason, reason_len);
    body_len = need;
    break;
  }
  case WAMBLE_CTRL_LOGIN_REQUEST: {
    size_t need = WAMBLE_PUBLIC_KEY_LENGTH;
    if (msg->login_has_signature)
      need += WAMBLE_LOGIN_SIGNATURE_LENGTH;
    if (need > payload_capacity)
      return NET_ERR_TRUNCATED;
    memcpy(payload, msg->login_pubkey, WAMBLE_PUBLIC_KEY_LENGTH);
    if (msg->login_has_signature) {
      memcpy(payload + WAMBLE_PUBLIC_KEY_LENGTH, msg->login_signature,
             WAMBLE_LOGIN_SIGNATURE_LENGTH);
    }
    body_len = need;
    break;
  }
  case WAMBLE_CTRL_LOGIN_CHALLENGE:
    if (WAMBLE_LOGIN_CHALLENGE_LENGTH > payload_capacity)
      return NET_ERR_TRUNCATED;
    memcpy(payload, msg->login_challenge, WAMBLE_LOGIN_CHALLENGE_LENGTH);
    body_len = WAMBLE_LOGIN_CHALLENGE_LENGTH;
    break;
  case WAMBLE_CTRL_PLAYER_STATS_DATA:
    if (payload_capacity < 16)
      return NET_ERR_TRUNCATED;
    {
      uint64_t bits = 0;
      memcpy(&bits, &msg->player_stats_score, sizeof(double));
      uint64_t be = host_to_net64(bits);
      for (int i = 0; i < 8; i++) {
        payload[i] = (uint8_t)((be >> (8 * (7 - i))) & 0xFF);
      }
      uint32_t gp_be = htonl(msg->player_stats_games_played);
      memcpy(payload + 8, &gp_be, 4);
      uint32_t c960_be = htonl(msg->player_stats_chess960_games_played);
      memcpy(payload + 12, &c960_be, 4);
      body_len = 16;
    }
    break;
  case WAMBLE_CTRL_LEADERBOARD_DATA: {
    uint8_t count = msg->leaderboard_count;
    if (count > WAMBLE_MAX_LEADERBOARD_ENTRIES)
      return NET_ERR_INVALID;
    size_t need = 1 + 1 + 4 + (size_t)count * 32;
    if (need > payload_capacity)
      return NET_ERR_TRUNCATED;
    payload[0] = msg->leaderboard_type ? msg->leaderboard_type
                                       : WAMBLE_LEADERBOARD_SCORE;
    payload[1] = count;
    uint32_t self_rank_be = htonl(msg->leaderboard_self_rank);
    memcpy(payload + 2, &self_rank_be, 4);
    size_t offset = 6;
    for (uint8_t i = 0; i < count; i++) {
      const WambleLeaderboardEntry *e = &msg->leaderboard[i];
      uint32_t rank_be = htonl(e->rank);
      uint64_t sid_be = host_to_net64(e->session_id);
      uint64_t score_bits = 0;
      uint64_t rating_bits = 0;
      memcpy(&score_bits, &e->score, sizeof(double));
      memcpy(&rating_bits, &e->rating, sizeof(double));
      score_bits = host_to_net64(score_bits);
      rating_bits = host_to_net64(rating_bits);
      uint32_t games_be = htonl(e->games_played);
      memcpy(payload + offset, &rank_be, 4);
      offset += 4;
      memcpy(payload + offset, &sid_be, 8);
      offset += 8;
      memcpy(payload + offset, &score_bits, 8);
      offset += 8;
      memcpy(payload + offset, &rating_bits, 8);
      offset += 8;
      memcpy(payload + offset, &games_be, 4);
      offset += 4;
    }
    body_len = need;
    break;
  }
  case WAMBLE_CTRL_PREDICTION_DATA: {
    uint8_t count = msg->prediction_count;
    if (count > WAMBLE_MAX_PREDICTION_ENTRIES)
      return NET_ERR_INVALID;
    size_t need = 1 + (size_t)count * WAMBLE_PREDICTION_ENTRY_WIRE_SIZE;
    if (need > payload_capacity)
      return NET_ERR_TRUNCATED;
    payload[0] = count;
    size_t offset = 1;
    for (uint8_t i = 0; i < count; i++) {
      const WamblePredictionEntry *e = &msg->predictions[i];
      uint64_t id_be = host_to_net64(e->id);
      uint64_t parent_be = host_to_net64(e->parent_id);
      uint64_t points_bits = 0;
      memcpy(&points_bits, &e->points_awarded, sizeof(double));
      points_bits = host_to_net64(points_bits);
      uint16_t ply_be = htons(e->target_ply);
      memcpy(payload + offset, &id_be, 8);
      offset += 8;
      memcpy(payload + offset, &parent_be, 8);
      offset += 8;
      memcpy(payload + offset, e->token, TOKEN_LENGTH);
      offset += TOKEN_LENGTH;
      memcpy(payload + offset, &points_bits, 8);
      offset += 8;
      memcpy(payload + offset, &ply_be, 2);
      offset += 2;
      payload[offset++] = e->depth;
      payload[offset++] = e->status;
      payload[offset++] = e->uci_len;
      memcpy(payload + offset, e->uci, MAX_UCI_LENGTH);
      offset += MAX_UCI_LENGTH;
    }
    body_len = need;
    break;
  }
  default:
    body_len = 0;
    break;
  }

  int has_ext = 0;
  if (msg->ext_count > 0) {
    if (body_len > payload_capacity)
      return NET_ERR_TRUNCATED;
    size_t ext_len = 0;
    NetworkStatus ext_status = encode_msg_extensions(
        msg, payload + body_len, payload_capacity - body_len, &ext_len);
    if (ext_status != NET_OK)
      return ext_status;
    if (ext_len > 0) {
      body_len += ext_len;
      has_ext = 1;
    }
  }

  *payload_len = body_len;
  if (out_has_ext)
    *out_has_ext = has_ext;
  return NET_OK;
}

static NetworkStatus build_message_payload_dynamic(const struct WambleMsg *msg,
                                                   uint8_t **out_payload,
                                                   size_t *out_payload_len,
                                                   int *out_has_ext) {
  if (!msg || !out_payload || !out_payload_len)
    return NET_ERR_INVALID;
  *out_payload = NULL;
  *out_payload_len = 0;
  if (out_has_ext)
    *out_has_ext = 0;

  size_t cap = WAMBLE_MAX_PAYLOAD;
  const size_t max_cap = 1024u * 1024u;
  while (cap <= max_cap) {
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf)
      return NET_ERR_IO;
    size_t len = 0;
    int has_ext = 0;
    NetworkStatus st = encode_message_payload(msg, buf, cap, &len, &has_ext);
    if (st == NET_OK) {
      *out_payload = buf;
      *out_payload_len = len;
      if (out_has_ext)
        *out_has_ext = has_ext;
      return NET_OK;
    }
    free(buf);
    if (st != NET_ERR_TRUNCATED)
      return st;
    if (cap == max_cap)
      break;
    size_t next = cap * 2u;
    if (next < cap)
      break;
    cap = (next > max_cap) ? max_cap : next;
  }
  return NET_ERR_TRUNCATED;
}

NetworkStatus wamble_packet_serialize(const struct WambleMsg *msg,
                                      uint8_t *buffer, size_t buffer_capacity,
                                      size_t *out_len, uint8_t flags) {
  if (!msg || !buffer || buffer_capacity < WAMBLE_HEADER_SIZE)
    return NET_ERR_INVALID;

  WambleHeader hdr = {0};
  hdr.ctrl = msg->ctrl;
  hdr.flags = (uint8_t)(flags & (uint8_t)~(WAMBLE_FLAG_EXT_PAYLOAD |
                                           WAMBLE_FLAG_FRAGMENT_PAYLOAD));
  uint8_t header_version =
      (msg->header_version != 0) ? msg->header_version : WAMBLE_PROTO_VERSION;
  hdr.version = header_version;
  hdr.reserved = 0;
  memcpy(hdr.token, msg->token, TOKEN_LENGTH);
  hdr.board_id = host_to_net64(msg->board_id);
  hdr.seq_num = htonl(msg->seq_num);
  int uses_fragment_payload = ctrl_supports_fragment_payload(msg->ctrl) &&
                              msg_uses_fragment_payload(msg);

  uint8_t payload[WAMBLE_MAX_PAYLOAD];
  size_t payload_len = 0;
  int has_ext = 0;
  NetworkStatus payload_status = encode_message_payload(
      msg, payload, sizeof(payload), &payload_len, &has_ext);
  if (payload_status != NET_OK)
    return payload_status;
  if (has_ext)
    hdr.flags |= WAMBLE_FLAG_EXT_PAYLOAD;
  if (uses_fragment_payload)
    hdr.flags |= WAMBLE_FLAG_FRAGMENT_PAYLOAD;

  hdr.payload_len = htons((uint16_t)payload_len);

  if (WAMBLE_HEADER_SIZE + payload_len > buffer_capacity)
    return NET_ERR_TRUNCATED;

  memcpy(buffer, &hdr, sizeof(hdr));
  if (payload_len > 0)
    memcpy(buffer + WAMBLE_HEADER_SIZE, payload, payload_len);
  if (out_len)
    *out_len = WAMBLE_HEADER_SIZE + payload_len;
  return NET_OK;
}

NetworkStatus wamble_packet_deserialize(const uint8_t *buffer,
                                        size_t buffer_size,
                                        struct WambleMsg *msg,
                                        uint8_t *out_flags) {
  if (!buffer || buffer_size < WAMBLE_HEADER_SIZE || !msg)
    return NET_ERR_INVALID;
  WambleHeader hdr;
  memcpy(&hdr, buffer, sizeof(hdr));
  if (hdr.reserved != 0) {
    return NET_ERR_INVALID;
  }
  size_t payload_len = ntohs(hdr.payload_len);
  if (buffer_size < WAMBLE_HEADER_SIZE + payload_len)
    return NET_ERR_TRUNCATED;

  memset(msg, 0, sizeof(*msg));
  msg->ctrl = hdr.ctrl;
  msg->flags = hdr.flags;
  memcpy(msg->token, hdr.token, TOKEN_LENGTH);
  msg->board_id = net_to_host64(hdr.board_id);
  msg->seq_num = ntohl(hdr.seq_num);
  msg->header_version = hdr.version;
  if (out_flags)
    *out_flags = hdr.flags;

  const uint8_t *payload = buffer + WAMBLE_HEADER_SIZE;
  int has_ext_payload = (hdr.flags & WAMBLE_FLAG_EXT_PAYLOAD) != 0;
  int has_fragment_payload = (hdr.flags & WAMBLE_FLAG_FRAGMENT_PAYLOAD) != 0;
  if (has_ext_payload && has_fragment_payload)
    return NET_ERR_INVALID;
  if (has_ext_payload) {
    size_t base_len = 0;
    NetworkStatus ext_status =
        decode_msg_extensions(payload, payload_len, msg, &base_len);
    if (ext_status != NET_OK)
      return ext_status;
    payload_len = base_len;
  } else {
    msg->ext_count = 0;
  }

  int is_fragmented = 0;
  if (has_fragment_payload) {
    if (!ctrl_supports_fragment_payload(hdr.ctrl))
      return NET_ERR_INVALID;
    NetworkStatus frag_status =
        decode_fragment_payload(payload, payload_len, msg, &is_fragmented);
    if (frag_status != NET_OK)
      return frag_status;
    if (!is_fragmented)
      return NET_ERR_INVALID;
    if (is_fragmented) {
      size_t preview_copy = msg->fragment_data_len;
      if (preview_copy > FEN_MAX_LENGTH - 1)
        preview_copy = FEN_MAX_LENGTH - 1;
      switch (hdr.ctrl) {
      case WAMBLE_CTRL_SERVER_HELLO:
      case WAMBLE_CTRL_BOARD_UPDATE:
      case WAMBLE_CTRL_SERVER_NOTIFICATION:
      case WAMBLE_CTRL_SPECTATE_UPDATE:
        if (preview_copy)
          memcpy(msg->fen, msg->fragment_data, preview_copy);
        msg->fen[preview_copy] = '\0';
        break;
      case WAMBLE_CTRL_PROFILE_INFO:
      case WAMBLE_CTRL_PROFILE_TOS_DATA:
        if (preview_copy)
          memcpy(msg->profile_info, msg->fragment_data, preview_copy);
        msg->profile_info[preview_copy] = '\0';
        msg->profile_info_len = (uint16_t)preview_copy;
        break;
      case WAMBLE_CTRL_PROFILES_LIST:
        if (preview_copy)
          memcpy(msg->profiles_list, msg->fragment_data, preview_copy);
        msg->profiles_list[preview_copy] = '\0';
        msg->profiles_list_len = (uint16_t)preview_copy;
        break;
      case WAMBLE_CTRL_ERROR:
      case WAMBLE_CTRL_LOGIN_FAILED:
        if (msg->fragment_chunk_index == 0 && msg->fragment_data_len >= 3) {
          uint16_t code_net =
              (uint16_t)((msg->fragment_data[0] << 8) | msg->fragment_data[1]);
          msg->error_code = ntohs(code_net);
          uint8_t reason_len = msg->fragment_data[2];
          size_t available = (size_t)msg->fragment_data_len - 3;
          if ((size_t)reason_len > available)
            reason_len = (uint8_t)available;
          size_t reason_copy =
              reason_len < FEN_MAX_LENGTH - 1 ? reason_len : FEN_MAX_LENGTH - 1;
          if (reason_copy)
            memcpy(msg->error_reason, msg->fragment_data + 3, reason_copy);
          msg->error_reason[reason_copy] = '\0';
        }
        break;
      default:
        break;
      }
      return NET_OK;
    }
  }

  switch (hdr.ctrl) {
  case WAMBLE_CTRL_CLIENT_HELLO:
  case WAMBLE_CTRL_ACK:
  case WAMBLE_CTRL_LIST_PROFILES:
  case WAMBLE_CTRL_CLIENT_GOODBYE:
  case WAMBLE_CTRL_SPECTATE_GAME:
  case WAMBLE_CTRL_SPECTATE_STOP:
  case WAMBLE_CTRL_LOGOUT:

    break;
  case WAMBLE_CTRL_LOGIN_CHALLENGE: {
    if (payload_len != WAMBLE_LOGIN_CHALLENGE_LENGTH)
      return NET_ERR_INVALID;
    memcpy(msg->login_challenge, payload, WAMBLE_LOGIN_CHALLENGE_LENGTH);
    break;
  }
  case WAMBLE_CTRL_GET_LEADERBOARD: {
    if (payload_len > 2)
      return NET_ERR_INVALID;
    msg->leaderboard_type = WAMBLE_LEADERBOARD_SCORE;
    msg->leaderboard_limit = 10;
    if (payload_len == 1) {
      msg->leaderboard_limit = payload[0];
    } else if (payload_len == 2) {
      msg->leaderboard_type = payload[0];
      msg->leaderboard_limit = payload[1];
    }
    break;
  }
  case WAMBLE_CTRL_GET_PREDICTIONS: {
    if (payload_len > 2)
      return NET_ERR_INVALID;
    msg->prediction_depth = (payload_len >= 1) ? payload[0] : 0;
    msg->prediction_limit = (payload_len >= 2) ? payload[1] : 0;
    break;
  }
  case WAMBLE_CTRL_PLAYER_MOVE: {
    if (payload_len < 1)
      return NET_ERR_TRUNCATED;
    msg->uci_len = payload[0];
    if ((size_t)msg->uci_len > MAX_UCI_LENGTH ||
        (size_t)msg->uci_len > payload_len - 1)
      return NET_ERR_INVALID;
    memcpy(msg->uci, &payload[1], msg->uci_len);
    break;
  }
  case WAMBLE_CTRL_SUBMIT_PREDICTION: {
    if (payload_len < 1 + 8)
      return NET_ERR_TRUNCATED;
    msg->uci_len = payload[0];
    if ((size_t)msg->uci_len > MAX_UCI_LENGTH ||
        payload_len != (size_t)1 + msg->uci_len + 8)
      return NET_ERR_INVALID;
    memcpy(msg->uci, &payload[1], msg->uci_len);
    uint64_t parent_be = 0;
    memcpy(&parent_be, &payload[1 + msg->uci_len], 8);
    msg->prediction_parent_id = net_to_host64(parent_be);
    break;
  }
  case WAMBLE_CTRL_SERVER_HELLO:
  case WAMBLE_CTRL_BOARD_UPDATE:
  case WAMBLE_CTRL_SERVER_NOTIFICATION:
  case WAMBLE_CTRL_SPECTATE_UPDATE:
  case WAMBLE_CTRL_ERROR: {

    if (hdr.ctrl == WAMBLE_CTRL_ERROR) {
      if (payload_len < 3)
        return NET_ERR_TRUNCATED;
      uint16_t code_net = (uint16_t)((payload[0] << 8) | payload[1]);
      uint8_t rlen = payload[2];
      if ((size_t)3 + rlen > payload_len)
        return NET_ERR_TRUNCATED;
      msg->error_code = ntohs(code_net);
      size_t copy = rlen < FEN_MAX_LENGTH - 1 ? rlen : (FEN_MAX_LENGTH - 1);
      if (copy)
        memcpy(msg->error_reason, &payload[3], copy);
      msg->error_reason[copy] = '\0';
    } else {
      size_t copy =
          payload_len < FEN_MAX_LENGTH - 1 ? payload_len : (FEN_MAX_LENGTH - 1);
      memcpy(msg->fen, payload, copy);
      msg->fen[copy] = '\0';
    }
    break;
  }
  case WAMBLE_CTRL_LOGIN_FAILED: {
    if (payload_len < 3)
      return NET_ERR_TRUNCATED;
    uint16_t code_net = (uint16_t)((payload[0] << 8) | payload[1]);
    uint8_t rlen = payload[2];
    if ((size_t)3 + rlen > payload_len)
      return NET_ERR_TRUNCATED;
    msg->error_code = ntohs(code_net);
    size_t copy = rlen < FEN_MAX_LENGTH - 1 ? rlen : (FEN_MAX_LENGTH - 1);
    if (copy)
      memcpy(msg->error_reason, &payload[3], copy);
    msg->error_reason[copy] = '\0';
    break;
  }
  case WAMBLE_CTRL_PROFILE_INFO: {
    size_t copy =
        payload_len < FEN_MAX_LENGTH - 1 ? payload_len : (FEN_MAX_LENGTH - 1);
    memcpy(msg->profile_info, payload, copy);
    msg->profile_info[copy] = '\0';
    msg->profile_info_len = (uint16_t)copy;
    break;
  }
  case WAMBLE_CTRL_PROFILE_TOS_DATA: {
    if (payload_len > WAMBLE_FRAGMENT_DATA_MAX)
      return NET_ERR_TRUNCATED;
    if (payload_len)
      memcpy(msg->fragment_data, payload, payload_len);
    msg->fragment_data_len = (uint16_t)payload_len;
    size_t copy =
        payload_len < FEN_MAX_LENGTH - 1 ? payload_len : (FEN_MAX_LENGTH - 1);
    memcpy(msg->profile_info, payload, copy);
    msg->profile_info[copy] = '\0';
    msg->profile_info_len = (uint16_t)copy;
    msg->fragment_total_len = (uint32_t)payload_len;
    break;
  }
  case WAMBLE_CTRL_PROFILES_LIST: {
    size_t copy =
        payload_len < FEN_MAX_LENGTH - 1 ? payload_len : (FEN_MAX_LENGTH - 1);
    memcpy(msg->profiles_list, payload, copy);
    msg->profiles_list[copy] = '\0';
    msg->profiles_list_len = (uint16_t)copy;
    break;
  }
  case WAMBLE_CTRL_GET_PROFILE_INFO: {

    if (payload_len < 1)
      return NET_ERR_TRUNCATED;
    msg->profile_name_len = payload[0];
    if ((size_t)msg->profile_name_len > payload_len - 1)
      return NET_ERR_INVALID;
    if (msg->profile_name_len) {
      memcpy(msg->profile_name, &payload[1], msg->profile_name_len);
    }
    msg->profile_name[msg->profile_name_len] = '\0';
    break;
  }
  case WAMBLE_CTRL_GET_PROFILE_TOS: {
    if (payload_len < 1)
      return NET_ERR_TRUNCATED;
    msg->profile_name_len = payload[0];
    if ((size_t)msg->profile_name_len > payload_len - 1)
      return NET_ERR_INVALID;
    if (msg->profile_name_len)
      memcpy(msg->profile_name, &payload[1], msg->profile_name_len);
    msg->profile_name[msg->profile_name_len] = '\0';
    break;
  }
  case WAMBLE_CTRL_GET_LEGAL_MOVES: {
    if (payload_len < 1)
      return NET_ERR_TRUNCATED;
    msg->move_square = payload[0];
    break;
  }
  case WAMBLE_CTRL_PLAYER_STATS_DATA: {
    if (payload_len < 12)
      return NET_ERR_TRUNCATED;
    uint64_t be = 0;
    for (int i = 0; i < 8; i++) {
      be = (be << 8) | payload[i];
    }
    uint64_t host = net_to_host64(be);
    double score = 0.0;
    memcpy(&score, &host, sizeof(double));
    msg->player_stats_score = score;

    if (payload_len >= 12) {
      uint32_t gp_be = 0;
      memcpy(&gp_be, payload + 8, 4);
      msg->player_stats_games_played = ntohl(gp_be);
    }
    if (payload_len >= 16) {
      uint32_t c960_be = 0;
      memcpy(&c960_be, payload + 12, 4);
      msg->player_stats_chess960_games_played = ntohl(c960_be);
    }
    break;
  }
  case WAMBLE_CTRL_LOGIN_REQUEST: {
    if (payload_len == WAMBLE_PUBLIC_KEY_LENGTH) {
      memcpy(msg->login_pubkey, payload, WAMBLE_PUBLIC_KEY_LENGTH);
      msg->login_has_signature = 0;
    } else if (payload_len ==
               WAMBLE_PUBLIC_KEY_LENGTH + WAMBLE_LOGIN_SIGNATURE_LENGTH) {
      memcpy(msg->login_pubkey, payload, WAMBLE_PUBLIC_KEY_LENGTH);
      memcpy(msg->login_signature, payload + WAMBLE_PUBLIC_KEY_LENGTH,
             WAMBLE_LOGIN_SIGNATURE_LENGTH);
      msg->login_has_signature = 1;
    } else {
      return NET_ERR_INVALID;
    }
    break;
  }
  case WAMBLE_CTRL_LEGAL_MOVES: {
    if (payload_len < 2)
      return NET_ERR_TRUNCATED;
    msg->move_square = payload[0];
    msg->move_count = payload[1];
    if (msg->move_count > WAMBLE_MAX_LEGAL_MOVES)
      return NET_ERR_INVALID;
    size_t expected = 2 + (size_t)msg->move_count * 3;
    if (payload_len < expected)
      return NET_ERR_TRUNCATED;
    size_t offset = 2;
    for (uint8_t i = 0; i < msg->move_count; i++) {
      msg->moves[i].from = payload[offset++];
      msg->moves[i].to = payload[offset++];
      msg->moves[i].promotion = (int8_t)payload[offset++];
    }
    break;
  }
  case WAMBLE_CTRL_LEADERBOARD_DATA: {
    if (payload_len < 6)
      return NET_ERR_TRUNCATED;
    msg->leaderboard_type = payload[0];
    msg->leaderboard_count = payload[1];
    if (msg->leaderboard_count > WAMBLE_MAX_LEADERBOARD_ENTRIES)
      return NET_ERR_INVALID;
    size_t need = 1 + 1 + 4 + (size_t)msg->leaderboard_count * 32;
    if (payload_len < need)
      return NET_ERR_TRUNCATED;
    uint32_t self_rank_be = 0;
    memcpy(&self_rank_be, payload + 2, 4);
    msg->leaderboard_self_rank = ntohl(self_rank_be);
    size_t offset = 6;
    for (uint8_t i = 0; i < msg->leaderboard_count; i++) {
      WambleLeaderboardEntry *e = &msg->leaderboard[i];
      uint32_t rank_be = 0;
      uint64_t sid_be = 0;
      uint64_t score_be = 0;
      uint64_t rating_be = 0;
      uint32_t games_be = 0;
      memcpy(&rank_be, payload + offset, 4);
      offset += 4;
      memcpy(&sid_be, payload + offset, 8);
      offset += 8;
      memcpy(&score_be, payload + offset, 8);
      offset += 8;
      memcpy(&rating_be, payload + offset, 8);
      offset += 8;
      memcpy(&games_be, payload + offset, 4);
      offset += 4;
      e->rank = ntohl(rank_be);
      e->session_id = net_to_host64(sid_be);
      score_be = net_to_host64(score_be);
      rating_be = net_to_host64(rating_be);
      memcpy(&e->score, &score_be, sizeof(double));
      memcpy(&e->rating, &rating_be, sizeof(double));
      e->games_played = ntohl(games_be);
    }
    break;
  }
  case WAMBLE_CTRL_PREDICTION_DATA: {
    if (payload_len < 1)
      return NET_ERR_TRUNCATED;
    msg->prediction_count = payload[0];
    if (msg->prediction_count > WAMBLE_MAX_PREDICTION_ENTRIES)
      return NET_ERR_INVALID;
    size_t need =
        1 + (size_t)msg->prediction_count * WAMBLE_PREDICTION_ENTRY_WIRE_SIZE;
    if (payload_len < need)
      return NET_ERR_TRUNCATED;
    size_t offset = 1;
    for (uint8_t i = 0; i < msg->prediction_count; i++) {
      WamblePredictionEntry *e = &msg->predictions[i];
      uint64_t id_be = 0;
      uint64_t parent_be = 0;
      uint64_t points_be = 0;
      uint16_t ply_be = 0;
      memcpy(&id_be, payload + offset, 8);
      offset += 8;
      memcpy(&parent_be, payload + offset, 8);
      offset += 8;
      memcpy(e->token, payload + offset, TOKEN_LENGTH);
      offset += TOKEN_LENGTH;
      memcpy(&points_be, payload + offset, 8);
      offset += 8;
      memcpy(&ply_be, payload + offset, 2);
      offset += 2;
      e->depth = payload[offset++];
      e->status = payload[offset++];
      e->uci_len = payload[offset++];
      memcpy(e->uci, payload + offset, MAX_UCI_LENGTH);
      offset += MAX_UCI_LENGTH;
      e->id = net_to_host64(id_be);
      e->parent_id = net_to_host64(parent_be);
      points_be = net_to_host64(points_be);
      memcpy(&e->points_awarded, &points_be, sizeof(double));
      e->target_ply = ntohs(ply_be);
      if (e->uci_len > MAX_UCI_LENGTH)
        return NET_ERR_INVALID;
    }
    break;
  }
  default:
    break;
  }
  return NET_OK;
}

static void network_ensure_thread_state_initialized(void) {
  if (!client_sessions) {
    network_init_thread_state();
  }
}

static WambleClientSession *
find_client_session(const struct sockaddr_in *addr) {
  network_ensure_thread_state_initialized();
  if (!client_sessions)
    return NULL;
  int idx = session_map_get(addr);
  if (idx >= 0)
    return &client_sessions[idx];
  return NULL;
}

static WambleClientSession *find_client_session_by_token(const uint8_t *token) {
  network_ensure_thread_state_initialized();
  if (!client_sessions)
    return NULL;
  for (int i = 0; i < num_sessions; i++) {
    if (memcmp(client_sessions[i].token, token, TOKEN_LENGTH) == 0)
      return &client_sessions[i];
  }
  return NULL;
}

static WambleClientSession *
create_client_session(const struct sockaddr_in *addr, const uint8_t *token) {
  if (!client_sessions)
    return NULL;
  if (num_sessions >= get_config()->max_client_sessions) {

    return NULL;
  }

  WambleClientSession *session = &client_sessions[num_sessions++];
  session->addr = *addr;
  memcpy(session->token, token, TOKEN_LENGTH);
  session->last_seq_num = 0;
  session->last_seen = wamble_now_wall();
  session->next_seq_num = 1;
  session->treatment_group_key[0] = '\0';
  session_map_put(addr, (int)(session - client_sessions));
  return session;
}

static void sync_client_session_treatment_group(WambleClientSession *session,
                                                const uint8_t *token) {
  if (!session || !token)
    return;
  WambleTreatmentAssignment assignment = {0};
  DbStatus status =
      wamble_query_get_session_treatment_assignment(token, &assignment);
  if (status == DB_OK) {
    snprintf(session->treatment_group_key, sizeof(session->treatment_group_key),
             "%s", assignment.group_key);
    return;
  }
  if (status == DB_NOT_FOUND)
    session->treatment_group_key[0] = '\0';
}

static void update_client_session(const struct sockaddr_in *addr,
                                  const uint8_t *token, uint32_t seq_num) {
  WambleClientSession *session = find_client_session(addr);
  if (!session) {
    session = find_client_session_by_token(token);
    if (session) {

      uint32_t diff = seq_num - session->last_seq_num;
      if (diff != 0 && diff <= (UINT32_MAX / 2u)) {
        session->addr = *addr;
        session_map_put(addr, (int)(session - client_sessions));
      }
    } else {
      session = create_client_session(addr, token);
      if (!session)
        return;
    }
  }

  session->last_seq_num = seq_num;
  session->last_seen = wamble_now_wall();
  memcpy(session->token, token, TOKEN_LENGTH);
  sync_client_session_treatment_group(session, token);
}

void network_init_thread_state(void) {
  if (!client_sessions) {
    client_sessions = malloc(sizeof(WambleClientSession) *
                             (size_t)get_config()->max_client_sessions);
  }
  if (!session_index_map) {
    session_index_map =
        malloc(sizeof(int) * (size_t)(get_config()->max_client_sessions * 2));
  }
  if ((get_config()->max_client_sessions > 0) &&
      (!client_sessions || !session_index_map)) {
    free(client_sessions);
    free(session_index_map);
    client_sessions = NULL;
    session_index_map = NULL;
    num_sessions = 0;
    pending_packets_reset();
    return;
  }
  num_sessions = 0;
  pending_packets_reset();
  session_map_init();
}

int network_get_session_treatment_group(const uint8_t *token, char *out_group,
                                        size_t out_group_size) {
  if (!token || !out_group || out_group_size == 0)
    return -1;
  if (!client_sessions)
    network_init_thread_state();
  if (!client_sessions)
    return -1;
  WambleClientSession *session = find_client_session_by_token(token);
  if (!session)
    return -1;
  sync_client_session_treatment_group(session, token);
  if (!session->treatment_group_key[0])
    return -1;
  snprintf(out_group, out_group_size, "%s", session->treatment_group_key);
  return 0;
}

wamble_socket_t create_and_bind_socket(int port) {
  wamble_socket_t sockfd;
  struct sockaddr_in servaddr;

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == WAMBLE_INVALID_SOCKET) {

    return -1;
  }

  int optval = 1;
  (void)setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&optval,
                   sizeof(optval));

  int buffer_size = get_config()->buffer_size;
  (void)setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (const char *)&buffer_size,
                   sizeof(buffer_size));
  (void)setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const char *)&buffer_size,
                   sizeof(buffer_size));

  memset(&servaddr, 0, sizeof(servaddr));

  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = INADDR_ANY;
  servaddr.sin_port = htons((uint16_t)port);

  if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
    wamble_close_socket(sockfd);
    return -1;
  }

  (void)wamble_set_nonblocking(sockfd);

  network_init_thread_state();
  if (get_config()->max_client_sessions > 0 &&
      (!client_sessions || !session_index_map)) {
    wamble_close_socket(sockfd);
    return WAMBLE_INVALID_SOCKET;
  }

  return sockfd;
}

static int receive_message_from_packet_impl(const uint8_t *packet,
                                            size_t packet_len,
                                            struct WambleMsg *msg,
                                            const struct sockaddr_in *cliaddr) {
  if (!packet || !msg || !cliaddr || packet_len == 0 ||
      packet_len > WAMBLE_MAX_PACKET_SIZE) {
    return -1;
  }
  network_ensure_thread_state_initialized();

  uint8_t flags = 0;
  if (wamble_packet_deserialize(packet, packet_len, msg, &flags) != NET_OK)
    return -1;

  if (!ctrl_is_supported(msg->ctrl))
    return -1;
  if (msg->uci_len > MAX_UCI_LENGTH)
    return -1;

  int token_valid = 0;
  for (int i = 0; i < TOKEN_LENGTH; i++) {
    if (msg->token[i] != 0) {
      token_valid = 1;
      break;
    }
  }
  if (!token_valid && msg->ctrl != WAMBLE_CTRL_CLIENT_HELLO)
    return -1;

  int is_dup = 0;
  WambleClientSession *session = find_client_session(cliaddr);
  if (!session)
    session = find_client_session_by_token(msg->token);
  if (session) {
    uint32_t last = session->last_seq_num;
    uint32_t forward = msg->seq_num - last;
    if (forward == 0) {
      is_dup = 1;
    } else if (!(forward <= (UINT32_MAX / 2u))) {
      uint32_t back = last - msg->seq_num;
      if (back <= WAMBLE_DUP_WINDOW)
        is_dup = 1;
    }
  }
  if (msg->ctrl != WAMBLE_CTRL_ACK &&
      (msg->flags & WAMBLE_FLAG_UNRELIABLE) == 0 && is_dup) {
    return -1;
  }

  if (msg->ctrl == WAMBLE_CTRL_CLIENT_HELLO && token_valid &&
      (msg->flags & WAMBLE_FLAG_UNRELIABLE) != 0) {
    update_client_session(cliaddr, msg->token, msg->seq_num);
  } else if (msg->ctrl != WAMBLE_CTRL_ACK &&
             (msg->flags & WAMBLE_FLAG_UNRELIABLE) == 0) {
    update_client_session(cliaddr, msg->token, msg->seq_num);
  }

  return (int)packet_len;
}

int receive_message_packet(const uint8_t *packet, size_t packet_len,
                           struct WambleMsg *msg,
                           const struct sockaddr_in *cliaddr) {
  return receive_message_from_packet_impl(packet, packet_len, msg, cliaddr);
}

int receive_message(wamble_socket_t sockfd, struct WambleMsg *msg,
                    struct sockaddr_in *cliaddr) {
  network_ensure_thread_state_initialized();
  wamble_socklen_t len = sizeof(*cliaddr);
  uint8_t receive_buffer[WAMBLE_MAX_PACKET_SIZE];
  size_t pending_len = 0;
  int pending_rc = pending_packet_pop(receive_buffer, sizeof(receive_buffer),
                                      &pending_len, cliaddr);
  ssize_t bytes_received = 0;
  if (pending_rc < 0)
    return -1;
  if (pending_rc > 0) {
    bytes_received = (ssize_t)pending_len;
  } else {
    bytes_received =
        recvfrom(sockfd, (char *)receive_buffer, WAMBLE_MAX_PACKET_SIZE, 0,
                 (struct sockaddr *)cliaddr, &len);
  }

  if (bytes_received <= 0)
    return (int)bytes_received;
  return receive_message_from_packet_impl(receive_buffer,
                                          (size_t)bytes_received, msg, cliaddr);
}

void send_ack(wamble_socket_t sockfd, const struct WambleMsg *msg,
              const struct sockaddr_in *cliaddr) {
  if (!msg || !cliaddr)
    return;
  if (ws_gateway_is_ws_client(cliaddr))
    return;

  struct WambleMsg ack_msg;
  memset(&ack_msg, 0, sizeof(ack_msg));
  ack_msg.ctrl = WAMBLE_CTRL_ACK;
  memcpy(ack_msg.token, msg->token, TOKEN_LENGTH);
  ack_msg.board_id = msg->board_id;
  ack_msg.seq_num = msg->seq_num;
  ack_msg.uci_len = 0;
  memset(ack_msg.uci, 0, MAX_UCI_LENGTH);
  memset(ack_msg.fen, 0, FEN_MAX_LENGTH);

  uint8_t send_buffer[WAMBLE_MAX_PACKET_SIZE];
  size_t serialized_size = 0;
  if (wamble_packet_serialize(&ack_msg, send_buffer, sizeof(send_buffer),
                              &serialized_size, 0) != NET_OK) {

    return;
  }

#ifdef WAMBLE_PLATFORM_WINDOWS
  sendto(sockfd, (const char *)send_buffer, (int)serialized_size, 0,
         (const struct sockaddr *)cliaddr, (int)sizeof(*cliaddr));
#else
  sendto(sockfd, (const char *)send_buffer, (size_t)serialized_size, 0,
         (const struct sockaddr *)cliaddr, (wamble_socklen_t)sizeof(*cliaddr));
#endif
}

static int send_fragmented_reliable_payload(wamble_socket_t sockfd,
                                            const struct WambleMsg *source_msg,
                                            const struct sockaddr_in *cliaddr,
                                            int timeout_ms, int max_retries) {
  if (!source_msg || !cliaddr || msg_uses_fragment_payload(source_msg) ||
      !ctrl_supports_fragment_payload(source_msg->ctrl) ||
      WAMBLE_FRAGMENT_DATA_MAX == 0) {
    return -1;
  }

  uint8_t *full_payload = NULL;
  size_t full_len = 0;
  NetworkStatus st =
      build_message_payload_dynamic(source_msg, &full_payload, &full_len, NULL);
  if (st != NET_OK)
    return -1;
  if (full_len <= WAMBLE_MAX_PAYLOAD || full_len > UINT32_MAX) {
    free(full_payload);
    return -1;
  }

  size_t chunk_size = (size_t)WAMBLE_FRAGMENT_DATA_MAX;
  size_t needed_chunks = (full_len + chunk_size - 1u) / chunk_size;
  if (needed_chunks == 0 || needed_chunks > UINT16_MAX) {
    free(full_payload);
    return -1;
  }

  uint8_t payload_hash[WAMBLE_FRAGMENT_HASH_LENGTH] = {0};
  crypto_blake2b(payload_hash, WAMBLE_FRAGMENT_HASH_LENGTH, full_payload,
                 full_len);
  uint32_t transfer_id = next_fragment_transfer_id();
  uint16_t chunk_count = (uint16_t)needed_chunks;

  for (uint16_t chunk_index = 0; chunk_index < chunk_count; chunk_index++) {
    size_t offset = (size_t)chunk_index * chunk_size;
    size_t chunk_len = full_len - offset;
    if (chunk_len > chunk_size)
      chunk_len = chunk_size;

    struct WambleMsg fragment = {0};
    fragment.ctrl = source_msg->ctrl;
    fragment.flags =
        (uint8_t)(source_msg->flags & (uint8_t)~(WAMBLE_FLAG_EXT_PAYLOAD |
                                                 WAMBLE_FLAG_FRAGMENT_PAYLOAD));
    fragment.header_version = source_msg->header_version;
    memcpy(fragment.token, source_msg->token, TOKEN_LENGTH);
    fragment.board_id = source_msg->board_id;
    fragment.fragment_version = WAMBLE_FRAGMENT_VERSION;
    fragment.fragment_hash_algo = WAMBLE_FRAGMENT_HASH_BLAKE2B_256;
    fragment.fragment_chunk_index = chunk_index;
    fragment.fragment_chunk_count = chunk_count;
    fragment.fragment_total_len = (uint32_t)full_len;
    fragment.fragment_transfer_id = transfer_id;
    memcpy(fragment.fragment_hash, payload_hash, WAMBLE_FRAGMENT_HASH_LENGTH);
    fragment.fragment_data_len = (uint16_t)chunk_len;
    if (chunk_len) {
      memcpy(fragment.fragment_data, full_payload + offset, chunk_len);
    }

    if (send_reliable_message(sockfd, &fragment, cliaddr, timeout_ms,
                              max_retries) != 0) {
      free(full_payload);
      return -1;
    }
  }

  free(full_payload);
  return 0;
}

static int
send_fragmented_unreliable_payload(wamble_socket_t sockfd,
                                   const struct WambleMsg *source_msg,
                                   const struct sockaddr_in *cliaddr) {
  if (!source_msg || !cliaddr || msg_uses_fragment_payload(source_msg) ||
      !ctrl_supports_fragment_payload(source_msg->ctrl) ||
      WAMBLE_FRAGMENT_DATA_MAX == 0) {
    return -1;
  }

  uint8_t *full_payload = NULL;
  size_t full_len = 0;
  NetworkStatus st =
      build_message_payload_dynamic(source_msg, &full_payload, &full_len, NULL);
  if (st != NET_OK)
    return -1;
  if (full_len <= WAMBLE_MAX_PAYLOAD || full_len > UINT32_MAX) {
    free(full_payload);
    return -1;
  }

  size_t chunk_size = (size_t)WAMBLE_FRAGMENT_DATA_MAX;
  size_t needed_chunks = (full_len + chunk_size - 1u) / chunk_size;
  if (needed_chunks == 0 || needed_chunks > UINT16_MAX) {
    free(full_payload);
    return -1;
  }

  uint8_t payload_hash[WAMBLE_FRAGMENT_HASH_LENGTH] = {0};
  crypto_blake2b(payload_hash, WAMBLE_FRAGMENT_HASH_LENGTH, full_payload,
                 full_len);
  uint32_t transfer_id = next_fragment_transfer_id();
  uint16_t chunk_count = (uint16_t)needed_chunks;

  for (uint16_t chunk_index = 0; chunk_index < chunk_count; chunk_index++) {
    size_t offset = (size_t)chunk_index * chunk_size;
    size_t chunk_len = full_len - offset;
    if (chunk_len > chunk_size)
      chunk_len = chunk_size;

    struct WambleMsg fragment = {0};
    fragment.ctrl = source_msg->ctrl;
    fragment.flags =
        (uint8_t)(source_msg->flags & (uint8_t)~(WAMBLE_FLAG_EXT_PAYLOAD |
                                                 WAMBLE_FLAG_FRAGMENT_PAYLOAD));
    fragment.header_version = source_msg->header_version;
    memcpy(fragment.token, source_msg->token, TOKEN_LENGTH);
    fragment.board_id = source_msg->board_id;
    fragment.fragment_version = WAMBLE_FRAGMENT_VERSION;
    fragment.fragment_hash_algo = WAMBLE_FRAGMENT_HASH_BLAKE2B_256;
    fragment.fragment_chunk_index = chunk_index;
    fragment.fragment_chunk_count = chunk_count;
    fragment.fragment_total_len = (uint32_t)full_len;
    fragment.fragment_transfer_id = transfer_id;
    memcpy(fragment.fragment_hash, payload_hash, WAMBLE_FRAGMENT_HASH_LENGTH);
    fragment.fragment_data_len = (uint16_t)chunk_len;
    if (chunk_len) {
      memcpy(fragment.fragment_data, full_payload + offset, chunk_len);
    }

    if (send_unreliable_packet(sockfd, &fragment, cliaddr) != 0) {
      free(full_payload);
      return -1;
    }
  }

  free(full_payload);
  return 0;
}

int send_reliable_message(wamble_socket_t sockfd, const struct WambleMsg *msg,
                          const struct sockaddr_in *cliaddr, int timeout_ms,
                          int max_retries) {
  if (!msg || !cliaddr)
    return -1;
  if (timeout_ms <= 0)
    timeout_ms = get_config()->timeout_ms;
  if (max_retries <= 0)
    max_retries = get_config()->max_retries;

  struct WambleMsg reliable_msg = *msg;

  WambleClientSession *session = find_client_session(cliaddr);
  char ip_str[INET_ADDRSTRLEN];
  wamble_inet_ntop(AF_INET, &(cliaddr->sin_addr), ip_str, INET_ADDRSTRLEN);

  if (!session) {
    session = create_client_session(cliaddr, msg->token);
    if (!session) {

      reliable_msg.seq_num = global_seq_num++;
      if (global_seq_num > (UINT32_MAX - 1000)) {
        global_seq_num = 1;
      }
    } else {
      reliable_msg.seq_num = session->next_seq_num++;
    }
  } else {
    reliable_msg.seq_num = session->next_seq_num++;
  }

  uint8_t send_buffer[WAMBLE_MAX_PACKET_SIZE];
  size_t serialized_size = 0;
  uint8_t send_flags = reliable_msg.flags;
  NetworkStatus serialize_status =
      wamble_packet_serialize(&reliable_msg, send_buffer, sizeof(send_buffer),
                              &serialized_size, send_flags);
  if (serialize_status != NET_OK) {
    if (serialize_status == NET_ERR_TRUNCATED) {
      return send_fragmented_reliable_payload(sockfd, &reliable_msg, cliaddr,
                                              timeout_ms, max_retries);
    }
    return -1;
  }

  int ws_rc = ws_gateway_queue_packet(cliaddr, send_buffer, serialized_size);
  if (ws_rc > 0)
    return 0;
  if (ws_rc < 0)
    return -1;

  int current_timeout = timeout_ms;
  for (int attempt = 0; attempt < max_retries; attempt++) {
    ssize_t bytes_sent = sendto(sockfd, (const char *)send_buffer,
#ifdef WAMBLE_PLATFORM_WINDOWS
                                (int)serialized_size,
#else
                                (size_t)serialized_size,
#endif
                                0, (const struct sockaddr *)cliaddr,
#ifdef WAMBLE_PLATFORM_WINDOWS
                                (int)sizeof(*cliaddr)
#else
                                (wamble_socklen_t)sizeof(*cliaddr)
#endif
    );

    if (bytes_sent < 0) {
      return -1;
    }

    fd_set readfds;
    struct timeval timeout;
    timeout.tv_sec = current_timeout / 1000;
    timeout.tv_usec = (current_timeout % 1000) * 1000;
    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);
    int sel =
#ifdef WAMBLE_PLATFORM_WINDOWS
        select(0, &readfds, NULL, NULL, &timeout);
#else
        select(sockfd + 1, &readfds, NULL, NULL, &timeout);
#endif
    if (sel > 0) {
      for (int drained = 0; drained < 64; drained++) {
        uint8_t ack_buffer[WAMBLE_MAX_PACKET_SIZE];
        struct WambleMsg ack_msg;
        struct sockaddr_in ack_cliaddr;
        wamble_socklen_t ack_len = sizeof(ack_cliaddr);
        ssize_t rcv = recvfrom(sockfd, (char *)ack_buffer,
#ifdef WAMBLE_PLATFORM_WINDOWS
                               (int)WAMBLE_MAX_PACKET_SIZE,
#else
                               (size_t)WAMBLE_MAX_PACKET_SIZE,
#endif
                               0, (struct sockaddr *)&ack_cliaddr, &ack_len);
        if (rcv <= 0)
          break;
        uint8_t ack_flags = 0;
        if (wamble_packet_deserialize(ack_buffer, (size_t)rcv, &ack_msg,
                                      &ack_flags) == NET_OK &&
            ack_msg.ctrl == WAMBLE_CTRL_ACK &&
            ack_msg.seq_num == reliable_msg.seq_num &&
            sockaddr_in_equal(&ack_cliaddr, cliaddr) &&
            memcmp(ack_msg.token, reliable_msg.token, TOKEN_LENGTH) == 0) {
          return 0;
        }
        pending_packet_push(ack_buffer, (size_t)rcv, &ack_cliaddr);
      }
    }

    if (current_timeout < 8000) {
      int next = current_timeout * 2;
      current_timeout = next > 8000 ? 8000 : next;
    }
  }

  return -1;
}

int send_unreliable_packet(wamble_socket_t sockfd, const struct WambleMsg *msg,
                           const struct sockaddr_in *cliaddr) {
  if (!msg || !cliaddr)
    return -1;
  uint8_t buffer[WAMBLE_MAX_PACKET_SIZE];
  size_t serialized_size = 0;
  NetworkStatus serialize_status = wamble_packet_serialize(
      msg, buffer, sizeof(buffer), &serialized_size, WAMBLE_FLAG_UNRELIABLE);
  if (serialize_status != NET_OK) {
    if (serialize_status == NET_ERR_TRUNCATED)
      return send_fragmented_unreliable_payload(sockfd, msg, cliaddr);
    return -1;
  }
  int ws_rc = ws_gateway_queue_packet(cliaddr, buffer, serialized_size);
  if (ws_rc > 0)
    return 0;
  if (ws_rc < 0)
    return -1;
#ifdef WAMBLE_PLATFORM_WINDOWS
  int rc = sendto(sockfd, (const char *)buffer, (int)serialized_size, 0,
                  (const struct sockaddr *)cliaddr, (int)sizeof(*cliaddr));
  return (rc >= 0) ? 0 : -1;
#else
  int tries = 0;
  while (tries < 4) {
    ssize_t rc = sendto(sockfd, (const char *)buffer, (size_t)serialized_size,
                        MSG_DONTWAIT, (const struct sockaddr *)cliaddr,
                        (wamble_socklen_t)sizeof(*cliaddr));
    if (rc >= 0)
      return 0;
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      struct timespec ts = {0, 1000000L};
      nanosleep(&ts, NULL);
      tries++;
      continue;
    }
    break;
  }
  return -1;
#endif
}

void cleanup_expired_sessions(void) {
  time_t now = wamble_now_wall();
  int write_idx = 0;

  for (int read_idx = 0; read_idx < num_sessions; read_idx++) {
    if (now - client_sessions[read_idx].last_seen <
        get_config()->session_timeout) {
      if (write_idx != read_idx) {
        client_sessions[write_idx] = client_sessions[read_idx];
      }
      write_idx++;
    }
  }

  if (write_idx != num_sessions) {
    num_sessions = write_idx;
    session_map_init();
    for (int i = 0; i < num_sessions; i++) {
      session_map_put(&client_sessions[i].addr, i);
    }
  }
}

static const char base64url_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

void format_token_for_url(const uint8_t *token, char *url_buffer) {
  if (!token || !url_buffer)
    return;

  int j = 0;
  for (int i = 0; i < 16; i += 3) {
    uint32_t block = 0;
    int bytes_in_block = (i + 3 <= 16) ? 3 : (16 - i);

    for (int k = 0; k < bytes_in_block; k++) {
      block |= ((uint32_t)token[i + k]) << (8 * (2 - k));
    }

    for (int k = 0; k < 4; k++) {
      if (j >= 22)
        break;
      url_buffer[j++] = base64url_chars[(block >> (6 * (3 - k))) & 0x3F];
    }
  }

  url_buffer[22] = '\0';
}

int wamble_socket_bound_port(wamble_socket_t sock) {
  struct sockaddr_in addr;
  wamble_socklen_t len = (wamble_socklen_t)sizeof(addr);
  if (getsockname(sock, (struct sockaddr *)&addr, &len) != 0)
    return -1;
  return (int)ntohs(addr.sin_port);
}

int decode_token_from_url(const char *url_string, uint8_t *token_buffer) {
  if (!url_string || !token_buffer || strlen(url_string) != 22) {
    return -1;
  }

  uint8_t decode_table[256];
  memset(decode_table, 0xFF, 256);

  for (int i = 0; i < 64; i++) {
    decode_table[(unsigned char)base64url_chars[i]] = (uint8_t)i;
  }

  memset(token_buffer, 0, 16);

  int token_pos = 0;
  for (int i = 0; i < 22; i += 4) {
    uint32_t block = 0;
    int valid_chars = 0;

    for (int j = 0; j < 4 && (i + j) < 22; j++) {
      unsigned char c = (unsigned char)url_string[i + j];
      if (decode_table[c] == 0xFF) {
        return -1;
      }
      block |= ((uint32_t)decode_table[c]) << (6 * (3 - j));
      valid_chars++;
    }

    for (int j = 0; j < 3 && token_pos < 16; j++) {
      token_buffer[token_pos++] = (block >> (8 * (2 - j))) & 0xFF;
    }
  }

  return 0;
}
