#include "../include/wamble/wamble.h"
void crypto_blake2b(uint8_t *hash, size_t hash_size, const uint8_t *msg,
                    size_t msg_size);
#define WAMBLE_PENDING_PACKET_CAP 64

typedef struct WambleTerminalCacheSlot {
  uint32_t req_seq;
  uint64_t stored_mono_ms;
  size_t len;
  size_t cap;
  uint8_t *data;
} WambleTerminalCacheSlot;

typedef struct WambleClientSession {
  struct sockaddr_in addr;
  uint8_t token[TOKEN_LENGTH];
  uint32_t last_seq_num;
  time_t last_seen;
  uint32_t next_seq_num;
  char treatment_group_key[128];
  WambleTerminalCacheSlot *terminal_cache;
  int terminal_cache_count;
} WambleClientSession;

typedef struct WambleCurrentRequest {
  struct WambleClientSession *session;
  uint32_t seq_num;
} WambleCurrentRequest;

static WAMBLE_THREAD_LOCAL WambleCurrentRequest g_current_request;

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
  case WAMBLE_CTRL_ACCEPT_PROFILE_TOS:
  case WAMBLE_CTRL_GET_ACTIVE_RESERVATIONS:
  case WAMBLE_CTRL_ACTIVE_RESERVATIONS_DATA:
    return 1;
  default:
    return 0;
  }
}

static int token_has_any_byte(const uint8_t *token) {
  if (!token)
    return 0;
  for (int i = 0; i < TOKEN_LENGTH; i++) {
    if (token[i] != 0)
      return 1;
  }
  return 0;
}

static int ctrl_allows_anonymous_token(uint8_t ctrl) {
  switch (ctrl) {
  case WAMBLE_CTRL_CLIENT_HELLO:
  case WAMBLE_CTRL_LIST_PROFILES:
  case WAMBLE_CTRL_GET_PROFILE_INFO:
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
  if (msg->fragment.fragment_chunk_count == 0 ||
      msg->fragment.fragment_chunk_index >= msg->fragment.fragment_chunk_count)
    return 0;
  if (msg->fragment.fragment_data_len > WAMBLE_FRAGMENT_DATA_MAX)
    return 0;
  size_t total_len = (size_t)msg->fragment.fragment_total_len;
  size_t offset = (size_t)msg->fragment.fragment_chunk_index *
                  (size_t)WAMBLE_FRAGMENT_DATA_MAX;
  size_t len = (size_t)msg->fragment.fragment_data_len;
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
  size_t total_len = (size_t)msg->fragment.fragment_total_len;
  size_t chunk_count = (size_t)msg->fragment.fragment_chunk_count;
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
  reassembly->hash_algo = msg->fragment.fragment_hash_algo;
  reassembly->chunk_count = msg->fragment.fragment_chunk_count;
  reassembly->received_chunks = 0;
  reassembly->total_len = msg->fragment.fragment_total_len;
  reassembly->transfer_id = msg->fragment.fragment_transfer_id;
  memcpy(reassembly->expected_hash, msg->fragment.fragment_hash,
         WAMBLE_FRAGMENT_HASH_LENGTH);
  reassembly->integrity = WAMBLE_FRAGMENT_INTEGRITY_UNKNOWN;
  return 0;
}

static int reassembly_payload_base_len(const uint8_t *payload,
                                       size_t payload_len,
                                       size_t *out_base_len) {
  enum {
    WAMBLE_EXT_MAGIC_0_LOCAL = 0x57,
    WAMBLE_EXT_MAGIC_1_LOCAL = 0x58,
    WAMBLE_EXT_VERSION_LOCAL = 1
  };
  const uint8_t *p = NULL;
  const uint8_t *end = NULL;
  if (!payload || !out_base_len)
    return 0;
  *out_base_len = payload_len;
  if (payload_len < 4 || payload[payload_len - 4] != WAMBLE_EXT_MAGIC_0_LOCAL ||
      payload[payload_len - 3] != WAMBLE_EXT_MAGIC_1_LOCAL) {
    return 0;
  }

  uint16_t body_be = 0;
  memcpy(&body_be, payload + payload_len - 2, 2);
  size_t body_len = (size_t)ntohs(body_be);
  if (body_len < 2 || body_len > payload_len - 4)
    return 0;
  *out_base_len = payload_len - 4 - body_len;
  p = payload + *out_base_len;
  end = p + body_len;
  if (p[0] != WAMBLE_EXT_VERSION_LOCAL)
    return 0;
  uint8_t count = p[1];
  p += 2;
  for (uint8_t i = 0; i < count; i++) {
    if ((size_t)(end - p) < 2)
      return 0;
    uint8_t key_len = *p++;
    if (key_len == 0 || (size_t)(end - p) < (size_t)key_len + 1)
      return 0;
    p += key_len;
    uint8_t value_type = *p++;
    if (value_type == WAMBLE_TREATMENT_VALUE_STRING) {
      if ((size_t)(end - p) < 2)
        return 0;
      uint16_t slen_be = 0;
      memcpy(&slen_be, p, 2);
      p += 2;
      size_t slen = (size_t)ntohs(slen_be);
      if ((size_t)(end - p) < slen)
        return 0;
      p += slen;
    } else if (value_type == WAMBLE_TREATMENT_VALUE_INT ||
               value_type == WAMBLE_TREATMENT_VALUE_DOUBLE) {
      if ((size_t)(end - p) < 8)
        return 0;
      p += 8;
    } else if (value_type == WAMBLE_TREATMENT_VALUE_BOOL) {
      if ((size_t)(end - p) < 1)
        return 0;
      p += 1;
    } else {
      return 0;
    }
  }
  return p == end;
}

WambleFragmentReassemblyResult
wamble_fragment_reassembly_push(WambleFragmentReassembly *reassembly,
                                const struct WambleMsg *msg) {
  if (!reassembly || !msg)
    return WAMBLE_FRAGMENT_REASSEMBLY_ERR_INVALID;
  if (!ctrl_supports_fragment_payload(msg->ctrl))
    return WAMBLE_FRAGMENT_REASSEMBLY_IGNORED;
  if (msg->fragment.fragment_version != WAMBLE_FRAGMENT_VERSION)
    return WAMBLE_FRAGMENT_REASSEMBLY_IGNORED;
  if (msg->fragment.fragment_hash_algo != WAMBLE_FRAGMENT_HASH_BLAKE2B_256)
    return WAMBLE_FRAGMENT_REASSEMBLY_ERR_INVALID;

  size_t offset = 0;
  size_t len = 0;
  if (!reassembly_fragment_shape_valid(msg, &offset, &len))
    return WAMBLE_FRAGMENT_REASSEMBLY_ERR_INVALID;

  int same_transfer =
      reassembly->active && reassembly->ctrl == msg->ctrl &&
      reassembly->hash_algo == msg->fragment.fragment_hash_algo &&
      reassembly->chunk_count == msg->fragment.fragment_chunk_count &&
      reassembly->total_len == msg->fragment.fragment_total_len &&
      reassembly->transfer_id == msg->fragment.fragment_transfer_id &&
      memcmp(reassembly->expected_hash, msg->fragment.fragment_hash,
             WAMBLE_FRAGMENT_HASH_LENGTH) == 0;
  if (!same_transfer) {
    if (reassembly_begin_transfer(reassembly, msg) != 0)
      return WAMBLE_FRAGMENT_REASSEMBLY_ERR_NOMEM;
  }

  uint16_t idx = msg->fragment.fragment_chunk_index;
  if (reassembly->chunk_seen[idx]) {
    if (len && memcmp(reassembly->data + offset, msg->fragment.fragment_data,
                      len) != 0) {
      return WAMBLE_FRAGMENT_REASSEMBLY_ERR_INVALID;
    }
  } else {
    if (len)
      memcpy(reassembly->data + offset, msg->fragment.fragment_data, len);
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
    if (reassembly->ctrl == WAMBLE_CTRL_PROFILE_TOS_DATA) {
      size_t base_len = 0;
      if (reassembly_payload_base_len(
              reassembly->data, (size_t)reassembly->total_len, &base_len) &&
          base_len <= UINT32_MAX) {
        reassembly->total_len = (uint32_t)base_len;
      }
    }
    return WAMBLE_FRAGMENT_REASSEMBLY_COMPLETE;
  }
  reassembly->integrity = WAMBLE_FRAGMENT_INTEGRITY_MISMATCH;
  return WAMBLE_FRAGMENT_REASSEMBLY_COMPLETE_BAD_HASH;
}

static NetworkStatus
build_message_payload_dynamic(const struct WambleMsg *msg,
                              uint8_t **out_payload, size_t *out_payload_len,
                              uint8_t *out_transport_flags) {
  if (!msg || !out_payload || !out_payload_len)
    return NET_ERR_INVALID;
  *out_payload = NULL;
  *out_payload_len = 0;
  if (out_transport_flags)
    *out_transport_flags = 0;

  size_t cap = WAMBLE_MAX_PAYLOAD;
  const size_t max_cap = 1024u * 1024u;
  while (cap <= max_cap) {
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf)
      return NET_ERR_IO;
    size_t len = 0;
    uint8_t transport_flags = 0;
    NetworkStatus st =
        wamble_payload_serialize(msg, buf, cap, &len, &transport_flags);
    if (st == NET_OK) {
      *out_payload = buf;
      *out_payload_len = len;
      if (out_transport_flags)
        *out_transport_flags = transport_flags;
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
  session->terminal_cache = NULL;
  session->terminal_cache_count = 0;
  session_map_put(addr, (int)(session - client_sessions));
  return session;
}

static void terminal_cache_free_all(WambleClientSession *session) {
  if (!session || !session->terminal_cache)
    return;
  for (int i = 0; i < session->terminal_cache_count; i++)
    free(session->terminal_cache[i].data);
  free(session->terminal_cache);
  session->terminal_cache = NULL;
  session->terminal_cache_count = 0;
}

static void terminal_cache_expire(WambleClientSession *session,
                                  uint64_t now_ms) {
  if (!session || !session->terminal_cache)
    return;
  int ttl = get_config()->terminal_cache_ttl_ms;
  if (ttl <= 0) {
    terminal_cache_free_all(session);
    return;
  }
  int write = 0;
  for (int i = 0; i < session->terminal_cache_count; i++) {
    WambleTerminalCacheSlot *s = &session->terminal_cache[i];
    if (now_ms - s->stored_mono_ms > (uint64_t)ttl) {
      free(s->data);
      continue;
    }
    if (write != i)
      session->terminal_cache[write] = *s;
    write++;
  }
  session->terminal_cache_count = write;
  if (write == 0) {
    free(session->terminal_cache);
    session->terminal_cache = NULL;
  }
}

#define WAMBLE_TERMINAL_CACHE_MAX_SLOTS 8

static int terminal_cache_store(WambleClientSession *session, uint32_t req_seq,
                                const uint8_t *data, size_t len) {
  if (!session || !data || len == 0 || len > WAMBLE_MAX_PACKET_SIZE)
    return -1;
  int ttl = get_config()->terminal_cache_ttl_ms;
  if (ttl <= 0)
    return -1;
  uint64_t now_ms = wamble_now_mono_millis();
  terminal_cache_expire(session, now_ms);
  WambleTerminalCacheSlot *slot = NULL;
  int oldest = 0;
  for (int i = 0; i < session->terminal_cache_count; i++) {
    if (session->terminal_cache[i].req_seq == req_seq) {
      slot = &session->terminal_cache[i];
      break;
    }
    if (session->terminal_cache[i].stored_mono_ms <
        session->terminal_cache[oldest].stored_mono_ms)
      oldest = i;
  }
  if (!slot) {
    if (session->terminal_cache_count >= WAMBLE_TERMINAL_CACHE_MAX_SLOTS) {
      slot = &session->terminal_cache[oldest];
    } else {
      int new_count = session->terminal_cache_count + 1;
      WambleTerminalCacheSlot *grown = (WambleTerminalCacheSlot *)realloc(
          session->terminal_cache,
          (size_t)new_count * sizeof(*session->terminal_cache));
      if (!grown)
        return -1;
      session->terminal_cache = grown;
      slot = &session->terminal_cache[session->terminal_cache_count];
      slot->data = NULL;
      slot->cap = 0;
      slot->len = 0;
      session->terminal_cache_count = new_count;
    }
  }
  if (slot->cap < len) {
    uint8_t *buf = (uint8_t *)realloc(slot->data, len);
    if (!buf)
      return -1;
    slot->data = buf;
    slot->cap = len;
  }
  slot->req_seq = req_seq;
  slot->len = len;
  slot->stored_mono_ms = now_ms;
  memcpy(slot->data, data, len);
  return 0;
}

static size_t terminal_cache_lookup_copy(WambleClientSession *session,
                                         uint32_t req_seq, uint8_t *out,
                                         size_t out_cap) {
  if (!session || !session->terminal_cache)
    return 0;
  terminal_cache_expire(session, wamble_now_mono_millis());
  for (int i = 0; i < session->terminal_cache_count; i++) {
    WambleTerminalCacheSlot *s = &session->terminal_cache[i];
    if (s->req_seq != req_seq)
      continue;
    if (s->len == 0)
      return 0;
    if (!out)
      return s->len;
    if (out_cap < s->len)
      return 0;
    memcpy(out, s->data, s->len);
    return s->len;
  }
  return 0;
}

static void terminal_cache_release(WambleClientSession *session) {
  terminal_cache_free_all(session);
}

static void network_send_raw_to_client(wamble_socket_t sockfd,
                                       const struct sockaddr_in *cliaddr,
                                       const uint8_t *data, size_t len) {
  if (!cliaddr || !data || len == 0)
    return;
  int ws_rc = ws_gateway_queue_packet(cliaddr, data, len);
  if (ws_rc != 0)
    return;
  if (sockfd == WAMBLE_INVALID_SOCKET)
    return;
#ifdef WAMBLE_PLATFORM_WINDOWS
  sendto(sockfd, (const char *)data, (int)len, 0,
         (const struct sockaddr *)cliaddr, (int)sizeof(*cliaddr));
#else
  sendto(sockfd, (const char *)data, len, 0, (const struct sockaddr *)cliaddr,
         (wamble_socklen_t)sizeof(*cliaddr));
#endif
}

static void network_begin_request_for_session(WambleClientSession *session,
                                              uint32_t seq_num) {
  g_current_request.session = session;
  g_current_request.seq_num = seq_num;
}

void network_end_request(void) { g_current_request.session = NULL; }

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
  int token_valid = token_has_any_byte(token);
  WambleClientSession *session = find_client_session(addr);
  if (!session) {
    if (token_valid)
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
  if (token_valid) {
    sync_client_session_treatment_group(session, token);
  } else {
    session->treatment_group_key[0] = '\0';
  }
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
  for (int i = 0; i < num_sessions; i++)
    terminal_cache_release(&client_sessions[i]);
  num_sessions = 0;
  g_current_request.session = NULL;
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

int network_get_client_addr_by_token(const uint8_t *token,
                                     struct sockaddr_in *out_addr) {
  if (!token || !out_addr)
    return -1;
  if (!client_sessions)
    network_init_thread_state();
  if (!client_sessions)
    return -1;
  WambleClientSession *session = find_client_session_by_token(token);
  if (!session)
    return -1;
  *out_addr = session->addr;
  return 0;
}

void network_bind_client_token(const struct sockaddr_in *addr,
                               const uint8_t *token) {
  if (!addr || !token || !token_has_any_byte(token))
    return;
  update_client_session(addr, token, 0);
}

int network_get_bound_token_for_addr(const struct sockaddr_in *addr,
                                     uint8_t out_token[TOKEN_LENGTH]) {
  if (!addr || !out_token)
    return -1;
  network_ensure_thread_state_initialized();
  if (!client_sessions)
    return -1;
  WambleClientSession *session = find_client_session(addr);
  if (!session || !token_has_any_byte(session->token))
    return -1;
  memcpy(out_token, session->token, TOKEN_LENGTH);
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

static int receive_message_from_packet_impl(wamble_socket_t sockfd,
                                            const uint8_t *packet,
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
  if (msg->text.uci_len > MAX_UCI_LENGTH)
    return -1;

  int token_valid = token_has_any_byte(msg->token);
  if (!token_valid && !ctrl_allows_anonymous_token(msg->ctrl))
    return -1;

  int is_dup = 0;
  WambleClientSession *session = find_client_session(cliaddr);
  if (!session && token_valid)
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
    if (session && !sockaddr_in_equal(&session->addr, cliaddr)) {
      session->addr = *cliaddr;
      session_map_put(cliaddr, (int)(session - client_sessions));
      session->last_seen = wamble_now_wall();
    }
    uint8_t replay_buf[WAMBLE_MAX_PACKET_SIZE];
    size_t replay_len = terminal_cache_lookup_copy(
        session, msg->seq_num, replay_buf, sizeof(replay_buf));
    if (replay_len > 0)
      network_send_raw_to_client(sockfd, cliaddr, replay_buf, replay_len);
    send_ack(sockfd, msg, cliaddr);
    return -1;
  }

  int reliable_request = 0;
  if (msg->ctrl == WAMBLE_CTRL_CLIENT_HELLO && token_valid &&
      (msg->flags & WAMBLE_FLAG_UNRELIABLE) != 0) {
    update_client_session(cliaddr, msg->token, msg->seq_num);
  } else if (msg->ctrl != WAMBLE_CTRL_ACK &&
             (msg->flags & WAMBLE_FLAG_UNRELIABLE) == 0) {
    update_client_session(cliaddr, msg->token, msg->seq_num);
    reliable_request = 1;
  }

  if (reliable_request) {
    WambleClientSession *admitted = find_client_session(cliaddr);
    network_begin_request_for_session(admitted, msg->seq_num);
  }

  return (int)packet_len;
}

int receive_message_packet(const uint8_t *packet, size_t packet_len,
                           struct WambleMsg *msg,
                           const struct sockaddr_in *cliaddr) {
  return receive_message_from_packet_impl(WAMBLE_INVALID_SOCKET, packet,
                                          packet_len, msg, cliaddr);
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
  return receive_message_from_packet_impl(sockfd, receive_buffer,
                                          (size_t)bytes_received, msg, cliaddr);
}

void send_ack(wamble_socket_t sockfd, const struct WambleMsg *msg,
              const struct sockaddr_in *cliaddr) {
  if (!msg || !cliaddr)
    return;

  struct WambleMsg ack_msg;
  memset(&ack_msg, 0, sizeof(ack_msg));
  ack_msg.ctrl = WAMBLE_CTRL_ACK;
  memcpy(ack_msg.token, msg->token, TOKEN_LENGTH);
  ack_msg.board_id = msg->board_id;
  ack_msg.seq_num = msg->seq_num;
  ack_msg.text.uci_len = 0;
  memset(ack_msg.text.uci, 0, MAX_UCI_LENGTH);
  memset(ack_msg.view.fen, 0, FEN_MAX_LENGTH);

  uint8_t send_buffer[WAMBLE_MAX_PACKET_SIZE];
  size_t serialized_size = 0;
  if (wamble_packet_serialize(&ack_msg, send_buffer, sizeof(send_buffer),
                              &serialized_size, 0) != NET_OK) {

    return;
  }

  int ws_rc = ws_gateway_queue_packet(cliaddr, send_buffer, serialized_size);
  if (ws_rc > 0) {
    (void)ws_gateway_flush_route(cliaddr);
    return;
  }
  if (ws_rc < 0)
    return;

#ifdef WAMBLE_PLATFORM_WINDOWS
  sendto(sockfd, (const char *)send_buffer, (int)serialized_size, 0,
         (const struct sockaddr *)cliaddr, (int)sizeof(*cliaddr));
#else
  sendto(sockfd, (const char *)send_buffer, (size_t)serialized_size, 0,
         (const struct sockaddr *)cliaddr, (wamble_socklen_t)sizeof(*cliaddr));
#endif
}

static uint32_t reserve_reliable_seq_num(const struct sockaddr_in *cliaddr,
                                         const uint8_t *token) {
  static const uint8_t zero_token[TOKEN_LENGTH] = {0};
  const uint8_t *effective_token = token ? token : zero_token;
  WambleClientSession *session = find_client_session(cliaddr);
  if (!session) {
    session = create_client_session(cliaddr, effective_token);
    if (!session) {
      uint32_t seq_num = global_seq_num++;
      if (global_seq_num > (UINT32_MAX - 1000))
        global_seq_num = 1;
      return seq_num;
    }
  }
  return session->next_seq_num++;
}

static NetworkStatus serialize_packet_with_payload(
    uint8_t ctrl, uint8_t header_version, const uint8_t *token,
    uint64_t board_id, uint32_t seq_num, uint8_t flags, const uint8_t *payload,
    size_t payload_len, uint8_t *buffer, size_t buffer_capacity,
    size_t *out_len) {
  if (!buffer || !out_len || buffer_capacity < WAMBLE_HEADER_WIRE_SIZE ||
      payload_len > WAMBLE_MAX_PAYLOAD || payload_len > UINT16_MAX) {
    return NET_ERR_INVALID;
  }

  if (WAMBLE_HEADER_WIRE_SIZE + payload_len > buffer_capacity)
    return NET_ERR_TRUNCATED;

  memset(buffer, 0, WAMBLE_HEADER_WIRE_SIZE);
  buffer[0] = ctrl;
  buffer[1] = flags;
  buffer[2] = header_version ? header_version : WAMBLE_PROTO_VERSION;
  if (token)
    memcpy(buffer + 4, token, TOKEN_LENGTH);
  for (int i = 0; i < 8; i++) {
    buffer[20 + i] = (uint8_t)((board_id >> (8 * (7 - i))) & 0xFFu);
  }
  buffer[28] = (uint8_t)((seq_num >> 24) & 0xFFu);
  buffer[29] = (uint8_t)((seq_num >> 16) & 0xFFu);
  buffer[30] = (uint8_t)((seq_num >> 8) & 0xFFu);
  buffer[31] = (uint8_t)(seq_num & 0xFFu);
  buffer[32] = (uint8_t)((payload_len >> 8) & 0xFFu);
  buffer[33] = (uint8_t)(payload_len & 0xFFu);
  if (payload_len && payload)
    memcpy(buffer + WAMBLE_HEADER_WIRE_SIZE, payload, payload_len);
  *out_len = WAMBLE_HEADER_WIRE_SIZE + payload_len;
  return NET_OK;
}

static void terminal_cache_store_for_current_request(const uint8_t *data,
                                                     size_t len) {
  if (!g_current_request.session)
    return;
  (void)terminal_cache_store(g_current_request.session,
                             g_current_request.seq_num, data, len);
}

static int send_reliable_serialized_packet(
    wamble_socket_t sockfd, const uint8_t *token, uint32_t seq_num,
    const uint8_t *send_buffer, size_t serialized_size,
    const struct sockaddr_in *cliaddr, int timeout_ms, int max_retries) {
  static const uint8_t zero_token[TOKEN_LENGTH] = {0};
  const uint8_t *effective_token = token ? token : zero_token;
  int ws_rc = ws_gateway_queue_packet(cliaddr, send_buffer, serialized_size);
  if (ws_rc > 0) {
    terminal_cache_store_for_current_request(send_buffer, serialized_size);
    if (ws_gateway_flush_route(cliaddr) != 0)
      return -1;
    return 0;
  }
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

    if (bytes_sent < 0)
      return -1;

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
            ack_msg.ctrl == WAMBLE_CTRL_ACK && ack_msg.seq_num == seq_num &&
            sockaddr_in_equal(&ack_cliaddr, cliaddr) &&
            memcmp(ack_msg.token, effective_token, TOKEN_LENGTH) == 0) {
          terminal_cache_store_for_current_request(send_buffer,
                                                   serialized_size);
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

int send_reliable_payload_bytes(wamble_socket_t sockfd, uint8_t ctrl,
                                const uint8_t *token, uint64_t board_id,
                                const uint8_t *payload, size_t payload_len,
                                const struct sockaddr_in *cliaddr,
                                int timeout_ms, int max_retries,
                                int force_fragment) {
  static const uint8_t zero_token[TOKEN_LENGTH] = {0};
  const uint8_t *effective_token = token ? token : zero_token;
  if (!cliaddr)
    return -1;
  if (timeout_ms <= 0)
    timeout_ms = get_config()->timeout_ms;
  if (max_retries <= 0)
    max_retries = get_config()->max_retries;

  if ((force_fragment || payload_len > WAMBLE_MAX_PAYLOAD) && payload_len > 0) {
    if (!ctrl_supports_fragment_payload(ctrl) ||
        payload_len > (size_t)UINT32_MAX || WAMBLE_FRAGMENT_DATA_MAX == 0) {
      return -1;
    }
    size_t chunk_size = (size_t)WAMBLE_FRAGMENT_DATA_MAX;
    size_t needed_chunks = (payload_len + chunk_size - 1u) / chunk_size;
    if (needed_chunks == 0 || needed_chunks > UINT16_MAX)
      return -1;

    uint8_t payload_hash[WAMBLE_FRAGMENT_HASH_LENGTH] = {0};
    crypto_blake2b(payload_hash, WAMBLE_FRAGMENT_HASH_LENGTH, payload,
                   payload_len);
    uint32_t transfer_id = next_fragment_transfer_id();
    uint16_t chunk_count = (uint16_t)needed_chunks;

    for (uint16_t chunk_index = 0; chunk_index < chunk_count; chunk_index++) {
      size_t offset = (size_t)chunk_index * chunk_size;
      size_t chunk_len = payload_len - offset;
      struct WambleMsg fragment = {0};
      if (chunk_len > chunk_size)
        chunk_len = chunk_size;
      fragment.ctrl = ctrl;
      fragment.header_version = WAMBLE_PROTO_VERSION;
      memcpy(fragment.token, effective_token, TOKEN_LENGTH);
      fragment.board_id = board_id;
      fragment.fragment.fragment_version = WAMBLE_FRAGMENT_VERSION;
      fragment.fragment.fragment_hash_algo = WAMBLE_FRAGMENT_HASH_BLAKE2B_256;
      fragment.fragment.fragment_chunk_index = chunk_index;
      fragment.fragment.fragment_chunk_count = chunk_count;
      fragment.fragment.fragment_total_len = (uint32_t)payload_len;
      fragment.fragment.fragment_transfer_id = transfer_id;
      memcpy(fragment.fragment.fragment_hash, payload_hash,
             WAMBLE_FRAGMENT_HASH_LENGTH);
      fragment.fragment.fragment_data_len = (uint16_t)chunk_len;
      if (chunk_len)
        memcpy(fragment.fragment.fragment_data, payload + offset, chunk_len);
      if (send_reliable_message(sockfd, &fragment, cliaddr, timeout_ms,
                                max_retries) != 0) {
        return -1;
      }
    }
    return 0;
  }

  if (payload_len > WAMBLE_MAX_PAYLOAD)
    return -1;

  uint32_t seq_num = reserve_reliable_seq_num(cliaddr, effective_token);
  uint8_t send_buffer[WAMBLE_MAX_PACKET_SIZE];
  size_t serialized_size = 0;
  if (serialize_packet_with_payload(ctrl, WAMBLE_PROTO_VERSION, effective_token,
                                    board_id, seq_num, 0, payload, payload_len,
                                    send_buffer, sizeof(send_buffer),
                                    &serialized_size) != NET_OK) {
    return -1;
  }

  return send_reliable_serialized_packet(sockfd, effective_token, seq_num,
                                         send_buffer, serialized_size, cliaddr,
                                         timeout_ms, max_retries);
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
    fragment.fragment.fragment_version = WAMBLE_FRAGMENT_VERSION;
    fragment.fragment.fragment_hash_algo = WAMBLE_FRAGMENT_HASH_BLAKE2B_256;
    fragment.fragment.fragment_chunk_index = chunk_index;
    fragment.fragment.fragment_chunk_count = chunk_count;
    fragment.fragment.fragment_total_len = (uint32_t)full_len;
    fragment.fragment.fragment_transfer_id = transfer_id;
    memcpy(fragment.fragment.fragment_hash, payload_hash,
           WAMBLE_FRAGMENT_HASH_LENGTH);
    fragment.fragment.fragment_data_len = (uint16_t)chunk_len;
    if (chunk_len) {
      memcpy(fragment.fragment.fragment_data, full_payload + offset, chunk_len);
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
    fragment.fragment.fragment_version = WAMBLE_FRAGMENT_VERSION;
    fragment.fragment.fragment_hash_algo = WAMBLE_FRAGMENT_HASH_BLAKE2B_256;
    fragment.fragment.fragment_chunk_index = chunk_index;
    fragment.fragment.fragment_chunk_count = chunk_count;
    fragment.fragment.fragment_total_len = (uint32_t)full_len;
    fragment.fragment.fragment_transfer_id = transfer_id;
    memcpy(fragment.fragment.fragment_hash, payload_hash,
           WAMBLE_FRAGMENT_HASH_LENGTH);
    fragment.fragment.fragment_data_len = (uint16_t)chunk_len;
    if (chunk_len) {
      memcpy(fragment.fragment.fragment_data, full_payload + offset, chunk_len);
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
  reliable_msg.seq_num = reserve_reliable_seq_num(cliaddr, msg->token);

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
  return send_reliable_serialized_packet(
      sockfd, reliable_msg.token, reliable_msg.seq_num, send_buffer,
      serialized_size, cliaddr, timeout_ms, max_retries);
}

static int send_reliable_spectate_state_update(
    wamble_socket_t sockfd, const uint8_t *token,
    const struct sockaddr_in *cliaddr, SpectatorState state,
    const SpectatorUpdate *event) {
  struct WambleMsg out = {0};
  out.ctrl = WAMBLE_CTRL_SPECTATE_UPDATE;
  if (token)
    memcpy(out.token, token, TOKEN_LENGTH);
  if (event) {
    out.board_id = event->board_id;
    out.flags = (uint8_t)(event->flags & ~WAMBLE_FLAG_UNRELIABLE);
    snprintf(out.view.fen, sizeof(out.view.fen), "%s", event->fen);
  }
  out.extensions.count = 1;
  snprintf(out.extensions.fields[0].key, sizeof(out.extensions.fields[0].key),
           "%s", "spectate.state");
  out.extensions.fields[0].value_type = WAMBLE_TREATMENT_VALUE_STRING;
  snprintf(out.extensions.fields[0].string_value,
           sizeof(out.extensions.fields[0].string_value), "%s",
           state == SPECTATOR_STATE_FOCUS
               ? "focus"
               : (state == SPECTATOR_STATE_SUMMARY ? "summary" : "idle"));
  if (event && event->summary_generation > 0 &&
      out.extensions.count < WAMBLE_MAX_MESSAGE_EXT_FIELDS) {
    uint8_t idx = out.extensions.count++;
    snprintf(out.extensions.fields[idx].key,
             sizeof(out.extensions.fields[idx].key), "%s",
             "spectate.summary_generation");
    out.extensions.fields[idx].value_type = WAMBLE_TREATMENT_VALUE_INT;
    out.extensions.fields[idx].int_value = (int64_t)event->summary_generation;
  }
  return send_reliable_message(sockfd, &out, cliaddr, get_config()->timeout_ms,
                               get_config()->max_retries);
}

static int send_reliable_spectate_state_snapshot(
    wamble_socket_t sockfd, const uint8_t *token,
    const struct sockaddr_in *cliaddr, SpectatorState state) {
  int cap = get_config()->max_boards + 2;
  if (cap < 1)
    cap = 1;

  SpectatorUpdate *events =
      (SpectatorUpdate *)calloc((size_t)cap, sizeof(*events));
  if (!events)
    return -1;

  int count = spectator_collect_state_snapshot(token, events, cap);
  int rc = 0;
  if (count <= 0) {
    rc = send_reliable_spectate_state_update(sockfd, token, cliaddr, state,
                                             NULL);
  } else {
    for (int i = 0; i < count; i++) {
      if (send_reliable_spectate_state_update(sockfd, token, cliaddr, state,
                                              &events[i]) != 0) {
        rc = -1;
        break;
      }
    }
  }

  free(events);
  return rc;
}

static int resolve_spectate_state_sync(SpectatorState *out_state,
                                       uint64_t *out_focus_board_id,
                                       const uint8_t *token) {
  if (!out_state || !out_focus_board_id || !token)
    return -1;
  *out_state = SPECTATOR_STATE_IDLE;
  *out_focus_board_id = 0;
  if (spectator_get_state_by_token(token, out_state, out_focus_board_id) == 0)
    return 0;
  return 0;
}

int send_reliable_spectate_state_sync(wamble_socket_t sockfd,
                                      const uint8_t *token,
                                      const struct sockaddr_in *cliaddr) {
  SpectatorState state = SPECTATOR_STATE_IDLE;
  uint64_t focus_board_id = 0;
  if (resolve_spectate_state_sync(&state, &focus_board_id, token) != 0)
    return -1;
  (void)focus_board_id;
  if (state == SPECTATOR_STATE_IDLE)
    return send_reliable_spectate_state_update(sockfd, token, cliaddr, state,
                                               NULL);
  return send_reliable_spectate_state_snapshot(sockfd, token, cliaddr, state);
}

int send_unreliable_packet(wamble_socket_t sockfd, const struct WambleMsg *msg,
                           const struct sockaddr_in *cliaddr) {
  if (!msg || !cliaddr)
    return -1;
  uint8_t buffer[WAMBLE_MAX_PACKET_SIZE];
  size_t serialized_size = 0;
  uint8_t send_flags = (uint8_t)(msg->flags | WAMBLE_FLAG_UNRELIABLE);
  NetworkStatus serialize_status = wamble_packet_serialize(
      msg, buffer, sizeof(buffer), &serialized_size, send_flags);
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
    } else {
      terminal_cache_release(&client_sessions[read_idx]);
    }
  }

  if (write_idx != num_sessions) {
    num_sessions = write_idx;
    g_current_request.session = NULL;
    session_map_init();
    for (int i = 0; i < num_sessions; i++) {
      session_map_put(&client_sessions[i].addr, i);
    }
  }
}

int wamble_socket_bound_port(wamble_socket_t sock) {
  struct sockaddr_in addr;
  wamble_socklen_t len = (wamble_socklen_t)sizeof(addr);
  if (getsockname(sock, (struct sockaddr *)&addr, &len) != 0)
    return -1;
  return (int)ntohs(addr.sin_port);
}
