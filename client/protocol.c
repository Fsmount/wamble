#include "wamble/wamble_client.h"

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
#define WAMBLE_EXT_MAGIC_0 0x57
#define WAMBLE_EXT_MAGIC_1 0x58
#define WAMBLE_EXT_VERSION 1

static const char base64url_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
static inline uint64_t host_to_net64(uint64_t x) { return x; }
static inline uint64_t net_to_host64(uint64_t x) { return x; }
#else
static inline uint64_t host_to_net64(uint64_t x) {
  uint32_t hi = (uint32_t)(x >> 32);
  uint32_t lo = (uint32_t)(x & 0xffffffffu);
  return ((uint64_t)htonl(lo) << 32) | htonl(hi);
}

static inline uint64_t net_to_host64(uint64_t x) {
  uint32_t hi = (uint32_t)(x >> 32);
  uint32_t lo = (uint32_t)(x & 0xffffffffu);
  return ((uint64_t)ntohl(lo) << 32) | ntohl(hi);
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
      {
        uint16_t sbe = htons((uint16_t)slen);
        memcpy(dst + off, &sbe, 2);
      }
      off += 2;
      if (slen) {
        memcpy(dst + off, field->string_value, slen);
        off += slen;
      }
    } else if (field->value_type == WAMBLE_TREATMENT_VALUE_INT) {
      if (off + 8 > cap)
        return NET_ERR_TRUNCATED;
      {
        uint64_t ibe = host_to_net64((uint64_t)field->int_value);
        memcpy(dst + off, &ibe, 8);
      }
      off += 8;
    } else if (field->value_type == WAMBLE_TREATMENT_VALUE_DOUBLE) {
      if (off + 8 > cap)
        return NET_ERR_TRUNCATED;
      {
        uint64_t bits = 0;
        memcpy(&bits, &field->double_value, sizeof(bits));
        bits = host_to_net64(bits);
        memcpy(dst + off, &bits, 8);
      }
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
  {
    size_t body_len = off;
    if (off + 4 > cap)
      return NET_ERR_TRUNCATED;
    dst[off++] = WAMBLE_EXT_MAGIC_0;
    dst[off++] = WAMBLE_EXT_MAGIC_1;
    {
      uint16_t body_be = htons((uint16_t)body_len);
      memcpy(dst + off, &body_be, 2);
    }
    off += 2;
    *out_len = off;
  }
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
      {
        uint64_t ibe = 0;
        memcpy(&ibe, p, 8);
        field->int_value = (int64_t)net_to_host64(ibe);
      }
      p += 8;
    } else if (field->value_type == WAMBLE_TREATMENT_VALUE_DOUBLE) {
      if ((size_t)(end - p) < 8)
        return NET_ERR_INVALID;
      {
        uint64_t bits = 0;
        memcpy(&bits, p, 8);
        bits = net_to_host64(bits);
        memcpy(&field->double_value, &bits, sizeof(bits));
      }
      p += 8;
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
  {
    size_t chunk_len = (size_t)msg->fragment_data_len;
    size_t need = WAMBLE_FRAGMENT_WIRE_HEADER_LENGTH + chunk_len;
    if (need > payload_capacity)
      return NET_ERR_TRUNCATED;

    payload[0] = WAMBLE_FRAGMENT_VERSION;
    payload[1] = WAMBLE_FRAGMENT_HASH_BLAKE2B_256;
    {
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
    }
    if (chunk_len) {
      memcpy(payload + WAMBLE_FRAGMENT_WIRE_HEADER_LENGTH, msg->fragment_data,
             chunk_len);
    }
    *payload_len = need;
  }
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
  {
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
  }
  *is_fragmented = 1;
  return NET_OK;
}

static NetworkStatus encode_profile_target_payload(const struct WambleMsg *msg,
                                                   uint8_t *payload,
                                                   size_t payload_capacity,
                                                   size_t *out_len) {
  size_t name_len = 0;
  if (!msg || !payload || !out_len)
    return NET_ERR_INVALID;
  name_len = msg->profile_name_len
                 ? (size_t)msg->profile_name_len
                 : strnlen(msg->profile_name, PROFILE_NAME_MAX_LENGTH - 1);
  if (name_len > 255)
    return NET_ERR_INVALID;
  if (1 + name_len > payload_capacity)
    return NET_ERR_TRUNCATED;
  payload[0] = (uint8_t)name_len;
  if (name_len)
    memcpy(&payload[1], msg->profile_name, name_len);
  *out_len = 1 + name_len;
  return NET_OK;
}

static NetworkStatus decode_profile_target_payload(const uint8_t *payload,
                                                   size_t payload_len,
                                                   struct WambleMsg *msg) {
  if (!payload || !msg)
    return NET_ERR_INVALID;
  if (payload_len < 1)
    return NET_ERR_TRUNCATED;
  msg->profile_name_len = payload[0];
  if ((size_t)msg->profile_name_len > payload_len - 1)
    return NET_ERR_INVALID;
  if (msg->profile_name_len)
    memcpy(msg->profile_name, &payload[1], msg->profile_name_len);
  msg->profile_name[msg->profile_name_len] = '\0';
  return NET_OK;
}

NetworkStatus wamble_payload_serialize(const struct WambleMsg *msg,
                                       uint8_t *payload,
                                       size_t payload_capacity, size_t *out_len,
                                       uint8_t *out_transport_flags) {
  if (!msg || !payload || !out_len)
    return NET_ERR_INVALID;

  uint8_t transport_flags = 0;
  if (ctrl_supports_fragment_payload(msg->ctrl) &&
      msg_uses_fragment_payload(msg)) {
    if (msg->ext_count > 0)
      return NET_ERR_INVALID;
    {
      size_t fragment_len = 0;
      NetworkStatus frag_status = encode_fragment_payload(
          msg, payload, payload_capacity, &fragment_len);
      if (frag_status != NET_OK)
        return frag_status;
      *out_len = fragment_len;
    }
    transport_flags |= WAMBLE_FLAG_FRAGMENT_PAYLOAD;
    if (out_transport_flags)
      *out_transport_flags = transport_flags;
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
    {
      uint64_t parent_be = host_to_net64(msg->prediction_parent_id);
      memcpy(&payload[1 + msg->uci_len], &parent_be, 8);
    }
    body_len = need;
    break;
  }
  case WAMBLE_CTRL_SERVER_HELLO:
  case WAMBLE_CTRL_BOARD_UPDATE:
  case WAMBLE_CTRL_SPECTATE_UPDATE: {
    size_t len = strnlen(msg->fen, FEN_MAX_LENGTH);
    if (len > payload_capacity)
      return NET_ERR_TRUNCATED;
    if (len)
      memcpy(payload, msg->fen, len);
    body_len = len;
    break;
  }
  case WAMBLE_CTRL_SERVER_NOTIFICATION: {
    size_t len = strnlen(msg->fen, FEN_MAX_LENGTH);
    if (1 + len > payload_capacity)
      return NET_ERR_TRUNCATED;
    payload[0] = msg->notification_type;
    if (len)
      memcpy(payload + 1, msg->fen, len);
    body_len = 1 + len;
    break;
  }
  case WAMBLE_CTRL_PROFILE_INFO:
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
  case WAMBLE_CTRL_GET_PROFILE_TOS:
  case WAMBLE_CTRL_ACCEPT_PROFILE_TOS: {
    NetworkStatus st = encode_profile_target_payload(
        msg, payload, payload_capacity, &body_len);
    if (st != NET_OK)
      return st;
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
      uint64_t be = 0;
      uint32_t gp_be = htonl(msg->player_stats_games_played);
      uint32_t c960_be = htonl(msg->player_stats_chess960_games_played);
      memcpy(&bits, &msg->player_stats_score, sizeof(double));
      be = host_to_net64(bits);
      for (int i = 0; i < 8; i++)
        payload[i] = (uint8_t)((be >> (8 * (7 - i))) & 0xFF);
      memcpy(payload + 8, &gp_be, 4);
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
    {
      uint32_t self_rank_be = htonl(msg->leaderboard_self_rank);
      memcpy(payload + 2, &self_rank_be, 4);
    }
    size_t offset = 6;
    for (uint8_t i = 0; i < count; i++) {
      const WambleLeaderboardEntry *e = &msg->leaderboard[i];
      uint32_t rank_be = htonl(e->rank);
      uint64_t sid_be = host_to_net64(e->session_id);
      uint64_t score_bits = 0;
      uint64_t rating_bits = 0;
      uint32_t games_be = htonl(e->games_played);
      memcpy(&score_bits, &e->score, sizeof(double));
      memcpy(&rating_bits, &e->rating, sizeof(double));
      score_bits = host_to_net64(score_bits);
      rating_bits = host_to_net64(rating_bits);
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
      uint16_t ply_be = htons(e->target_ply);
      memcpy(&points_bits, &e->points_awarded, sizeof(double));
      points_bits = host_to_net64(points_bits);
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

  if (msg->ext_count > 0) {
    size_t ext_len = 0;
    NetworkStatus ext_status = encode_msg_extensions(
        msg, payload + body_len, payload_capacity - body_len, &ext_len);
    if (ext_status != NET_OK)
      return ext_status;
    if (ext_len > 0) {
      body_len += ext_len;
      transport_flags |= WAMBLE_FLAG_EXT_PAYLOAD;
    }
  }

  *out_len = body_len;
  if (out_transport_flags)
    *out_transport_flags = transport_flags;
  return NET_OK;
}

static NetworkStatus decode_message_payload(uint8_t ctrl, uint8_t flags,
                                            const uint8_t *payload,
                                            size_t payload_len,
                                            struct WambleMsg *msg) {
  if (!msg)
    return NET_ERR_INVALID;

  size_t base_len = payload_len;
  msg->ext_count = 0;
  if (payload && payload_len >= 4) {
    int ext_mandatory = (flags & WAMBLE_FLAG_EXT_PAYLOAD) != 0;
    NetworkStatus ext_status =
        decode_msg_extensions(payload, payload_len, msg, &base_len);
    if (ext_mandatory) {
      if (ext_status != NET_OK)
        return ext_status;
      payload_len = base_len;
    } else if (ext_status == NET_OK) {
      payload_len = base_len;
    } else {
      msg->ext_count = 0;
    }
  }

  switch (ctrl) {
  case WAMBLE_CTRL_CLIENT_HELLO:
  case WAMBLE_CTRL_ACK:
  case WAMBLE_CTRL_LIST_PROFILES:
  case WAMBLE_CTRL_CLIENT_GOODBYE:
  case WAMBLE_CTRL_SPECTATE_GAME:
  case WAMBLE_CTRL_SPECTATE_STOP:
  case WAMBLE_CTRL_LOGOUT:
    break;
  case WAMBLE_CTRL_LOGIN_CHALLENGE:
    if (payload_len != WAMBLE_LOGIN_CHALLENGE_LENGTH)
      return NET_ERR_INVALID;
    memcpy(msg->login_challenge, payload, WAMBLE_LOGIN_CHALLENGE_LENGTH);
    break;
  case WAMBLE_CTRL_GET_LEADERBOARD:
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
  case WAMBLE_CTRL_GET_PREDICTIONS:
    if (payload_len > 2)
      return NET_ERR_INVALID;
    msg->prediction_depth = (payload_len >= 1) ? payload[0] : 0;
    msg->prediction_limit = (payload_len >= 2) ? payload[1] : 0;
    break;
  case WAMBLE_CTRL_PLAYER_MOVE:
    if (payload_len < 1)
      return NET_ERR_TRUNCATED;
    msg->uci_len = payload[0];
    if ((size_t)msg->uci_len > MAX_UCI_LENGTH ||
        (size_t)msg->uci_len > payload_len - 1) {
      return NET_ERR_INVALID;
    }
    memcpy(msg->uci, &payload[1], msg->uci_len);
    break;
  case WAMBLE_CTRL_SUBMIT_PREDICTION:
    if (payload_len < 1 + 8)
      return NET_ERR_TRUNCATED;
    msg->uci_len = payload[0];
    if ((size_t)msg->uci_len > MAX_UCI_LENGTH ||
        payload_len != (size_t)1 + msg->uci_len + 8) {
      return NET_ERR_INVALID;
    }
    memcpy(msg->uci, &payload[1], msg->uci_len);
    {
      uint64_t parent_be = 0;
      memcpy(&parent_be, &payload[1 + msg->uci_len], 8);
      msg->prediction_parent_id = net_to_host64(parent_be);
    }
    break;
  case WAMBLE_CTRL_SERVER_HELLO:
  case WAMBLE_CTRL_BOARD_UPDATE:
  case WAMBLE_CTRL_SPECTATE_UPDATE:
  case WAMBLE_CTRL_ERROR:
    if (ctrl == WAMBLE_CTRL_ERROR) {
      if (payload_len < 3)
        return NET_ERR_TRUNCATED;
      {
        uint16_t code_net = (uint16_t)((payload[0] << 8) | payload[1]);
        uint8_t rlen = payload[2];
        if ((size_t)3 + rlen > payload_len)
          return NET_ERR_TRUNCATED;
        msg->error_code = ntohs(code_net);
        {
          size_t copy = rlen < FEN_MAX_LENGTH - 1 ? rlen : (FEN_MAX_LENGTH - 1);
          if (copy)
            memcpy(msg->error_reason, &payload[3], copy);
          msg->error_reason[copy] = '\0';
        }
      }
    } else {
      size_t copy =
          payload_len < FEN_MAX_LENGTH - 1 ? payload_len : (FEN_MAX_LENGTH - 1);
      if (copy)
        memcpy(msg->fen, payload, copy);
      msg->fen[copy] = '\0';
    }
    break;
  case WAMBLE_CTRL_SERVER_NOTIFICATION:
    if (payload_len < 1)
      return NET_ERR_TRUNCATED;
    msg->notification_type = payload[0];
    {
      size_t text_len = payload_len - 1;
      size_t copy =
          text_len < FEN_MAX_LENGTH - 1 ? text_len : (FEN_MAX_LENGTH - 1);
      if (copy)
        memcpy(msg->fen, payload + 1, copy);
      msg->fen[copy] = '\0';
    }
    break;
  case WAMBLE_CTRL_LOGIN_FAILED:
    if (payload_len < 3)
      return NET_ERR_TRUNCATED;
    {
      uint16_t code_net = (uint16_t)((payload[0] << 8) | payload[1]);
      uint8_t rlen = payload[2];
      if ((size_t)3 + rlen > payload_len)
        return NET_ERR_TRUNCATED;
      msg->error_code = ntohs(code_net);
      {
        size_t copy = rlen < FEN_MAX_LENGTH - 1 ? rlen : (FEN_MAX_LENGTH - 1);
        if (copy)
          memcpy(msg->error_reason, &payload[3], copy);
        msg->error_reason[copy] = '\0';
      }
    }
    break;
  case WAMBLE_CTRL_PROFILE_INFO: {
    size_t copy =
        payload_len < FEN_MAX_LENGTH - 1 ? payload_len : (FEN_MAX_LENGTH - 1);
    if (copy)
      memcpy(msg->profile_info, payload, copy);
    msg->profile_info[copy] = '\0';
    msg->profile_info_len = (uint16_t)copy;
    break;
  }
  case WAMBLE_CTRL_PROFILE_TOS_DATA:
    if (payload_len > WAMBLE_FRAGMENT_DATA_MAX)
      return NET_ERR_TRUNCATED;
    if (payload_len)
      memcpy(msg->fragment_data, payload, payload_len);
    msg->fragment_data_len = (uint16_t)payload_len;
    {
      size_t copy =
          payload_len < FEN_MAX_LENGTH - 1 ? payload_len : (FEN_MAX_LENGTH - 1);
      if (copy)
        memcpy(msg->profile_info, payload, copy);
      msg->profile_info[copy] = '\0';
      msg->profile_info_len = (uint16_t)copy;
    }
    msg->fragment_total_len = (uint32_t)payload_len;
    break;
  case WAMBLE_CTRL_PROFILES_LIST: {
    size_t copy =
        payload_len < FEN_MAX_LENGTH - 1 ? payload_len : (FEN_MAX_LENGTH - 1);
    if (copy)
      memcpy(msg->profiles_list, payload, copy);
    msg->profiles_list[copy] = '\0';
    msg->profiles_list_len = (uint16_t)copy;
    break;
  }
  case WAMBLE_CTRL_GET_PROFILE_INFO:
  case WAMBLE_CTRL_GET_PROFILE_TOS:
  case WAMBLE_CTRL_ACCEPT_PROFILE_TOS:
    return decode_profile_target_payload(payload, payload_len, msg);
  case WAMBLE_CTRL_GET_LEGAL_MOVES:
    if (payload_len < 1)
      return NET_ERR_TRUNCATED;
    msg->move_square = payload[0];
    break;
  case WAMBLE_CTRL_PLAYER_STATS_DATA:
    if (payload_len < 12)
      return NET_ERR_TRUNCATED;
    {
      uint64_t be = 0;
      uint64_t host = 0;
      double score = 0.0;
      for (int i = 0; i < 8; i++)
        be = (be << 8) | payload[i];
      host = net_to_host64(be);
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
    }
    break;
  case WAMBLE_CTRL_LOGIN_REQUEST:
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
  case WAMBLE_CTRL_LEGAL_MOVES:
    if (payload_len < 2)
      return NET_ERR_TRUNCATED;
    msg->move_square = payload[0];
    msg->move_count = payload[1];
    if (msg->move_count > WAMBLE_MAX_LEGAL_MOVES)
      return NET_ERR_INVALID;
    if (payload_len < 2 + (size_t)msg->move_count * 3)
      return NET_ERR_TRUNCATED;
    {
      size_t offset = 2;
      for (uint8_t i = 0; i < msg->move_count; i++) {
        msg->moves[i].from = payload[offset++];
        msg->moves[i].to = payload[offset++];
        msg->moves[i].promotion = (int8_t)payload[offset++];
      }
    }
    break;
  case WAMBLE_CTRL_LEADERBOARD_DATA:
    if (payload_len < 6)
      return NET_ERR_TRUNCATED;
    msg->leaderboard_type = payload[0];
    msg->leaderboard_count = payload[1];
    if (msg->leaderboard_count > WAMBLE_MAX_LEADERBOARD_ENTRIES)
      return NET_ERR_INVALID;
    if (payload_len < 1 + 1 + 4 + (size_t)msg->leaderboard_count * 32)
      return NET_ERR_TRUNCATED;
    {
      uint32_t self_rank_be = 0;
      memcpy(&self_rank_be, payload + 2, 4);
      msg->leaderboard_self_rank = ntohl(self_rank_be);
    }
    {
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
    }
    break;
  case WAMBLE_CTRL_PREDICTION_DATA:
    if (payload_len < 1)
      return NET_ERR_TRUNCATED;
    msg->prediction_count = payload[0];
    if (msg->prediction_count > WAMBLE_MAX_PREDICTION_ENTRIES)
      return NET_ERR_INVALID;
    if (payload_len <
        1 + (size_t)msg->prediction_count * WAMBLE_PREDICTION_ENTRY_WIRE_SIZE) {
      return NET_ERR_TRUNCATED;
    }
    {
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
    }
    break;
  default:
    break;
  }
  return NET_OK;
}

NetworkStatus wamble_message_deserialize_payload(uint8_t ctrl, uint8_t flags,
                                                 const uint8_t *payload,
                                                 size_t payload_len,
                                                 struct WambleMsg *msg) {
  if (!msg)
    return NET_ERR_INVALID;
  memset(msg, 0, sizeof(*msg));
  msg->ctrl = ctrl;
  msg->flags = flags;
  msg->header_version = WAMBLE_PROTO_VERSION;
  return decode_message_payload(ctrl, flags, payload, payload_len, msg);
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
  hdr.version =
      (msg->header_version != 0) ? msg->header_version : WAMBLE_PROTO_VERSION;
  memcpy(hdr.token, msg->token, TOKEN_LENGTH);
  hdr.board_id = host_to_net64(msg->board_id);
  hdr.seq_num = htonl(msg->seq_num);

  uint8_t payload[WAMBLE_MAX_PAYLOAD];
  size_t payload_len = 0;
  uint8_t transport_flags = 0;
  NetworkStatus payload_status = wamble_payload_serialize(
      msg, payload, sizeof(payload), &payload_len, &transport_flags);
  if (payload_status != NET_OK)
    return payload_status;
  hdr.flags |= transport_flags;
  hdr.payload_len = htons((uint16_t)payload_len);

  if (WAMBLE_HEADER_SIZE + payload_len > buffer_capacity)
    return NET_ERR_TRUNCATED;

  memcpy(buffer, &hdr, sizeof(hdr));
  if (payload_len)
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
  if (hdr.reserved != 0)
    return NET_ERR_INVALID;

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
  if (has_fragment_payload) {
    int is_fragmented = 0;
    if (!ctrl_supports_fragment_payload(hdr.ctrl))
      return NET_ERR_INVALID;
    {
      NetworkStatus frag_status =
          decode_fragment_payload(payload, payload_len, msg, &is_fragmented);
      if (frag_status != NET_OK)
        return frag_status;
    }
    if (!is_fragmented)
      return NET_ERR_INVALID;

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
        {
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
      }
      break;
    default:
      break;
    }
    return NET_OK;
  }
  return decode_message_payload(hdr.ctrl, hdr.flags, payload, payload_len, msg);
}

void format_token_for_url(const uint8_t *token, char *url_buffer) {
  if (!token || !url_buffer)
    return;

  int j = 0;
  for (int i = 0; i < 16; i += 3) {
    uint32_t block = 0;
    int bytes_in_block = (i + 3 <= 16) ? 3 : (16 - i);
    for (int k = 0; k < bytes_in_block; k++)
      block |= ((uint32_t)token[i + k]) << (8 * (2 - k));
    for (int k = 0; k < 4; k++) {
      if (j >= 22)
        break;
      url_buffer[j++] = base64url_chars[(block >> (6 * (3 - k))) & 0x3F];
    }
  }
  url_buffer[22] = '\0';
}

int decode_token_from_url(const char *url_string, uint8_t *token_buffer) {
  if (!url_string || !token_buffer || strlen(url_string) != 22)
    return -1;

  uint8_t decode_table[256];
  memset(decode_table, 0xFF, sizeof(decode_table));
  for (int i = 0; i < 64; i++)
    decode_table[(unsigned char)base64url_chars[i]] = (uint8_t)i;

  memset(token_buffer, 0, 16);
  int token_pos = 0;
  for (int i = 0; i < 22; i += 4) {
    uint32_t block = 0;
    for (int j = 0; j < 4 && (i + j) < 22; j++) {
      unsigned char c = (unsigned char)url_string[i + j];
      if (decode_table[c] == 0xFF)
        return -1;
      block |= ((uint32_t)decode_table[c]) << (6 * (3 - j));
    }
    for (int j = 0; j < 3 && token_pos < 16; j++)
      token_buffer[token_pos++] = (uint8_t)((block >> (8 * (2 - j))) & 0xFF);
  }
  return 0;
}

/* --- Fragment reassembly --- */

void crypto_blake2b(uint8_t *hash, size_t hash_size, const uint8_t *msg,
                    size_t msg_size);

WAMBLE_WEAK void
wamble_fragment_reassembly_init(WambleFragmentReassembly *reassembly) {
  if (!reassembly)
    return;
  memset(reassembly, 0, sizeof(*reassembly));
  reassembly->integrity = WAMBLE_FRAGMENT_INTEGRITY_UNKNOWN;
}

WAMBLE_WEAK void
wamble_fragment_reassembly_reset(WambleFragmentReassembly *reassembly) {
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

WAMBLE_WEAK void
wamble_fragment_reassembly_free(WambleFragmentReassembly *reassembly) {
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

WAMBLE_WEAK WambleFragmentReassemblyResult wamble_fragment_reassembly_push(
    WambleFragmentReassembly *reassembly, const struct WambleMsg *msg) {
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
