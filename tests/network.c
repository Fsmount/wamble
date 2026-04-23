#include "common/wamble_test.h"
#include "common/wamble_test_helpers.h"
#include "wamble/wamble.h"
#include "wamble/wamble_client.h"
#include "wamble/wamble_db.h"

void crypto_blake2b(uint8_t *hash, size_t hash_size, const uint8_t *msg,
                    size_t msg_size);

static void write_be_u64(uint8_t out[8], uint64_t v) {
  uint64_t be = wamble_host_to_net64(v);
  memcpy(out, &be, sizeof(be));
}

WAMBLE_TEST(token_base64url_roundtrip) {
  uint8_t token[TOKEN_LENGTH];
  for (int i = 0; i < TOKEN_LENGTH; i++)
    token[i] = (uint8_t)(i * 7 + 3);
  char url[23];
  format_token_for_url(token, url);
  uint8_t out[TOKEN_LENGTH];
  T_ASSERT_STATUS_OK(decode_token_from_url(url, out));
  T_ASSERT_EQ_INT((int)strlen(url), 22);
  for (int i = 0; i < 22; i++) {
    char c = url[i];
    int ok = ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_');
    T_ASSERT(ok);
  }
  for (int i = 0; i < TOKEN_LENGTH; i++)
    T_ASSERT(token[i] == out[i]);
  return 0;
}

typedef struct {
  wamble_socket_t sock;
  struct sockaddr_in from;
  struct WambleMsg msg;
  int received;
} RecvOneCtx;

typedef struct {
  wamble_socket_t sockfd;
  struct WambleMsg msg;
  struct sockaddr_in cliaddr;
  int trust_tier;
  const char *profile_name;
  ServerStatus status;
} HandleMessageCtx;

typedef struct {
  wamble_socket_t srv;
  wamble_socket_t cli;
  struct sockaddr_in cliaddr;
} UdpLoopbackPair;

static void *recv_one_thread(void *arg) {
  RecvOneCtx *c = arg;
  fd_set rfds;
  struct timeval tv;
  FD_ZERO(&rfds);
  FD_SET(c->sock, &rfds);
  tv.tv_sec = 0;
  tv.tv_usec = 600 * 1000;
#ifdef WAMBLE_PLATFORM_WINDOWS
  int ready = select(0, &rfds, NULL, NULL, &tv);
#else
  int ready = select(c->sock + 1, &rfds, NULL, NULL, &tv);
#endif
  int rc = (ready > 0) ? receive_message(c->sock, &c->msg, &c->from) : 0;
  c->received = (rc > 0) ? 1 : 0;
  return NULL;
}

static void *recv_one_and_ack_thread(void *arg) {
  RecvOneCtx *c = arg;
  fd_set rfds;
  struct timeval tv;
  FD_ZERO(&rfds);
  FD_SET(c->sock, &rfds);
  tv.tv_sec = 0;
  tv.tv_usec = 600 * 1000;
#ifdef WAMBLE_PLATFORM_WINDOWS
  int ready = select(0, &rfds, NULL, NULL, &tv);
#else
  int ready = select(c->sock + 1, &rfds, NULL, NULL, &tv);
#endif
  int rc = (ready > 0) ? receive_message(c->sock, &c->msg, &c->from) : 0;
  c->received = (rc > 0) ? 1 : 0;
  if (c->received && (c->msg.flags & WAMBLE_FLAG_UNRELIABLE) == 0 &&
      c->msg.ctrl != WAMBLE_CTRL_ACK) {
    send_ack(c->sock, &c->msg, &c->from);
  }
  return NULL;
}

static void *handle_message_thread(void *arg) {
  HandleMessageCtx *ctx = arg;
  ctx->status = handle_message(ctx->sockfd, &ctx->msg, &ctx->cliaddr,
                               ctx->trust_tier, ctx->profile_name);
  return NULL;
}

static int recv_message_with_timeout(wamble_socket_t sock,
                                     struct WambleMsg *msg,
                                     struct sockaddr_in *from, int timeout_ms) {
  fd_set rfds;
  struct timeval tv;
  FD_ZERO(&rfds);
  FD_SET(sock, &rfds);
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
#ifdef WAMBLE_PLATFORM_WINDOWS
  int ready = select(0, &rfds, NULL, NULL, &tv);
#else
  int ready = select(sock + 1, &rfds, NULL, NULL, &tv);
#endif
  if (ready <= 0)
    return ready;
  return receive_message(sock, msg, from);
}

static int init_udp_loopback_pair(UdpLoopbackPair *pair) {
  struct sockaddr_in bindaddr;
  wamble_socklen_t slen;

  T_ASSERT(pair != NULL);
  memset(pair, 0, sizeof(*pair));
  pair->srv = create_and_bind_socket(0);
  T_ASSERT(pair->srv != WAMBLE_INVALID_SOCKET);
  pair->cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(pair->cli != WAMBLE_INVALID_SOCKET);

  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(
      bind(pair->cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  slen = (wamble_socklen_t)sizeof(pair->cliaddr);
  T_ASSERT_STATUS_OK(
      getsockname(pair->cli, (struct sockaddr *)&pair->cliaddr, &slen));
  return 0;
}

static void cleanup_udp_loopback_pair(UdpLoopbackPair *pair) {
  if (!pair)
    return;
  if (pair->cli != WAMBLE_INVALID_SOCKET)
    wamble_close_socket(pair->cli);
  if (pair->srv != WAMBLE_INVALID_SOCKET)
    wamble_close_socket(pair->srv);
  pair->cli = WAMBLE_INVALID_SOCKET;
  pair->srv = WAMBLE_INVALID_SOCKET;
}

static int ack_terminal_and_expect_request_ack(wamble_socket_t cli,
                                               const struct WambleMsg *terminal,
                                               const struct sockaddr_in *from,
                                               uint32_t request_seq) {
  struct WambleMsg rx = {0};
  struct sockaddr_in ack_from;

  T_ASSERT(terminal != NULL);
  T_ASSERT(from != NULL);
  send_ack(cli, terminal, from);
  T_ASSERT(recv_message_with_timeout(cli, &rx, &ack_from, 1000) > 0);
  T_ASSERT_EQ_INT(rx.ctrl, WAMBLE_CTRL_ACK);
  T_ASSERT_EQ_INT((int)rx.seq_num, (int)request_seq);
  return 0;
}

typedef struct {
  wamble_socket_t sock;
  struct sockaddr_in from;
  uint8_t expected_ctrl;
  int received;
  int expected_chunks;
  int chunk_count;
  uint32_t total_len;
  uint32_t transfer_id;
  uint8_t hash_algo;
  uint8_t hash[WAMBLE_FRAGMENT_HASH_LENGTH];
  uint8_t assembled[8192];
  size_t assembled_len;
} RecvTosFragmentsCtx;

static void *recv_tos_fragments_and_ack_thread(void *arg) {
  RecvTosFragmentsCtx *c = arg;
  uint8_t expected_ctrl =
      c->expected_ctrl ? c->expected_ctrl : WAMBLE_CTRL_PROFILE_TOS_DATA;
  int quiet_polls = 0;
  while (quiet_polls < 3) {
    fd_set rfds;
    struct timeval tv;
    FD_ZERO(&rfds);
    FD_SET(c->sock, &rfds);
    tv.tv_sec = 0;
    tv.tv_usec = 350 * 1000;
#ifdef WAMBLE_PLATFORM_WINDOWS
    int ready = select(0, &rfds, NULL, NULL, &tv);
#else
    int ready = select(c->sock + 1, &rfds, NULL, NULL, &tv);
#endif
    if (ready <= 0) {
      quiet_polls++;
      if (c->expected_chunks > 0 && c->chunk_count >= c->expected_chunks)
        break;
      continue;
    }
    quiet_polls = 0;
    struct WambleMsg in = {0};
    int rc = receive_message(c->sock, &in, &c->from);
    if (rc <= 0)
      continue;
    if ((in.flags & WAMBLE_FLAG_UNRELIABLE) == 0 &&
        in.ctrl != WAMBLE_CTRL_ACK) {
      send_ack(c->sock, &in, &c->from);
    }
    if (in.ctrl != expected_ctrl ||
        in.fragment.fragment_version != WAMBLE_FRAGMENT_VERSION)
      continue;
    if (c->expected_chunks == 0) {
      c->expected_chunks = (int)in.fragment.fragment_chunk_count;
      c->total_len = in.fragment.fragment_total_len;
      c->transfer_id = in.fragment.fragment_transfer_id;
      c->hash_algo = in.fragment.fragment_hash_algo;
      memcpy(c->hash, in.fragment.fragment_hash, WAMBLE_FRAGMENT_HASH_LENGTH);
    } else if (in.fragment.fragment_transfer_id != c->transfer_id ||
               in.fragment.fragment_hash_algo != c->hash_algo ||
               in.fragment.fragment_chunk_count !=
                   (uint16_t)c->expected_chunks ||
               in.fragment.fragment_total_len != c->total_len) {
      continue;
    }
    if (in.fragment.fragment_chunk_count == 0 ||
        in.fragment.fragment_chunk_index >= in.fragment.fragment_chunk_count ||
        in.fragment.fragment_data_len > WAMBLE_FRAGMENT_DATA_MAX) {
      continue;
    }
    size_t off = (size_t)in.fragment.fragment_chunk_index *
                 (size_t)WAMBLE_FRAGMENT_DATA_MAX;
    if (off + in.fragment.fragment_data_len > sizeof(c->assembled))
      continue;
    if (in.fragment.fragment_data_len) {
      memcpy(c->assembled + off, in.fragment.fragment_data,
             in.fragment.fragment_data_len);
    }
    size_t end = off + in.fragment.fragment_data_len;
    if (end > c->assembled_len)
      c->assembled_len = end;
    c->chunk_count++;
    c->received = 1;
    if (c->expected_chunks > 0 && c->chunk_count >= c->expected_chunks)
      break;
  }
  return NULL;
}

static void build_oversized_string_extensions(struct WambleMsg *msg) {
  if (!msg)
    return;
  msg->extensions.count = 5;
  for (uint8_t i = 0; i < msg->extensions.count; i++) {
    WambleMessageExtField *field = &msg->extensions.fields[i];
    memset(field, 0, sizeof(*field));
    snprintf(field->key, sizeof(field->key), "ext.%u.large", (unsigned)i);
    field->value_type = WAMBLE_TREATMENT_VALUE_STRING;
    size_t usable = sizeof(field->string_value) - 1;
    memset(field->string_value, 'a' + (char)i, usable);
    field->string_value[usable] = '\0';
  }
}

static const WambleMessageExtField *find_ext_field(const struct WambleMsg *msg,
                                                   const char *key) {
  if (!msg || !key)
    return NULL;
  for (uint8_t i = 0; i < msg->extensions.count; i++) {
    if (strcmp(msg->extensions.fields[i].key, key) == 0)
      return &msg->extensions.fields[i];
  }
  return NULL;
}

static int parse_payload_string_ext(const uint8_t *payload, size_t payload_len,
                                    const char *key, size_t *out_base_len,
                                    char *out_value,
                                    size_t out_value_capacity) {
  struct WambleMsg tmp;
  int rc;
  uint8_t i;
  if (!payload || !key || !*key || !out_base_len || !out_value ||
      out_value_capacity == 0)
    return 0;
  out_value[0] = '\0';
  memset(&tmp, 0, sizeof(tmp));
  rc = wamble_client_payload_decode_extensions(payload, payload_len, &tmp,
                                               out_base_len);
  if (rc != 0)
    return 0;
  for (i = 0; i < tmp.extensions.count; i++) {
    if (tmp.extensions.fields[i].value_type == WAMBLE_TREATMENT_VALUE_STRING &&
        strcmp(tmp.extensions.fields[i].key, key) == 0) {
      snprintf(out_value, out_value_capacity, "%s",
               tmp.extensions.fields[i].string_value);
      return 1;
    }
  }
  return 0;
}

WAMBLE_TEST(spectate_update_roundtrip) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
#if defined(WAMBLE_PLATFORM_POSIX)
  {
    int flags = fcntl(srv, F_GETFL, 0);
    T_ASSERT(flags >= 0);
    T_ASSERT_STATUS_OK(fcntl(srv, F_SETFL, flags & ~O_NONBLOCK));
  }
#endif

  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  RecvOneCtx ctx = {.sock = cli};
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, recv_one_thread, &ctx) == 0);

  struct WambleMsg out;
  memset(&out, 0, sizeof(out));
  out.ctrl = WAMBLE_CTRL_SPECTATE_UPDATE;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(i + 1);
  out.board_id = 1234;
  strncpy(out.view.fen, "fen-io", FEN_MAX_LENGTH);

  T_ASSERT_STATUS_OK(send_unreliable_packet(srv, &out, &cliaddr));
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  T_ASSERT_EQ_INT(ctx.received, 1);
  T_ASSERT_EQ_INT(ctx.msg.ctrl, WAMBLE_CTRL_SPECTATE_UPDATE);
  T_ASSERT_EQ_INT(ctx.msg.board_id, 1234);
  T_ASSERT((ctx.msg.flags & WAMBLE_FLAG_UNRELIABLE) != 0);
  T_ASSERT_EQ_INT(ctx.msg.seq_num, 0);
  T_ASSERT_EQ_INT(ctx.msg.header_version, WAMBLE_PROTO_VERSION);
  T_ASSERT_STREQ(ctx.msg.view.fen, "fen-io");

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(outbound_extension_roundtrip) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);

  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  RecvOneCtx ctx = {.sock = cli};
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, recv_one_thread, &ctx) == 0);

  struct WambleMsg out = {0};
  out.ctrl = WAMBLE_CTRL_SERVER_NOTIFICATION;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(0x40 + i);
  strncpy(out.view.fen, "payload-ext", FEN_MAX_LENGTH);
  out.extensions.count = 3;
  snprintf(out.extensions.fields[0].key, sizeof(out.extensions.fields[0].key),
           "%s", "note");
  out.extensions.fields[0].value_type = WAMBLE_TREATMENT_VALUE_STRING;
  snprintf(out.extensions.fields[0].string_value,
           sizeof(out.extensions.fields[0].string_value), "%s", "hello");
  snprintf(out.extensions.fields[1].key, sizeof(out.extensions.fields[1].key),
           "%s", "points");
  out.extensions.fields[1].value_type = WAMBLE_TREATMENT_VALUE_DOUBLE;
  out.extensions.fields[1].double_value = 12.5;
  snprintf(out.extensions.fields[2].key, sizeof(out.extensions.fields[2].key),
           "%s", "active");
  out.extensions.fields[2].value_type = WAMBLE_TREATMENT_VALUE_BOOL;
  out.extensions.fields[2].bool_value = 1;

  T_ASSERT_STATUS_OK(send_unreliable_packet(srv, &out, &cliaddr));
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  T_ASSERT_EQ_INT(ctx.received, 1);
  T_ASSERT_EQ_INT(ctx.msg.ctrl, WAMBLE_CTRL_SERVER_NOTIFICATION);
  T_ASSERT((ctx.msg.flags & WAMBLE_FLAG_UNRELIABLE) != 0);
  T_ASSERT((ctx.msg.flags & WAMBLE_FLAG_EXT_PAYLOAD) != 0);
  T_ASSERT_STREQ(ctx.msg.view.fen, "payload-ext");
  T_ASSERT_EQ_INT(ctx.msg.extensions.count, 3);
  T_ASSERT_STREQ(ctx.msg.extensions.fields[0].key, "note");
  T_ASSERT_EQ_INT(ctx.msg.extensions.fields[0].value_type,
                  WAMBLE_TREATMENT_VALUE_STRING);
  T_ASSERT_STREQ(ctx.msg.extensions.fields[0].string_value, "hello");
  T_ASSERT_STREQ(ctx.msg.extensions.fields[1].key, "points");
  T_ASSERT_EQ_INT(ctx.msg.extensions.fields[1].value_type,
                  WAMBLE_TREATMENT_VALUE_DOUBLE);
  T_ASSERT(fabs(ctx.msg.extensions.fields[1].double_value - 12.5) < 1e-9);
  T_ASSERT_STREQ(ctx.msg.extensions.fields[2].key, "active");
  T_ASSERT_EQ_INT(ctx.msg.extensions.fields[2].value_type,
                  WAMBLE_TREATMENT_VALUE_BOOL);
  T_ASSERT_EQ_INT(ctx.msg.extensions.fields[2].bool_value, 1);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(leaderboard_data_roundtrip) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);

  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  RecvOneCtx ctx = {.sock = cli};
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, recv_one_thread, &ctx) == 0);

  struct WambleMsg out = {0};
  out.ctrl = WAMBLE_CTRL_LEADERBOARD_DATA;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(0x20 + i);
  out.leaderboard_payload.type = WAMBLE_LEADERBOARD_RATING;
  out.leaderboard_payload.self_rank = 9;
  out.leaderboard_payload.count = 2;
  out.leaderboard_payload.entries[0].rank = 1;
  out.leaderboard_payload.entries[0].session_id = 101;
  out.leaderboard_payload.entries[0].score = 150.5;
  out.leaderboard_payload.entries[0].rating = 1210.0;
  out.leaderboard_payload.entries[0].games_played = 12;
  out.leaderboard_payload.entries[0].has_identity = 1;
  for (int i = 0; i < WAMBLE_PUBLIC_KEY_LENGTH; i++)
    out.leaderboard_payload.entries[0].public_key[i] = (uint8_t)(0x40 + i);
  out.leaderboard_payload.entries[0].handle = "h_alpha123456";
  out.leaderboard_payload.entries[1].rank = 2;
  out.leaderboard_payload.entries[1].session_id = 102;
  out.leaderboard_payload.entries[1].score = 120.0;
  out.leaderboard_payload.entries[1].rating = 1188.25;
  out.leaderboard_payload.entries[1].games_played = 8;
  out.leaderboard_payload.entries[1].has_identity = 0;

  T_ASSERT_STATUS_OK(send_unreliable_packet(srv, &out, &cliaddr));
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  T_ASSERT_EQ_INT(ctx.received, 1);
  T_ASSERT_EQ_INT(ctx.msg.ctrl, WAMBLE_CTRL_LEADERBOARD_DATA);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard_payload.type,
                  WAMBLE_LEADERBOARD_RATING);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard_payload.self_rank, 9);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard_payload.count, 2);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard_payload.entries[0].rank, 1);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard_payload.entries[0].session_id, 101);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard_payload.entries[0].games_played, 12);
  T_ASSERT(fabs(ctx.msg.leaderboard_payload.entries[0].score - 150.5) < 1e-9);
  T_ASSERT(fabs(ctx.msg.leaderboard_payload.entries[0].rating - 1210.0) < 1e-9);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard_payload.entries[0].has_identity, 1);
  T_ASSERT(memcmp(ctx.msg.leaderboard_payload.entries[0].public_key,
                  out.leaderboard_payload.entries[0].public_key,
                  WAMBLE_PUBLIC_KEY_LENGTH) == 0);
  T_ASSERT_STREQ(ctx.msg.leaderboard_payload.entries[0].handle,
                 "h_alpha123456");
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard_payload.entries[1].has_identity, 0);
  T_ASSERT(ctx.msg.leaderboard_payload.entries[1].handle == NULL);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(leaderboard_data_score_type_roundtrip_without_fragment_marker) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);

  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  RecvOneCtx ctx = {.sock = cli};
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, recv_one_thread, &ctx) == 0);

  struct WambleMsg out = {0};
  out.ctrl = WAMBLE_CTRL_LEADERBOARD_DATA;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(0x24 + i);
  out.leaderboard_payload.type = WAMBLE_LEADERBOARD_SCORE;
  out.leaderboard_payload.self_rank = 11;
  out.leaderboard_payload.count = 2;
  out.leaderboard_payload.entries[0].rank = 1;
  out.leaderboard_payload.entries[0].session_id = 2001;
  out.leaderboard_payload.entries[0].score = 321.25;
  out.leaderboard_payload.entries[0].rating = 1432.5;
  out.leaderboard_payload.entries[0].games_played = 21;
  out.leaderboard_payload.entries[0].has_identity = 0;
  out.leaderboard_payload.entries[1].rank = 2;
  out.leaderboard_payload.entries[1].session_id = 2002;
  out.leaderboard_payload.entries[1].score = 300.0;
  out.leaderboard_payload.entries[1].rating = 1411.0;
  out.leaderboard_payload.entries[1].games_played = 19;
  out.leaderboard_payload.entries[1].has_identity = 1;
  for (int i = 0; i < WAMBLE_PUBLIC_KEY_LENGTH; i++)
    out.leaderboard_payload.entries[1].public_key[i] = (uint8_t)(0x80 + i);
  out.leaderboard_payload.entries[1].handle = "h_beta654321";

  T_ASSERT_STATUS_OK(send_unreliable_packet(srv, &out, &cliaddr));
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  T_ASSERT_EQ_INT(ctx.received, 1);
  T_ASSERT_EQ_INT(ctx.msg.ctrl, WAMBLE_CTRL_LEADERBOARD_DATA);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard_payload.type,
                  WAMBLE_LEADERBOARD_SCORE);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard_payload.self_rank, 11);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard_payload.count, 2);
  T_ASSERT((ctx.msg.flags & WAMBLE_FLAG_FRAGMENT_PAYLOAD) == 0);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard_payload.entries[0].rank, 1);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard_payload.entries[0].session_id, 2001);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard_payload.entries[0].games_played, 21);
  T_ASSERT(fabs(ctx.msg.leaderboard_payload.entries[0].score - 321.25) < 1e-9);
  T_ASSERT(fabs(ctx.msg.leaderboard_payload.entries[0].rating - 1432.5) < 1e-9);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard_payload.entries[0].has_identity, 0);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard_payload.entries[1].has_identity, 1);
  T_ASSERT(memcmp(ctx.msg.leaderboard_payload.entries[1].public_key,
                  out.leaderboard_payload.entries[1].public_key,
                  WAMBLE_PUBLIC_KEY_LENGTH) == 0);
  T_ASSERT_STREQ(ctx.msg.leaderboard_payload.entries[1].handle, "h_beta654321");

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(player_stats_data_roundtrip) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);

  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  RecvOneCtx ctx = {.sock = cli};
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, recv_one_thread, &ctx) == 0);

  struct WambleMsg out = {0};
  out.ctrl = WAMBLE_CTRL_PLAYER_STATS_DATA;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(0x10 + i);
  out.stats.player_stats.score = 42.5;
  out.stats.player_stats.games_played = 18;
  out.stats.player_stats.chess960_games_played = 7;

  T_ASSERT_STATUS_OK(send_unreliable_packet(srv, &out, &cliaddr));
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  T_ASSERT_EQ_INT(ctx.received, 1);
  T_ASSERT_EQ_INT(ctx.msg.ctrl, WAMBLE_CTRL_PLAYER_STATS_DATA);
  T_ASSERT(fabs(ctx.msg.stats.player_stats.score - 42.5) < 1e-9);
  T_ASSERT_EQ_INT((int)ctx.msg.stats.player_stats.games_played, 18);
  T_ASSERT_EQ_INT((int)ctx.msg.stats.player_stats.chess960_games_played, 7);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(login_challenge_roundtrip) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);

  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  RecvOneCtx ctx = {.sock = cli};
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, recv_one_thread, &ctx) == 0);

  struct WambleMsg out = {0};
  out.ctrl = WAMBLE_CTRL_LOGIN_CHALLENGE;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(0x41 + i);
  for (int i = 0; i < WAMBLE_LOGIN_CHALLENGE_LENGTH; i++)
    out.login.challenge[i] = (uint8_t)(0xa0 + i);

  T_ASSERT_STATUS_OK(send_unreliable_packet(srv, &out, &cliaddr));
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  T_ASSERT_EQ_INT(ctx.received, 1);
  T_ASSERT_EQ_INT(ctx.msg.ctrl, WAMBLE_CTRL_LOGIN_CHALLENGE);
  for (int i = 0; i < WAMBLE_LOGIN_CHALLENGE_LENGTH; i++) {
    T_ASSERT_EQ_INT((int)ctx.msg.login.challenge[i], (int)(0xa0 + i));
  }

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(login_request_with_signature_roundtrip) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);
  struct sockaddr_in dst = {0};
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons((uint16_t)wamble_socket_bound_port(srv));

  struct WambleMsg out = {0};
  out.ctrl = WAMBLE_CTRL_LOGIN_REQUEST;
  out.login.has_signature = 1;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(0x73 + i);
  for (int i = 0; i < WAMBLE_PUBLIC_KEY_LENGTH; i++)
    out.login.public_key[i] = (uint8_t)(0x10 + i);
  for (int i = 0; i < WAMBLE_LOGIN_SIGNATURE_LENGTH; i++)
    out.login.signature[i] = (uint8_t)(0x80 + i);

  T_ASSERT_STATUS_OK(send_unreliable_packet(cli, &out, &dst));

  struct WambleMsg in = {0};
  struct sockaddr_in from;
  fd_set rfds;
  struct timeval tv;
  FD_ZERO(&rfds);
  FD_SET(srv, &rfds);
  tv.tv_sec = 0;
  tv.tv_usec = 400 * 1000;
#ifdef WAMBLE_PLATFORM_WINDOWS
  int ready = select(0, &rfds, NULL, NULL, &tv);
#else
  int ready = select(srv + 1, &rfds, NULL, NULL, &tv);
#endif
  int got = (ready > 0) ? receive_message(srv, &in, &from) : 0;
  T_ASSERT(got > 0);
  T_ASSERT_EQ_INT(in.ctrl, WAMBLE_CTRL_LOGIN_REQUEST);
  T_ASSERT_EQ_INT((int)in.login.has_signature, 1);
  for (int i = 0; i < WAMBLE_PUBLIC_KEY_LENGTH; i++) {
    T_ASSERT_EQ_INT((int)in.login.public_key[i], (int)(0x10 + i));
  }
  for (int i = 0; i < WAMBLE_LOGIN_SIGNATURE_LENGTH; i++) {
    T_ASSERT_EQ_INT((int)in.login.signature[i], (int)(0x80 + i));
  }

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(profile_tos_data_fragment_roundtrip) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);

  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  RecvOneCtx ctx = {.sock = cli};
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, recv_one_thread, &ctx) == 0);

  struct WambleMsg out = {0};
  out.ctrl = WAMBLE_CTRL_PROFILE_TOS_DATA;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(0x36 + i);
  const char *fragment = "By continuing you agree to terms.";
  out.fragment.fragment_data_len = (uint16_t)strlen(fragment);
  memcpy(out.fragment.fragment_data, fragment, out.fragment.fragment_data_len);
  out.fragment.fragment_version = WAMBLE_FRAGMENT_VERSION;
  out.fragment.fragment_hash_algo = WAMBLE_FRAGMENT_HASH_BLAKE2B_256;
  out.fragment.fragment_chunk_index = 1;
  out.fragment.fragment_chunk_count = 3;
  out.fragment.fragment_total_len = 200;
  out.fragment.fragment_transfer_id = 77;
  for (int i = 0; i < WAMBLE_FRAGMENT_HASH_LENGTH; i++)
    out.fragment.fragment_hash[i] = (uint8_t)(0xa0 + i);

  T_ASSERT_STATUS_OK(send_unreliable_packet(srv, &out, &cliaddr));
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  T_ASSERT_EQ_INT(ctx.received, 1);
  T_ASSERT_EQ_INT(ctx.msg.ctrl, WAMBLE_CTRL_PROFILE_TOS_DATA);
  T_ASSERT((ctx.msg.flags & WAMBLE_FLAG_FRAGMENT_PAYLOAD) != 0);
  T_ASSERT_EQ_INT((int)ctx.msg.fragment.fragment_version,
                  WAMBLE_FRAGMENT_VERSION);
  T_ASSERT_EQ_INT((int)ctx.msg.fragment.fragment_hash_algo,
                  WAMBLE_FRAGMENT_HASH_BLAKE2B_256);
  T_ASSERT_EQ_INT((int)ctx.msg.fragment.fragment_chunk_index, 1);
  T_ASSERT_EQ_INT((int)ctx.msg.fragment.fragment_chunk_count, 3);
  T_ASSERT_EQ_INT((int)ctx.msg.fragment.fragment_total_len, 200);
  T_ASSERT_EQ_INT((int)ctx.msg.fragment.fragment_transfer_id, 77);
  T_ASSERT_EQ_INT((int)ctx.msg.fragment.fragment_data_len,
                  (int)strlen(fragment));
  T_ASSERT(memcmp(ctx.msg.fragment.fragment_data, fragment, strlen(fragment)) ==
           0);
  for (int i = 0; i < WAMBLE_FRAGMENT_HASH_LENGTH; i++)
    T_ASSERT_EQ_INT((int)ctx.msg.fragment.fragment_hash[i], (int)(0xa0 + i));

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(server_notification_ext_auto_fragment_unreliable) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);

  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  RecvTosFragmentsCtx rx = {
      .sock = cli,
      .expected_ctrl = WAMBLE_CTRL_SERVER_NOTIFICATION,
  };
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, recv_tos_fragments_and_ack_thread, &rx) ==
           0);

  struct WambleMsg out = {0};
  out.ctrl = WAMBLE_CTRL_SERVER_NOTIFICATION;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(0x70 + i);
  strncpy(out.view.fen, "oversized-fragmented-notice",
          sizeof(out.view.fen) - 1);
  build_oversized_string_extensions(&out);

  T_ASSERT_STATUS_OK(send_unreliable_packet(srv, &out, &cliaddr));
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  T_ASSERT_EQ_INT(rx.received, 1);
  T_ASSERT(rx.expected_chunks > 1);
  T_ASSERT_EQ_INT(rx.chunk_count, rx.expected_chunks);
  T_ASSERT_EQ_INT((int)rx.hash_algo, WAMBLE_FRAGMENT_HASH_BLAKE2B_256);
  T_ASSERT(rx.transfer_id != 0);
  T_ASSERT(rx.total_len > WAMBLE_MAX_PAYLOAD);
  T_ASSERT_EQ_INT((int)rx.assembled_len, (int)rx.total_len);
  T_ASSERT_EQ_INT((int)rx.assembled[0], (int)out.session.notification_type);
  size_t base_len = strlen(out.view.fen);
  T_ASSERT(memcmp(rx.assembled + 1, out.view.fen, base_len) == 0);
  T_ASSERT(rx.total_len >= 1 + base_len + 4);
  T_ASSERT_EQ_INT((int)rx.assembled[rx.total_len - 4], 0x57);
  T_ASSERT_EQ_INT((int)rx.assembled[rx.total_len - 3], 0x58);
  uint8_t computed_hash[WAMBLE_FRAGMENT_HASH_LENGTH] = {0};
  crypto_blake2b(computed_hash, WAMBLE_FRAGMENT_HASH_LENGTH, rx.assembled,
                 rx.total_len);
  T_ASSERT(memcmp(computed_hash, rx.hash, WAMBLE_FRAGMENT_HASH_LENGTH) == 0);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(server_notification_ext_auto_fragment_reliable) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);

  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  RecvTosFragmentsCtx rx = {
      .sock = cli,
      .expected_ctrl = WAMBLE_CTRL_SERVER_NOTIFICATION,
  };
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, recv_tos_fragments_and_ack_thread, &rx) ==
           0);

  struct WambleMsg out = {0};
  out.ctrl = WAMBLE_CTRL_SERVER_NOTIFICATION;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(0x51 + i);
  strncpy(out.view.fen, "oversized-fragmented-reliable",
          sizeof(out.view.fen) - 1);
  build_oversized_string_extensions(&out);

  T_ASSERT_EQ_INT(
      send_reliable_message(srv, &out, &cliaddr, get_config()->timeout_ms, 5),
      0);
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  T_ASSERT_EQ_INT(rx.received, 1);
  T_ASSERT(rx.expected_chunks > 1);
  T_ASSERT_EQ_INT(rx.chunk_count, rx.expected_chunks);
  T_ASSERT_EQ_INT((int)rx.hash_algo, WAMBLE_FRAGMENT_HASH_BLAKE2B_256);
  T_ASSERT(rx.transfer_id != 0);
  T_ASSERT(rx.total_len > WAMBLE_MAX_PAYLOAD);
  T_ASSERT_EQ_INT((int)rx.assembled_len, (int)rx.total_len);
  T_ASSERT_EQ_INT((int)rx.assembled[0], (int)out.session.notification_type);
  size_t base_len = strlen(out.view.fen);
  T_ASSERT(memcmp(rx.assembled + 1, out.view.fen, base_len) == 0);
  T_ASSERT(rx.total_len >= 1 + base_len + 4);
  T_ASSERT_EQ_INT((int)rx.assembled[rx.total_len - 4], 0x57);
  T_ASSERT_EQ_INT((int)rx.assembled[rx.total_len - 3], 0x58);
  uint8_t computed_hash[WAMBLE_FRAGMENT_HASH_LENGTH] = {0};
  crypto_blake2b(computed_hash, WAMBLE_FRAGMENT_HASH_LENGTH, rx.assembled,
                 rx.total_len);
  T_ASSERT(memcmp(computed_hash, rx.hash, WAMBLE_FRAGMENT_HASH_LENGTH) == 0);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(fragment_reassembly_api_complete_with_integrity_ok) {
  char full[WAMBLE_FRAGMENT_DATA_MAX * 2 + 23];
  size_t full_len = sizeof(full);
  for (size_t i = 0; i < full_len; i++)
    full[i] = (char)('a' + (i % 26));

  uint8_t hash[WAMBLE_FRAGMENT_HASH_LENGTH] = {0};
  crypto_blake2b(hash, WAMBLE_FRAGMENT_HASH_LENGTH, (const uint8_t *)full,
                 full_len);

  WambleFragmentReassembly reassembly;
  wamble_fragment_reassembly_init(&reassembly);

  uint16_t order[3] = {1, 0, 2};
  for (int i = 0; i < 3; i++) {
    uint16_t idx = order[i];
    size_t off = (size_t)idx * (size_t)WAMBLE_FRAGMENT_DATA_MAX;
    size_t len = full_len - off;
    if (len > WAMBLE_FRAGMENT_DATA_MAX)
      len = WAMBLE_FRAGMENT_DATA_MAX;

    struct WambleMsg frag = {0};
    frag.ctrl = WAMBLE_CTRL_PROFILE_TOS_DATA;
    frag.fragment.fragment_version = WAMBLE_FRAGMENT_VERSION;
    frag.fragment.fragment_hash_algo = WAMBLE_FRAGMENT_HASH_BLAKE2B_256;
    frag.fragment.fragment_chunk_index = idx;
    frag.fragment.fragment_chunk_count = 3;
    frag.fragment.fragment_total_len = (uint32_t)full_len;
    frag.fragment.fragment_transfer_id = 101;
    memcpy(frag.fragment.fragment_hash, hash, WAMBLE_FRAGMENT_HASH_LENGTH);
    frag.fragment.fragment_data_len = (uint16_t)len;
    memcpy(frag.fragment.fragment_data, full + off, len);

    WambleFragmentReassemblyResult st =
        wamble_fragment_reassembly_push(&reassembly, &frag);
    if (i < 2) {
      T_ASSERT_EQ_INT(st, WAMBLE_FRAGMENT_REASSEMBLY_IN_PROGRESS);
    } else {
      T_ASSERT_EQ_INT(st, WAMBLE_FRAGMENT_REASSEMBLY_COMPLETE);
    }
  }

  T_ASSERT_EQ_INT((int)reassembly.integrity, WAMBLE_FRAGMENT_INTEGRITY_OK);
  T_ASSERT_EQ_INT((int)reassembly.total_len, (int)full_len);
  T_ASSERT(memcmp(reassembly.data, full, full_len) == 0);
  wamble_fragment_reassembly_free(&reassembly);
  return 0;
}

WAMBLE_TEST(fragment_reassembly_api_reports_hash_mismatch) {
  char full[WAMBLE_FRAGMENT_DATA_MAX + 5];
  size_t full_len = sizeof(full);
  for (size_t i = 0; i < full_len; i++)
    full[i] = (char)('k' + (i % 7));

  uint8_t hash[WAMBLE_FRAGMENT_HASH_LENGTH] = {0};
  crypto_blake2b(hash, WAMBLE_FRAGMENT_HASH_LENGTH, (const uint8_t *)full,
                 full_len);
  hash[0] ^= 0x5a;

  WambleFragmentReassembly reassembly;
  wamble_fragment_reassembly_init(&reassembly);

  for (uint16_t idx = 0; idx < 2; idx++) {
    size_t off = (size_t)idx * (size_t)WAMBLE_FRAGMENT_DATA_MAX;
    size_t len = full_len - off;
    if (len > WAMBLE_FRAGMENT_DATA_MAX)
      len = WAMBLE_FRAGMENT_DATA_MAX;
    struct WambleMsg frag = {0};
    frag.ctrl = WAMBLE_CTRL_PROFILE_TOS_DATA;
    frag.fragment.fragment_version = WAMBLE_FRAGMENT_VERSION;
    frag.fragment.fragment_hash_algo = WAMBLE_FRAGMENT_HASH_BLAKE2B_256;
    frag.fragment.fragment_chunk_index = idx;
    frag.fragment.fragment_chunk_count = 2;
    frag.fragment.fragment_total_len = (uint32_t)full_len;
    frag.fragment.fragment_transfer_id = 102;
    memcpy(frag.fragment.fragment_hash, hash, WAMBLE_FRAGMENT_HASH_LENGTH);
    frag.fragment.fragment_data_len = (uint16_t)len;
    memcpy(frag.fragment.fragment_data, full + off, len);

    WambleFragmentReassemblyResult st =
        wamble_fragment_reassembly_push(&reassembly, &frag);
    if (idx == 0) {
      T_ASSERT_EQ_INT(st, WAMBLE_FRAGMENT_REASSEMBLY_IN_PROGRESS);
    } else {
      T_ASSERT_EQ_INT(st, WAMBLE_FRAGMENT_REASSEMBLY_COMPLETE_BAD_HASH);
    }
  }

  T_ASSERT_EQ_INT((int)reassembly.integrity,
                  WAMBLE_FRAGMENT_INTEGRITY_MISMATCH);
  T_ASSERT_EQ_INT((int)reassembly.total_len, (int)full_len);
  T_ASSERT(memcmp(reassembly.data, full, full_len) == 0);
  wamble_fragment_reassembly_free(&reassembly);
  return 0;
}

WAMBLE_TEST(fragment_reassembly_api_switches_transfers) {
  char a[WAMBLE_FRAGMENT_DATA_MAX + 10];
  for (size_t i = 0; i < sizeof(a); i++)
    a[i] = (char)('m' + (i % 13));
  const char *b = "reset-transfer";

  uint8_t hash_a[WAMBLE_FRAGMENT_HASH_LENGTH] = {0};
  uint8_t hash_b[WAMBLE_FRAGMENT_HASH_LENGTH] = {0};
  crypto_blake2b(hash_a, WAMBLE_FRAGMENT_HASH_LENGTH, (const uint8_t *)a,
                 sizeof(a));
  crypto_blake2b(hash_b, WAMBLE_FRAGMENT_HASH_LENGTH, (const uint8_t *)b,
                 strlen(b));

  WambleFragmentReassembly reassembly;
  wamble_fragment_reassembly_init(&reassembly);

  struct WambleMsg first = {0};
  first.ctrl = WAMBLE_CTRL_PROFILE_TOS_DATA;
  first.fragment.fragment_version = WAMBLE_FRAGMENT_VERSION;
  first.fragment.fragment_hash_algo = WAMBLE_FRAGMENT_HASH_BLAKE2B_256;
  first.fragment.fragment_chunk_index = 0;
  first.fragment.fragment_chunk_count = 2;
  first.fragment.fragment_total_len = (uint32_t)sizeof(a);
  first.fragment.fragment_transfer_id = 200;
  memcpy(first.fragment.fragment_hash, hash_a, WAMBLE_FRAGMENT_HASH_LENGTH);
  first.fragment.fragment_data_len = (uint16_t)WAMBLE_FRAGMENT_DATA_MAX;
  memcpy(first.fragment.fragment_data, a,
         (size_t)first.fragment.fragment_data_len);

  T_ASSERT_EQ_INT(wamble_fragment_reassembly_push(&reassembly, &first),
                  WAMBLE_FRAGMENT_REASSEMBLY_IN_PROGRESS);
  T_ASSERT_EQ_INT((int)reassembly.transfer_id, 200);

  struct WambleMsg second = {0};
  second.ctrl = WAMBLE_CTRL_PROFILE_TOS_DATA;
  second.fragment.fragment_version = WAMBLE_FRAGMENT_VERSION;
  second.fragment.fragment_hash_algo = WAMBLE_FRAGMENT_HASH_BLAKE2B_256;
  second.fragment.fragment_chunk_index = 0;
  second.fragment.fragment_chunk_count = 1;
  second.fragment.fragment_total_len = (uint32_t)strlen(b);
  second.fragment.fragment_transfer_id = 201;
  memcpy(second.fragment.fragment_hash, hash_b, WAMBLE_FRAGMENT_HASH_LENGTH);
  second.fragment.fragment_data_len = (uint16_t)strlen(b);
  memcpy(second.fragment.fragment_data, b,
         (size_t)second.fragment.fragment_data_len);

  T_ASSERT_EQ_INT(wamble_fragment_reassembly_push(&reassembly, &second),
                  WAMBLE_FRAGMENT_REASSEMBLY_COMPLETE);
  T_ASSERT_EQ_INT((int)reassembly.transfer_id, 201);
  T_ASSERT_EQ_INT((int)reassembly.integrity, WAMBLE_FRAGMENT_INTEGRITY_OK);
  T_ASSERT_EQ_INT((int)reassembly.total_len, (int)strlen(b));
  T_ASSERT(memcmp(reassembly.data, b, strlen(b)) == 0);
  wamble_fragment_reassembly_free(&reassembly);
  return 0;
}

WAMBLE_TEST(submit_prediction_roundtrip) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);
  struct sockaddr_in dst = {0};
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons((uint16_t)wamble_socket_bound_port(srv));

  struct WambleMsg out = {0};
  out.ctrl = WAMBLE_CTRL_SUBMIT_PREDICTION;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(0x44 + i);
  out.board_id = 77;
  out.prediction.parent_id = 1234;
  strcpy(out.text.uci, "e2e4");
  out.text.uci_len = 4;
  T_ASSERT_STATUS_OK(send_unreliable_packet(cli, &out, &dst));

  struct WambleMsg in;
  struct sockaddr_in from;
  fd_set rfds;
  struct timeval tv;
  FD_ZERO(&rfds);
  FD_SET(srv, &rfds);
  tv.tv_sec = 0;
  tv.tv_usec = 400 * 1000;
#ifdef WAMBLE_PLATFORM_WINDOWS
  int ready = select(0, &rfds, NULL, NULL, &tv);
#else
  int ready = select(srv + 1, &rfds, NULL, NULL, &tv);
#endif
  int got = (ready > 0) ? receive_message(srv, &in, &from) : 0;
  T_ASSERT(got > 0);
  T_ASSERT_EQ_INT(in.ctrl, WAMBLE_CTRL_SUBMIT_PREDICTION);
  T_ASSERT_EQ_INT((int)in.board_id, 77);
  T_ASSERT_EQ_INT((int)in.prediction.parent_id, 1234);
  T_ASSERT_EQ_INT((int)in.text.uci_len, 4);
  T_ASSERT_STREQ(in.text.uci, "e2e4");

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(prediction_data_roundtrip) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);

  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  RecvOneCtx ctx = {.sock = cli};
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, recv_one_thread, &ctx) == 0);

  struct WambleMsg out = {0};
  out.ctrl = WAMBLE_CTRL_PREDICTION_DATA;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(0x30 + i);
  out.board_id = 55;
  out.prediction.count = 2;
  out.prediction.entries[0].id = 1;
  out.prediction.entries[0].parent_id = 0;
  memcpy(out.prediction.entries[0].token, out.token, TOKEN_LENGTH);
  out.prediction.entries[0].points_awarded = 1.5;
  out.prediction.entries[0].target_ply = 4;
  out.prediction.entries[0].depth = 0;
  out.prediction.entries[0].status = WAMBLE_PREDICTION_STATUS_CORRECT;
  out.prediction.entries[0].uci_len = 4;
  memcpy(out.prediction.entries[0].uci, "e2e4", 4);
  out.prediction.entries[1].id = 2;
  out.prediction.entries[1].parent_id = 1;
  memcpy(out.prediction.entries[1].token, out.token, TOKEN_LENGTH);
  out.prediction.entries[1].points_awarded = 0.0;
  out.prediction.entries[1].target_ply = 5;
  out.prediction.entries[1].depth = 1;
  out.prediction.entries[1].status = WAMBLE_PREDICTION_STATUS_PENDING;
  out.prediction.entries[1].uci_len = 4;
  memcpy(out.prediction.entries[1].uci, "e7e5", 4);

  T_ASSERT_STATUS_OK(send_unreliable_packet(srv, &out, &cliaddr));
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  T_ASSERT_EQ_INT(ctx.received, 1);
  T_ASSERT_EQ_INT(ctx.msg.ctrl, WAMBLE_CTRL_PREDICTION_DATA);
  T_ASSERT_EQ_INT((int)ctx.msg.prediction.count, 2);
  T_ASSERT_EQ_INT((int)ctx.msg.prediction.entries[0].id, 1);
  T_ASSERT_EQ_INT((int)ctx.msg.prediction.entries[1].parent_id, 1);
  T_ASSERT_EQ_INT((int)ctx.msg.prediction.entries[1].depth, 1);
  T_ASSERT_EQ_INT((int)ctx.msg.prediction.entries[0].status,
                  WAMBLE_PREDICTION_STATUS_CORRECT);
  T_ASSERT_EQ_INT((int)ctx.msg.prediction.entries[1].status,
                  WAMBLE_PREDICTION_STATUS_PENDING);
  T_ASSERT(fabs(ctx.msg.prediction.entries[0].points_awarded - 1.5) < 1e-9);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(get_active_reservations_roundtrip) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);
  struct sockaddr_in dst = {0};
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons((uint16_t)wamble_socket_bound_port(srv));

  struct WambleMsg out = {0};
  out.ctrl = WAMBLE_CTRL_GET_ACTIVE_RESERVATIONS;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(0x59 + i);
  T_ASSERT_STATUS_OK(send_unreliable_packet(cli, &out, &dst));

  struct WambleMsg in = {0};
  struct sockaddr_in from;
  fd_set rfds;
  struct timeval tv;
  FD_ZERO(&rfds);
  FD_SET(srv, &rfds);
  tv.tv_sec = 0;
  tv.tv_usec = 400 * 1000;
#ifdef WAMBLE_PLATFORM_WINDOWS
  int ready = select(0, &rfds, NULL, NULL, &tv);
#else
  int ready = select(srv + 1, &rfds, NULL, NULL, &tv);
#endif
  int got = (ready > 0) ? receive_message(srv, &in, &from) : 0;
  T_ASSERT(got > 0);
  T_ASSERT_EQ_INT(in.ctrl, WAMBLE_CTRL_GET_ACTIVE_RESERVATIONS);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(active_reservations_data_roundtrip) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);

  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  RecvOneCtx ctx = {.sock = cli};
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, recv_one_thread, &ctx) == 0);

  struct WambleMsg out = {0};
  out.ctrl = WAMBLE_CTRL_ACTIVE_RESERVATIONS_DATA;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(0x6a + i);
  {
    uint16_t count_be = htons(2);
    size_t off = 0;
    memcpy(out.fragment.fragment_data, &count_be, 2);
    off = 2;
    write_be_u64(out.fragment.fragment_data + off, 101);
    off += 8;
    write_be_u64(out.fragment.fragment_data + off, 1700000000ULL);
    off += 8;
    write_be_u64(out.fragment.fragment_data + off, 1700000100ULL);
    off += 8;
    out.fragment.fragment_data[off++] = 1;
    out.fragment.fragment_data[off++] = 2;
    memcpy(out.fragment.fragment_data + off, "p1", 2);
    off += 2;
    write_be_u64(out.fragment.fragment_data + off, 202);
    off += 8;
    write_be_u64(out.fragment.fragment_data + off, 1700000015ULL);
    off += 8;
    write_be_u64(out.fragment.fragment_data + off, 1700000200ULL);
    off += 8;
    out.fragment.fragment_data[off++] = 0;
    out.fragment.fragment_data[off++] = 4;
    memcpy(out.fragment.fragment_data + off, "open", 4);
    off += 4;
    out.fragment.fragment_data_len = (uint16_t)off;
    out.fragment.fragment_version = WAMBLE_FRAGMENT_VERSION;
    out.fragment.fragment_hash_algo = WAMBLE_FRAGMENT_HASH_BLAKE2B_256;
    out.fragment.fragment_chunk_index = 0;
    out.fragment.fragment_chunk_count = 1;
    out.fragment.fragment_total_len = out.fragment.fragment_data_len;
    out.fragment.fragment_transfer_id = 1;
  }

  T_ASSERT_STATUS_OK(send_unreliable_packet(srv, &out, &cliaddr));
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  T_ASSERT_EQ_INT(ctx.received, 1);
  T_ASSERT_EQ_INT(ctx.msg.ctrl, WAMBLE_CTRL_ACTIVE_RESERVATIONS_DATA);
  T_ASSERT_EQ_INT((int)ctx.msg.session.active_count, 2);
  T_ASSERT_EQ_INT((int)ctx.msg.fragment.fragment_data_len, 60);
  {
    uint64_t board0_be = 0;
    uint64_t reserved0_be = 0;
    uint64_t expires0_be = 0;
    uint8_t available0 = 0;
    uint8_t profile_len0 = 0;
    memcpy(&board0_be, ctx.msg.fragment.fragment_data + 2, 8);
    memcpy(&reserved0_be, ctx.msg.fragment.fragment_data + 10, 8);
    memcpy(&expires0_be, ctx.msg.fragment.fragment_data + 18, 8);
    available0 = ctx.msg.fragment.fragment_data[26];
    profile_len0 = ctx.msg.fragment.fragment_data[27];
    T_ASSERT_EQ_INT((int)wamble_net_to_host64(board0_be), 101);
    T_ASSERT_EQ_INT((int)wamble_net_to_host64(reserved0_be), 1700000000);
    T_ASSERT_EQ_INT((int)wamble_net_to_host64(expires0_be), 1700000100);
    T_ASSERT_EQ_INT((int)available0, 1);
    T_ASSERT_EQ_INT((int)profile_len0, 2);
    T_ASSERT(memcmp(ctx.msg.fragment.fragment_data + 28, "p1", 2) == 0);
  }

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

static void *handle_msg_peer_thread(void *arg) {
  wamble_socket_t sock = *(wamble_socket_t *)arg;
  struct WambleMsg in;
  struct sockaddr_in src;
  int rc = receive_message(sock, &in, &src);
  if (rc > 0)
    handle_message(sock, &in, &src, 0, NULL);
  return NULL;
}

WAMBLE_TEST(reliable_ack_success) {
  const char *cfg_path = "build/test_network_reliable_ack.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(defprofile p1 ((def port 19420) (def advertise 1)))\n";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, "
          "'test_trust', 'test'), "
          "(0, 'protocol.ctrl', 'board_update', '*', 'allow', 0, "
          "'test_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }
  player_manager_init();
  board_manager_init();

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);

  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);
  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, handle_msg_peer_thread, &cli) == 0);

  struct WambleMsg msg;
  memset(&msg, 0, sizeof(msg));
  msg.ctrl = WAMBLE_CTRL_BOARD_UPDATE;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    msg.token[i] = (uint8_t)(0x10 + i);
  msg.board_id = 77;
  strncpy(msg.view.fen, "fen-data", FEN_MAX_LENGTH);
  T_ASSERT(db_create_session(msg.token, 0) > 0);

  int rc = send_reliable_message(srv, &msg, &cliaddr, get_config()->timeout_ms,
                                 get_config()->max_retries);
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));
  wamble_close_socket(cli);
  wamble_close_socket(srv);
  T_ASSERT_STATUS_OK(rc);
  return 0;
}

typedef struct {
  wamble_socket_t sock;
  struct sockaddr_in dst;
  struct WambleMsg msg;
  int delay_ms;
} DelayedSendCtx;

static void *delayed_send_thread(void *arg) {
  DelayedSendCtx *ctx = arg;
  if (ctx->delay_ms > 0)
    wamble_sleep_ms(ctx->delay_ms);
  (void)send_unreliable_packet(ctx->sock, &ctx->msg, &ctx->dst);
  return NULL;
}

WAMBLE_TEST(reliable_ack_rejects_wrong_source_and_preserves_packets) {
  const char *cfg_path = "build/test_network_reliable_ack_wrong_source.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(defprofile p1 ((def port 19422) (def advertise 1)))\n";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, "
          "'test_trust', 'test'), "
          "(0, 'protocol.ctrl', 'board_update', '*', 'allow', 0, "
          "'test_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }
  player_manager_init();
  board_manager_init();

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);

  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);
  wamble_socket_t other = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(other != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));
  T_ASSERT_STATUS_OK(
      bind(other, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  struct sockaddr_in srvaddr = {0};
  srvaddr.sin_family = AF_INET;
  srvaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  srvaddr.sin_port = htons((uint16_t)wamble_socket_bound_port(srv));

  wamble_thread_t ack_th;
  T_ASSERT(wamble_thread_create(&ack_th, handle_msg_peer_thread, &cli) == 0);

  DelayedSendCtx fake_ack = {.sock = other, .dst = srvaddr, .delay_ms = 5};
  fake_ack.msg.ctrl = WAMBLE_CTRL_ACK;
  fake_ack.msg.seq_num = 1;
  fake_ack.msg.board_id = 77;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    fake_ack.msg.token[i] = (uint8_t)(0x10 + i);

  DelayedSendCtx other_msg = {.sock = other, .dst = srvaddr, .delay_ms = 1};
  other_msg.msg.ctrl = WAMBLE_CTRL_LIST_PROFILES;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    other_msg.msg.token[i] = (uint8_t)(0x40 + i);

  wamble_thread_t fake_ack_th;
  wamble_thread_t other_msg_th;
  T_ASSERT(wamble_thread_create(&fake_ack_th, delayed_send_thread, &fake_ack) ==
           0);
  T_ASSERT(wamble_thread_create(&other_msg_th, delayed_send_thread,
                                &other_msg) == 0);

  struct WambleMsg msg = {0};
  msg.ctrl = WAMBLE_CTRL_BOARD_UPDATE;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    msg.token[i] = (uint8_t)(0x10 + i);
  msg.board_id = 77;
  strncpy(msg.view.fen, "fen-data", FEN_MAX_LENGTH);
  T_ASSERT(db_create_session(msg.token, 0) > 0);

  int rc = send_reliable_message(srv, &msg, &cliaddr, 500, 5);
  T_ASSERT_STATUS_OK(wamble_thread_join(other_msg_th, NULL));
  T_ASSERT_STATUS_OK(wamble_thread_join(fake_ack_th, NULL));
  T_ASSERT_STATUS_OK(wamble_thread_join(ack_th, NULL));
  T_ASSERT_STATUS_OK(rc);

  struct WambleMsg in = {0};
  struct sockaddr_in from;
  int recv_rc = receive_message(srv, &in, &from);
  T_ASSERT(recv_rc > 0);
  T_ASSERT_EQ_INT(in.ctrl, WAMBLE_CTRL_LIST_PROFILES);
  T_ASSERT(tokens_equal(in.token, other_msg.msg.token));

  wamble_close_socket(other);
  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

typedef struct {
  wamble_socket_t sock;
  int target;
  int count;
  uint64_t deadline_ms;
} RecvManyCtx;

static void *recv_many_thread(void *arg) {
  RecvManyCtx *c = arg;
  struct WambleMsg in;
  struct sockaddr_in from;
  while (c->count < c->target) {
    int rc = receive_message(c->sock, &in, &from);
    if (rc > 0) {
      c->count++;
      continue;
    }
    if (wamble_now_mono_millis() > c->deadline_ms)
      break;
    wamble_sleep_ms(1);
  }
  return NULL;
}

WAMBLE_TEST(perf_unreliable_throughput_local) {
  config_load(NULL, NULL, NULL, 0);

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);

  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);
  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  RecvManyCtx ctx = {.sock = cli,
                     .target = 1000,
                     .deadline_ms = wamble_now_mono_millis() + 5000};

  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, recv_many_thread, &ctx) == 0);

  uint64_t start_ns = wamble_now_nanos();
  for (int i = 0; i < ctx.target; i++) {
    struct WambleMsg out;
    memset(&out, 0, sizeof(out));
    out.ctrl = WAMBLE_CTRL_SPECTATE_UPDATE;
    for (int j = 0; j < TOKEN_LENGTH; j++)
      out.token[j] = (uint8_t)(j + 1);
    out.board_id = (uint64_t)(1000 + i);
    snprintf(out.view.fen, FEN_MAX_LENGTH, "fen-%d", i);
    T_ASSERT_STATUS_OK(send_unreliable_packet(srv, &out, &cliaddr));
    if ((i & 127) == 0)
      wamble_sleep_ms(1);
  }

  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  uint64_t end_ns = wamble_now_nanos();
  uint64_t elapsed_ns = end_ns - start_ns;
  double throughput =
      (elapsed_ns > 0) ? ((double)ctx.count * 1e9 / (double)elapsed_ns) : 0.0;
  wamble_metric("perf_unreliable_throughput",
                "msgs=%d received=%d elapsed_ns=%llu throughput=%.2f msg/s",
                ctx.target, ctx.count, (unsigned long long)elapsed_ns,
                throughput);
  T_ASSERT(ctx.count >= (ctx.target * 98) / 100);
  T_ASSERT(elapsed_ns < (uint64_t)2500 * 1000000ULL);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

typedef struct {
  wamble_socket_t sock;
  int target;
  int count;
} AckPeerManyCtx;

static void *ack_peer_many_thread(void *arg) {
  AckPeerManyCtx *p = arg;
  while (p->count < p->target) {
    struct WambleMsg in;
    struct sockaddr_in src;
    fd_set rfds;
    struct timeval tv;
    FD_ZERO(&rfds);
    FD_SET(p->sock, &rfds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
#ifdef WAMBLE_PLATFORM_WINDOWS
    int ready = select(0, &rfds, NULL, NULL, &tv);
#else
    int ready = select(p->sock + 1, &rfds, NULL, NULL, &tv);
#endif
    if (ready <= 0)
      break;
    int rc = receive_message(p->sock, &in, &src);
    if (rc > 0) {
      handle_message(p->sock, &in, &src, 0, NULL);
      p->count++;
    }
  }
  return NULL;
}

WAMBLE_TEST(perf_reliable_ack_latency) {
  const char *cfg_path = "build/test_network_perf_reliable_ack.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 1000)\n"
                    "(defprofile p1 ((def port 19423) (def advertise 1)))\n";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, "
          "'test_trust', 'test'), "
          "(0, 'protocol.ctrl', 'board_update', '*', 'allow', 0, "
          "'test_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }
  player_manager_init();
  board_manager_init();

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);

  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);
  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  const int iters = 200;
  AckPeerManyCtx peer = {.sock = cli, .target = iters};

  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, ack_peer_many_thread, &peer) == 0);

  struct WambleMsg msg;
  memset(&msg, 0, sizeof(msg));
  msg.ctrl = WAMBLE_CTRL_BOARD_UPDATE;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    msg.token[i] = (uint8_t)(0x10 + i);
  msg.board_id = 77;
  strncpy(msg.view.fen, "fen-data", FEN_MAX_LENGTH);
  T_ASSERT(db_create_session(msg.token, 0) > 0);

  uint64_t start_ns = wamble_now_nanos();
  for (int i = 0; i < iters; i++) {
    int rc =
        send_reliable_message(srv, &msg, &cliaddr, get_config()->timeout_ms,
                              get_config()->max_retries);
    T_ASSERT_STATUS_OK(rc);
  }
  uint64_t end_ns = wamble_now_nanos();
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  uint64_t elapsed_ns = end_ns - start_ns;
  double avg_ns = (iters > 0) ? ((double)elapsed_ns / (double)iters) : 0.0;
  double tput =
      (elapsed_ns > 0) ? ((double)iters * 1e9 / (double)elapsed_ns) : 0.0;
  wamble_metric("perf_reliable_ack_latency",
                "iters=%d elapsed_ns=%llu avg_ns=%.0f throughput=%.2f msg/s",
                iters, (unsigned long long)elapsed_ns, avg_ns, tput);

  T_ASSERT(elapsed_ns < (uint64_t)9000 * 1000000ULL);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

typedef struct {
  wamble_socket_t sock;
  int count;
  volatile int stop;
} StressRecvCtx;

static void *stress_recv_thread(void *arg) {
  StressRecvCtx *c = arg;
  struct WambleMsg in;
  struct sockaddr_in from;
  while (!c->stop) {
    int rc = receive_message(c->sock, &in, &from);
    if (rc > 0)
      c->count++;
    else
      wamble_sleep_ms(1);
  }
  return NULL;
}

WAMBLE_TEST(stress_unreliable_burst) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);

  enum { NUM_CLIENTS = 8 };
  const int msgs_per_client = 5000;

  wamble_socket_t clis[NUM_CLIENTS];
  struct sockaddr_in cliaddr[NUM_CLIENTS];
  StressRecvCtx ctx[NUM_CLIENTS];
  wamble_thread_t th[NUM_CLIENTS];

  for (int i = 0; i < NUM_CLIENTS; i++) {
    clis[i] = socket(AF_INET, SOCK_DGRAM, 0);
    T_ASSERT(clis[i] != WAMBLE_INVALID_SOCKET);
    struct sockaddr_in bindaddr;
    memset(&bindaddr, 0, sizeof(bindaddr));
    bindaddr.sin_family = AF_INET;
    bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bindaddr.sin_port = 0;
    T_ASSERT(bind(clis[i], (struct sockaddr *)&bindaddr, sizeof(bindaddr)) ==
             0);
    (void)wamble_set_nonblocking(clis[i]);

    wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr[i]);
    T_ASSERT_STATUS_OK(
        getsockname(clis[i], (struct sockaddr *)&cliaddr[i], &slen));

    memset(&ctx[i], 0, sizeof(ctx[i]));
    ctx[i].sock = clis[i];
    ctx[i].stop = 0;
    T_ASSERT(wamble_thread_create(&th[i], stress_recv_thread, &ctx[i]) == 0);
  }

  for (int m = 0; m < msgs_per_client; m++) {
    for (int i = 0; i < NUM_CLIENTS; i++) {
      struct WambleMsg out;
      memset(&out, 0, sizeof(out));
      out.ctrl = WAMBLE_CTRL_SPECTATE_UPDATE;
      for (int j = 0; j < TOKEN_LENGTH; j++)
        out.token[j] = (uint8_t)(1 + ((i + j) & 0xFF));
      out.board_id = (uint64_t)(100000 + i * 1000 + m);
      snprintf(out.view.fen, FEN_MAX_LENGTH, "c%d-m%d", i, m);
      T_ASSERT_STATUS_OK(send_unreliable_packet(srv, &out, &cliaddr[i]));
    }
    if ((m & 255) == 0)
      wamble_sleep_ms(1);
  }

  int drain_ms = (get_config()->select_timeout_usec / 1000) * 2;
  if (drain_ms <= 0)
    drain_ms = 200;
  wamble_sleep_ms(drain_ms);
  for (int i = 0; i < NUM_CLIENTS; i++)
    ctx[i].stop = 1;

  int total_received = 0;
  for (int i = 0; i < NUM_CLIENTS; i++) {
    T_ASSERT_STATUS_OK(wamble_thread_join(th[i], NULL));
    total_received += ctx[i].count;
  }
  int expected = NUM_CLIENTS * msgs_per_client;
  wamble_metric(
      "stress_unreliable_burst",
      "clients=%d msgs_per_client=%d received=%d expected=%d received_"
      "pct=%.2f%%",
      NUM_CLIENTS, msgs_per_client, total_received, expected,
      expected > 0 ? (100.0 * (double)total_received / (double)expected) : 0.0);
  T_ASSERT(total_received >= (expected * 9) / 10);

  for (int i = 0; i < NUM_CLIENTS; i++)
    wamble_close_socket(clis[i]);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(speed_token_encode_decode) {
  uint8_t token[TOKEN_LENGTH];
  for (int i = 0; i < TOKEN_LENGTH; i++)
    token[i] = (uint8_t)(i * 7 + 3);
  char url[23];
  uint8_t out[TOKEN_LENGTH];
  uint64_t start_ns = wamble_now_nanos();
  int iters = 20000;
  for (int i = 0; i < iters; i++) {
    format_token_for_url(token, url);
    T_ASSERT_STATUS_OK(decode_token_from_url(url, out));
    T_ASSERT_EQ_INT((int)strlen(url), 22);
  }
  uint64_t end_ns = wamble_now_nanos();
  uint64_t elapsed_ns = end_ns - start_ns;
  double ops_per_sec =
      (elapsed_ns > 0) ? ((double)iters * 1e9 / (double)elapsed_ns) : 0.0;
  wamble_metric("speed_token_encode_decode",
                "iters=%d elapsed_ns=%llu ops_per_sec=%.2f", iters,
                (unsigned long long)elapsed_ns, ops_per_sec);
  T_ASSERT(elapsed_ns < (uint64_t)2e9);
  return 0;
}

WAMBLE_TEST(malformed_tiny_packet_rejected) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);
  struct sockaddr_in dst = {0};
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons((uint16_t)wamble_socket_bound_port(srv));
  uint8_t tiny[5] = {0xFF, 0, 0, 0, 0};
  T_ASSERT(sendto(cli, (const char *)tiny, sizeof tiny, 0,
                  (struct sockaddr *)&dst, sizeof dst) >= 0);
  struct WambleMsg in;
  struct sockaddr_in from;
  int rc = receive_message(srv, &in, &from);
  T_ASSERT_STATUS(rc, -1);
  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(unknown_ctrl_rejected) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);
  struct sockaddr_in dst = {0};
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons((uint16_t)wamble_socket_bound_port(srv));
  enum { H = 34 };
  uint8_t buf[H];
  memset(buf, 0, sizeof buf);
  buf[0] = 0xEE;
  buf[1] = 0x00;
  buf[2] = 1;
  buf[3] = 0;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    buf[4 + i] = (uint8_t)(i + 1);

  buf[31] = 1;

  T_ASSERT(sendto(cli, (const char *)buf, sizeof buf, 0,
                  (struct sockaddr *)&dst, sizeof dst) >= 0);
  struct WambleMsg in;
  struct sockaddr_in from;
  int rc = receive_message(srv, &in, &from);
  T_ASSERT_STATUS(rc, -1);
  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(spectate_stop_accept) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);
  struct sockaddr_in dst = {0};
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons((uint16_t)wamble_socket_bound_port(srv));

  enum { H = 34 };
  uint8_t buf[H];
  memset(buf, 0, sizeof buf);
  buf[0] = WAMBLE_CTRL_SPECTATE_STOP;
  buf[1] = 0x00;
  buf[2] = WAMBLE_PROTO_VERSION;
  buf[3] = 0x00;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    buf[4 + i] = (uint8_t)(i + 1);

  buf[31] = 1;

  T_ASSERT(sendto(cli, (const char *)buf, sizeof buf, 0,
                  (struct sockaddr *)&dst, sizeof dst) >= 0);
  struct WambleMsg in;
  struct sockaddr_in from;
  int rc = receive_message(srv, &in, &from);
  T_ASSERT(rc > 0);
  T_ASSERT_EQ_INT(in.ctrl, WAMBLE_CTRL_SPECTATE_STOP);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(reserved_nonzero_rejected) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);
  struct sockaddr_in dst = {0};
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons((uint16_t)wamble_socket_bound_port(srv));

  enum { H = 34 };
  uint8_t buf[H];
  memset(buf, 0, sizeof buf);
  buf[0] = WAMBLE_CTRL_CLIENT_HELLO;
  buf[1] = 0x00;
  buf[2] = WAMBLE_PROTO_VERSION;
  buf[3] = 0x7F;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    buf[4 + i] = (uint8_t)(0xAA);
  buf[31] = 1;

  T_ASSERT(sendto(cli, (const char *)buf, sizeof buf, 0,
                  (struct sockaddr *)&dst, sizeof dst) >= 0);
  struct WambleMsg in;
  struct sockaddr_in from;
  int rc = receive_message(srv, &in, &from);
  T_ASSERT_STATUS(rc, -1);
  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(legal_moves_count_guard) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);
  struct sockaddr_in dst = {0};
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons((uint16_t)wamble_socket_bound_port(srv));

  enum { H = 34 };
  enum { MC = 255 };
  enum { PL = 2 + (MC * 3) };
  uint8_t buf[H + PL];
  memset(buf, 0, sizeof buf);
  buf[0] = WAMBLE_CTRL_LEGAL_MOVES;
  buf[1] = 0x00;
  buf[2] = WAMBLE_PROTO_VERSION;
  buf[3] = 0x00;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    buf[4 + i] = (uint8_t)(i + 1);

  buf[31] = 1;
  buf[32] = (uint8_t)((PL >> 8) & 0xFF);
  buf[33] = (uint8_t)(PL & 0xFF);
  buf[34] = 0;
  buf[35] = (uint8_t)MC;
  for (int i = 0; i < MC; i++) {
    size_t off = 36 + (size_t)i * 3;
    buf[off + 0] = (uint8_t)(i & 63);
    buf[off + 1] = (uint8_t)((i + 1) & 63);
    buf[off + 2] = 0;
  }

  T_ASSERT(sendto(cli, (const char *)buf, sizeof buf, 0,
                  (struct sockaddr *)&dst, sizeof dst) >= 0);
  struct WambleMsg in;
  struct sockaddr_in from;
  int rc = receive_message(srv, &in, &from);
  T_ASSERT_STATUS(rc, -1);
  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(token_base64url_invalid) {
  uint8_t token[TOKEN_LENGTH];
  for (int i = 0; i < TOKEN_LENGTH; i++)
    token[i] = (uint8_t)(i * 13 + 7);
  char url[23];
  format_token_for_url(token, url);
  url[5] = '=';
  uint8_t out[TOKEN_LENGTH];
  int rc = decode_token_from_url(url, out);
  T_ASSERT(rc == -1);
  return 0;
}

WAMBLE_TEST(token_base64url_wrong_length) {
  const char *shorty = "ABCDEFGHIJKLMNOPQRSTU";
  uint8_t out[TOKEN_LENGTH];
  int rc = decode_token_from_url(shorty, out);
  T_ASSERT(rc == -1);
  return 0;
}

WAMBLE_TEST(zero_token_rejected) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);
  struct sockaddr_in dst = {0};
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons((uint16_t)wamble_socket_bound_port(srv));
  enum { H2 = 34 };
  uint8_t buf[H2 + 5];
  memset(buf, 0, sizeof buf);
  buf[0] = WAMBLE_CTRL_PLAYER_MOVE;
  buf[1] = 0x00;
  buf[2] = 1;
  buf[3] = 0;
  buf[32] = 0;
  buf[33] = 5;
  buf[34] = 4;
  buf[35] = 'e';
  buf[36] = '2';
  buf[37] = 'e';
  buf[38] = '4';
  T_ASSERT(sendto(cli, (const char *)buf, sizeof buf, 0,
                  (struct sockaddr *)&dst, sizeof dst) >= 0);
  struct WambleMsg in;
  struct sockaddr_in from;
  int rc = receive_message(srv, &in, &from);
  T_ASSERT_STATUS(rc, -1);
  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(zero_token_hello_allowed) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);
  struct sockaddr_in dst = {0};
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons((uint16_t)wamble_socket_bound_port(srv));
  enum { H = 34 };
  uint8_t buf[H];
  memset(buf, 0, sizeof buf);
  buf[0] = WAMBLE_CTRL_CLIENT_HELLO;
  buf[1] = 0x00;
  buf[2] = WAMBLE_PROTO_VERSION;
  buf[3] = 0x00;
  buf[31] = 1;
  T_ASSERT(sendto(cli, (const char *)buf, sizeof buf, 0,
                  (struct sockaddr *)&dst, sizeof dst) >= 0);
  struct WambleMsg in;
  struct sockaddr_in from;
  int rc = receive_message(srv, &in, &from);
  T_ASSERT(rc > 0);
  T_ASSERT_EQ_INT(in.ctrl, WAMBLE_CTRL_CLIENT_HELLO);
  for (int i = 0; i < TOKEN_LENGTH; i++)
    T_ASSERT_EQ_INT(in.token[i], 0);
  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(zero_token_reliable_list_profiles_isolation_by_client_addr) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli_a = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli_a != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli_b = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli_b != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr = {0};
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(
      bind(cli_a, (const struct sockaddr *)&bindaddr, sizeof(bindaddr)));
  T_ASSERT_STATUS_OK(
      bind(cli_b, (const struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in dst = {0};
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons((uint16_t)wamble_socket_bound_port(srv));

  enum { HEADER_SIZE = 34 };
  uint8_t pkt[HEADER_SIZE];
  memset(pkt, 0, sizeof(pkt));
  pkt[0] = WAMBLE_CTRL_LIST_PROFILES;
  pkt[2] = WAMBLE_PROTO_VERSION;

  T_ASSERT(sendto(cli_a, (const char *)pkt, sizeof(pkt), 0,
                  (struct sockaddr *)&dst, sizeof(dst)) >= 0);
  struct WambleMsg in_a = {0};
  struct sockaddr_in from_a = {0};
  int rc_a = receive_message(srv, &in_a, &from_a);
  T_ASSERT(rc_a > 0);
  T_ASSERT_EQ_INT(in_a.ctrl, WAMBLE_CTRL_LIST_PROFILES);

  T_ASSERT(sendto(cli_b, (const char *)pkt, sizeof(pkt), 0,
                  (struct sockaddr *)&dst, sizeof(dst)) >= 0);
  struct WambleMsg in_b = {0};
  struct sockaddr_in from_b = {0};
  int rc_b = receive_message(srv, &in_b, &from_b);
  T_ASSERT(rc_b > 0);
  T_ASSERT_EQ_INT(in_b.ctrl, WAMBLE_CTRL_LIST_PROFILES);

  wamble_close_socket(cli_b);
  wamble_close_socket(cli_a);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(player_move_valid_uci_accept) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);
  struct sockaddr_in dst = {0};
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons((uint16_t)wamble_socket_bound_port(srv));

  struct WambleMsg out;
  memset(&out, 0, sizeof(out));
  out.ctrl = WAMBLE_CTRL_PLAYER_MOVE;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(i + 1);
  out.board_id = 42;
  const char *uci = "e2e4";
  out.text.uci_len = (uint8_t)strlen(uci);
  memcpy(out.text.uci, uci, out.text.uci_len);
  T_ASSERT_STATUS_OK(send_unreliable_packet(cli, &out, &dst));

  struct WambleMsg in;
  struct sockaddr_in from;
  fd_set rfds;
  struct timeval tv;
  FD_ZERO(&rfds);
  FD_SET(srv, &rfds);
  tv.tv_sec = 0;
  tv.tv_usec = 400 * 1000;
#ifdef WAMBLE_PLATFORM_WINDOWS
  int ready = select(0, &rfds, NULL, NULL, &tv);
#else
  int ready = select(srv + 1, &rfds, NULL, NULL, &tv);
#endif
  int got = (ready > 0) ? receive_message(srv, &in, &from) : 0;
  T_ASSERT(got > 0);
  T_ASSERT_EQ_INT(in.ctrl, WAMBLE_CTRL_PLAYER_MOVE);
  T_ASSERT_EQ_INT(in.text.uci_len, (int)strlen(uci));
  T_ASSERT_STREQ(in.text.uci, uci);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(get_profile_info_long_name_roundtrip) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);
  struct sockaddr_in dst = {0};
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons((uint16_t)wamble_socket_bound_port(srv));

  struct WambleMsg out = {0};
  const char *name = "profile-long-name";
  out.ctrl = WAMBLE_CTRL_GET_PROFILE_INFO;
  out.text.profile_name_len = (uint8_t)strlen(name);
  memcpy(out.text.profile_name, name, strlen(name));
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(i + 1);

  T_ASSERT_STATUS_OK(send_unreliable_packet(cli, &out, &dst));

  struct WambleMsg in = {0};
  struct sockaddr_in from;
  int rc = receive_message(srv, &in, &from);
  T_ASSERT(rc > 0);
  T_ASSERT_EQ_INT(in.ctrl, WAMBLE_CTRL_GET_PROFILE_INFO);
  T_ASSERT_EQ_INT((int)in.text.profile_name_len, (int)strlen(name));
  T_ASSERT_STREQ(in.text.profile_name, name);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(profile_info_roundtrip) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  RecvOneCtx ctx = {.sock = cli};
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, recv_one_thread, &ctx) == 0);

  struct WambleMsg out = {0};
  out.ctrl = WAMBLE_CTRL_PROFILE_INFO;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(0x51 + i);
  snprintf(out.text.profile_info, sizeof(out.text.profile_info), "%s",
           "alpha;8888;1;0");
  out.text.profile_info_len = (uint16_t)strlen(out.text.profile_info);

  T_ASSERT_STATUS_OK(send_unreliable_packet(srv, &out, &cliaddr));
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  T_ASSERT_EQ_INT(ctx.received, 1);
  T_ASSERT_EQ_INT(ctx.msg.ctrl, WAMBLE_CTRL_PROFILE_INFO);
  T_ASSERT_EQ_INT((int)ctx.msg.text.profile_info_len,
                  (int)strlen("alpha;8888;1;0"));
  T_ASSERT_STREQ(ctx.msg.text.profile_info, "alpha;8888;1;0");

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(profile_info_endpoint_ext_roundtrip) {
  uint8_t buffer[WAMBLE_MAX_PACKET_SIZE];
  size_t serialized = 0;
  uint8_t flags = 0;
  struct WambleMsg out = {0};
  struct WambleMsg in = {0};

  out.ctrl = WAMBLE_CTRL_PROFILE_INFO;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(0x61 + i);
  snprintf(out.text.profile_info, sizeof(out.text.profile_info), "%s",
           "alpha;8888;1;0");
  out.text.profile_info_len = (uint16_t)strlen(out.text.profile_info);

  out.extensions.count = 3;
  snprintf(out.extensions.fields[0].key, sizeof(out.extensions.fields[0].key),
           "%s", "profile.caps");
  out.extensions.fields[0].value_type = WAMBLE_TREATMENT_VALUE_INT;
  out.extensions.fields[0].int_value = WAMBLE_PROFILE_UI_CAP_TOS;
  snprintf(out.extensions.fields[1].key, sizeof(out.extensions.fields[1].key),
           "%s", "profile.websocket_port");
  out.extensions.fields[1].value_type = WAMBLE_TREATMENT_VALUE_INT;
  out.extensions.fields[1].int_value = 19421;
  snprintf(out.extensions.fields[2].key, sizeof(out.extensions.fields[2].key),
           "%s", "profile.websocket_path");
  out.extensions.fields[2].value_type = WAMBLE_TREATMENT_VALUE_STRING;
  snprintf(out.extensions.fields[2].string_value,
           sizeof(out.extensions.fields[2].string_value), "%s", "/proxy/p1/ws");

  T_ASSERT_EQ_INT(wamble_packet_serialize(&out, buffer, sizeof(buffer),
                                          &serialized, WAMBLE_FLAG_UNRELIABLE),
                  NET_OK);
  T_ASSERT_EQ_INT(wamble_packet_deserialize(buffer, serialized, &in, &flags),
                  NET_OK);
  T_ASSERT((flags & WAMBLE_FLAG_UNRELIABLE) != 0);
  T_ASSERT((flags & WAMBLE_FLAG_EXT_PAYLOAD) != 0);
  T_ASSERT_EQ_INT(in.ctrl, WAMBLE_CTRL_PROFILE_INFO);
  T_ASSERT_STREQ(in.text.profile_info, out.text.profile_info);
  T_ASSERT_EQ_INT((int)in.extensions.count, 3);

  const WambleMessageExtField *caps = find_ext_field(&in, "profile.caps");
  const WambleMessageExtField *ws_port =
      find_ext_field(&in, "profile.websocket_port");
  const WambleMessageExtField *ws_path =
      find_ext_field(&in, "profile.websocket_path");
  T_ASSERT(caps != NULL);
  T_ASSERT(ws_port != NULL);
  T_ASSERT(ws_path != NULL);
  T_ASSERT_EQ_INT(caps->value_type, WAMBLE_TREATMENT_VALUE_INT);
  T_ASSERT_EQ_INT((int)caps->int_value, (int)WAMBLE_PROFILE_UI_CAP_TOS);
  T_ASSERT_EQ_INT(ws_port->value_type, WAMBLE_TREATMENT_VALUE_INT);
  T_ASSERT_EQ_INT((int)ws_port->int_value, 19421);
  T_ASSERT_EQ_INT(ws_path->value_type, WAMBLE_TREATMENT_VALUE_STRING);
  T_ASSERT_STREQ(ws_path->string_value, "/proxy/p1/ws");

  return 0;
}

WAMBLE_TEST(profiles_list_roundtrip) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  RecvOneCtx ctx = {.sock = cli};
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, recv_one_thread, &ctx) == 0);

  struct WambleMsg out = {0};
  out.ctrl = WAMBLE_CTRL_PROFILES_LIST;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(0x61 + i);
  snprintf(out.view.profiles_list, sizeof(out.view.profiles_list), "%s",
           "alpha,beta,canary");
  out.view.profiles_list_len = (uint16_t)strlen(out.view.profiles_list);

  T_ASSERT_STATUS_OK(send_unreliable_packet(srv, &out, &cliaddr));
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  T_ASSERT_EQ_INT(ctx.received, 1);
  T_ASSERT_EQ_INT(ctx.msg.ctrl, WAMBLE_CTRL_PROFILES_LIST);
  T_ASSERT_EQ_INT((int)ctx.msg.view.profiles_list_len,
                  (int)strlen("alpha,beta,canary"));
  T_ASSERT_STREQ(ctx.msg.view.profiles_list, "alpha,beta,canary");

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(player_move_uci_len_guard) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);
  struct sockaddr_in dst = {0};
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons((uint16_t)wamble_socket_bound_port(srv));
  enum { H = 34 };
  uint8_t buf[H + 8];
  memset(buf, 0, sizeof buf);
  buf[0] = WAMBLE_CTRL_PLAYER_MOVE;
  buf[1] = 0x00;
  buf[2] = 1;
  buf[3] = 0;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    buf[4 + i] = 1;
  buf[31] = 1;

  buf[32] = 0;
  buf[33] = 8;

  buf[34] = (uint8_t)(MAX_UCI_LENGTH + 1);
  for (int i = 0; i < (MAX_UCI_LENGTH + 1); i++)
    buf[35 + i] = (uint8_t)('a' + (i % 26));
  T_ASSERT(sendto(cli, (const char *)buf, sizeof buf, 0,
                  (struct sockaddr *)&dst, sizeof dst) >= 0);
  struct WambleMsg in;
  struct sockaddr_in from;
  int rc = receive_message(srv, &in, &from);
  T_ASSERT(rc == -1);
  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(server_protocol_client_hello_requires_policy) {
  const char *cfg_path = "build/test_network_client_hello_policy.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(defprofile p1 ((def port 19419) (def advertise 1)))\n";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test');") !=
      0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  player_manager_init();
  board_manager_init();

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);
  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));
  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  struct WambleMsg hello = {0};
  hello.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  hello.token[0] = 0x11;

  RecvOneCtx rx1 = {.sock = cli};
  wamble_thread_t th1;
  T_ASSERT(wamble_thread_create(&th1, recv_one_thread, &rx1) == 0);

  ServerStatus hello_policy_status =
      handle_message(srv, &hello, &cliaddr, 0, "p1");
  T_ASSERT(hello_policy_status == SERVER_ERR_FORBIDDEN ||
           hello_policy_status == SERVER_ERR_SEND_FAILED);
  T_ASSERT_STATUS_OK(wamble_thread_join(th1, NULL));
  if (rx1.received) {
    T_ASSERT_EQ_INT(rx1.msg.ctrl, WAMBLE_CTRL_ERROR);
    T_ASSERT_EQ_INT(rx1.msg.view.error_code, WAMBLE_ERR_ACCESS_DENIED);
    T_ASSERT_EQ_INT(rx1.msg.view.error_reason[0], '\0');
  }

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(server_protocol_client_hello_advertises_session_caps) {
  const char *cfg_path = "build/test_network_client_hello_caps.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(def prediction-mode 0)\n"
                    "(defprofile p1 ((def port 19420) (def advertise 1)))\n";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 2, 'trust', 'test'), "
          "(0, 'protocol.ctrl', 'client_hello', '*', 'allow', 0, "
          "'hello_access', 'test'), "
          "(0, 'protocol.ctrl', 'login_request', '*', 'allow', 0, "
          "'login_access', 'test'), "
          "(0, 'protocol.ctrl', 'logout', '*', 'allow', 0, "
          "'logout_access', 'test'), "
          "(0, 'protocol.ctrl', 'get_legal_moves', '*', 'allow', 0, "
          "'legal_access', 'test'), "
          "(0, 'protocol.ctrl', 'player_move', '*', 'allow', 0, "
          "'move_access', 'test'), "
          "(0, 'protocol.ctrl', 'spectate_game', '*', 'allow', 0, "
          "'spectate_access', 'test'), "
          "(0, 'protocol.ctrl', 'spectate_stop', '*', 'allow', 0, "
          "'spectate_stop_access', 'test'), "
          "(0, 'game.move', 'legal', '*', 'allow', 0, 'legal', 'test'), "
          "(0, 'game.move', 'play', '*', 'allow', 0, 'play', 'test'), "
          "(0, 'spectate.access', 'view', '*', 'allow', 0, 'spectate', "
          "'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  player_manager_init();
  board_manager_init();

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  struct WambleMsg hello = {0};
  hello.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  hello.header_version = WAMBLE_PROTO_VERSION;
  hello.seq_num = 8;
  hello.token[0] = 0x33;

  RecvOneCtx rx = {.sock = cli};
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, recv_one_and_ack_thread, &rx) == 0);

  T_ASSERT_EQ_INT(handle_message(srv, &hello, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));
  T_ASSERT_EQ_INT(rx.received, 1);
  T_ASSERT_EQ_INT(rx.msg.ctrl, WAMBLE_CTRL_SERVER_HELLO);
  T_ASSERT_EQ_INT(rx.msg.header_version, WAMBLE_PROTO_VERSION);

  const WambleMessageExtField *caps = find_ext_field(&rx.msg, "session.caps");
  T_ASSERT(caps != NULL);
  T_ASSERT_EQ_INT(caps->value_type, WAMBLE_TREATMENT_VALUE_INT);
  T_ASSERT((caps->int_value & WAMBLE_SESSION_UI_CAP_ATTACH_IDENTITY) != 0);
  T_ASSERT((caps->int_value & WAMBLE_SESSION_UI_CAP_LOGOUT) != 0);
  T_ASSERT((caps->int_value & WAMBLE_SESSION_UI_CAP_MOVE) != 0);
  T_ASSERT((caps->int_value & WAMBLE_SESSION_UI_CAP_SPECTATE_SUMMARY) != 0);
  T_ASSERT((caps->int_value & WAMBLE_SESSION_UI_CAP_SPECTATE_FOCUS) != 0);
  T_ASSERT((caps->int_value & WAMBLE_SESSION_UI_CAP_STATS) == 0);
  T_ASSERT((caps->int_value & WAMBLE_SESSION_UI_CAP_LEADERBOARD) == 0);
  T_ASSERT((caps->int_value & WAMBLE_SESSION_UI_CAP_PREDICTION_SUBMIT) == 0);
  T_ASSERT((caps->int_value & WAMBLE_SESSION_UI_CAP_PREDICTION_READ) == 0);
  T_ASSERT(find_ext_field(&rx.msg, "trust.tier") == NULL);
  T_ASSERT(find_ext_field(&rx.msg, "prediction.source") == NULL);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(server_protocol_client_hello_reuses_existing_reserved_board) {
  const char *cfg_path = "build/test_network_client_hello_reuse_board.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(def reservation-timeout 120)\n"
                    "(defprofile p1 ((def port 19421) (def advertise 1)))\n";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 2, 'trust', 'test'), "
          "(0, 'protocol.ctrl', 'client_hello', '*', 'allow', 0, "
          "'hello_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  player_manager_init();
  board_manager_init();

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  struct WambleMsg hello = {0};
  hello.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  hello.header_version = WAMBLE_PROTO_VERSION;
  hello.token[0] = 0x51;

  RecvOneCtx rx1 = {.sock = cli};
  wamble_thread_t th1;
  T_ASSERT(wamble_thread_create(&th1, recv_one_and_ack_thread, &rx1) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &hello, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th1, NULL));
  T_ASSERT_EQ_INT(rx1.received, 1);
  T_ASSERT_EQ_INT(rx1.msg.ctrl, WAMBLE_CTRL_SERVER_HELLO);

  uint64_t board_id_1 = rx1.msg.board_id;
  WambleBoard *board_1 = get_board_by_id(board_id_1);
  T_ASSERT(board_1 != NULL);
  time_t reserved_at_1 = board_1->reservation_time;
  T_ASSERT(board_is_reserved_for_player(board_id_1, rx1.msg.token));
  const WambleMessageExtField *reserved_at_ext_1 =
      find_ext_field(&rx1.msg, "reservation.reserved_at");
  T_ASSERT(reserved_at_ext_1 != NULL);
  T_ASSERT_EQ_INT(reserved_at_ext_1->value_type, WAMBLE_TREATMENT_VALUE_INT);

  struct WambleMsg hello_again = {0};
  hello_again.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  hello_again.header_version = WAMBLE_PROTO_VERSION;
  memcpy(hello_again.token, rx1.msg.token, TOKEN_LENGTH);

  RecvOneCtx rx2 = {.sock = cli};
  wamble_thread_t th2;
  T_ASSERT(wamble_thread_create(&th2, recv_one_and_ack_thread, &rx2) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &hello_again, &cliaddr, 0, "p1"),
                  SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th2, NULL));
  T_ASSERT_EQ_INT(rx2.received, 1);
  T_ASSERT_EQ_INT(rx2.msg.ctrl, WAMBLE_CTRL_SERVER_HELLO);
  T_ASSERT(tokens_equal(rx1.msg.token, rx2.msg.token));
  T_ASSERT_EQ_INT((int)rx2.msg.board_id, (int)board_id_1);
  T_ASSERT(board_is_reserved_for_player(rx2.msg.board_id, rx2.msg.token));

  WambleBoard *board_2 = get_board_by_id(rx2.msg.board_id);
  T_ASSERT(board_2 != NULL);
  T_ASSERT_EQ_INT((int)board_2->reservation_time, (int)reserved_at_1);
  const WambleMessageExtField *reserved_at_ext_2 =
      find_ext_field(&rx2.msg, "reservation.reserved_at");
  T_ASSERT(reserved_at_ext_2 != NULL);
  T_ASSERT_EQ_INT(reserved_at_ext_2->value_type, WAMBLE_TREATMENT_VALUE_INT);
  T_ASSERT_EQ_INT((int)reserved_at_ext_2->int_value,
                  (int)reserved_at_ext_1->int_value);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(server_protocol_profile_info_advertises_profile_caps) {
  const char *cfg_path = "build/test_network_profile_info_caps.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(defprofile p1 ((def port 19421) (def advertise 1) "
                    "(def tos-text \"terms\")))\n";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test'), "
          "(0, 'protocol.ctrl', 'get_profile_info', '*', 'allow', 0, "
          "'profile_info_access', 'test'), "
          "(0, 'protocol.ctrl', 'get_profile_tos', '*', 'allow', 0, "
          "'profile_tos_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  struct WambleMsg req = {0};
  req.ctrl = WAMBLE_CTRL_GET_PROFILE_INFO;
  req.token[0] = 0x44;
  req.text.profile_name_len = 2;
  memcpy(req.text.profile_name, "p1", 2);

  RecvOneCtx rx = {.sock = cli};
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, recv_one_and_ack_thread, &rx) == 0);

  T_ASSERT_EQ_INT(handle_message(srv, &req, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));
  T_ASSERT_EQ_INT(rx.received, 1);
  T_ASSERT_EQ_INT(rx.msg.ctrl, WAMBLE_CTRL_PROFILE_INFO);

  const WambleMessageExtField *caps = find_ext_field(&rx.msg, "profile.caps");
  const WambleMessageExtField *ws_port =
      find_ext_field(&rx.msg, "profile.websocket_port");
  const WambleMessageExtField *ws_path =
      find_ext_field(&rx.msg, "profile.websocket_path");
  T_ASSERT(caps != NULL);
  T_ASSERT(ws_port != NULL);
  T_ASSERT_EQ_INT(caps->value_type, WAMBLE_TREATMENT_VALUE_INT);
  T_ASSERT_EQ_INT(ws_port->value_type, WAMBLE_TREATMENT_VALUE_INT);
  T_ASSERT((caps->int_value & WAMBLE_PROFILE_UI_CAP_JOIN) == 0);
  T_ASSERT((caps->int_value & WAMBLE_PROFILE_UI_CAP_TOS) != 0);
  T_ASSERT_EQ_INT((int)ws_port->int_value, 0);
  T_ASSERT(ws_path == NULL);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(server_protocol_profile_info_omits_tos_cap_when_text_empty) {
  const char *cfg_path = "build/test_network_profile_info_empty_tos.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(defprofile p1 ((def port 19422) (def advertise 1) "
                    "(def tos-text \"\")))\n";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test'), "
          "(0, 'protocol.ctrl', 'get_profile_info', '*', 'allow', 0, "
          "'profile_info_access', 'test'), "
          "(0, 'protocol.ctrl', 'get_profile_tos', '*', 'allow', 0, "
          "'profile_tos_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  struct WambleMsg req = {0};
  req.ctrl = WAMBLE_CTRL_GET_PROFILE_INFO;
  req.token[0] = 0x45;
  req.text.profile_name_len = 2;
  memcpy(req.text.profile_name, "p1", 2);

  RecvOneCtx rx = {.sock = cli};
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, recv_one_and_ack_thread, &rx) == 0);

  T_ASSERT_EQ_INT(handle_message(srv, &req, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));
  T_ASSERT_EQ_INT(rx.received, 1);
  T_ASSERT_EQ_INT(rx.msg.ctrl, WAMBLE_CTRL_PROFILE_INFO);

  const WambleMessageExtField *caps = find_ext_field(&rx.msg, "profile.caps");
  T_ASSERT(caps != NULL);
  T_ASSERT_EQ_INT(caps->value_type, WAMBLE_TREATMENT_VALUE_INT);
  T_ASSERT((caps->int_value & WAMBLE_PROFILE_UI_CAP_TOS) == 0);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(server_protocol_accept_profile_tos_persists_terms) {
  const char *cfg_path = "build/test_network_accept_profile_tos.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(defprofile p1 ((def port 19423) (def advertise 1) "
                    "(def tos-text \"profile terms v1\")))\n";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test'), "
          "(0, 'protocol.ctrl', 'client_hello', '*', 'allow', 0, "
          "'hello_access', 'test'), "
          "(0, 'protocol.ctrl', 'accept_profile_tos', '*', 'allow', 0, "
          "'accept_profile_tos_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  player_manager_init();
  board_manager_init();

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  struct WambleMsg hello = {0};
  hello.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  hello.header_version = WAMBLE_PROTO_VERSION;

  RecvOneCtx rx_hello = {.sock = cli};
  wamble_thread_t th_hello;
  T_ASSERT(
      wamble_thread_create(&th_hello, recv_one_and_ack_thread, &rx_hello) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &hello, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_hello, NULL));
  T_ASSERT_EQ_INT(rx_hello.received, 1);
  T_ASSERT_EQ_INT(rx_hello.msg.ctrl, WAMBLE_CTRL_SERVER_HELLO);

  struct WambleMsg accept = {0};
  accept.ctrl = WAMBLE_CTRL_ACCEPT_PROFILE_TOS;
  accept.header_version = WAMBLE_PROTO_VERSION;
  accept.seq_num = 101;
  memcpy(accept.token, rx_hello.msg.token, TOKEN_LENGTH);
  memcpy(accept.text.profile_name, "p1", 2);
  accept.text.profile_name_len = 2;

  RecvOneCtx rx_accept = {.sock = cli};
  wamble_thread_t th_accept;
  T_ASSERT(wamble_thread_create(&th_accept, recv_one_and_ack_thread,
                                &rx_accept) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &accept, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_accept, NULL));
  T_ASSERT_EQ_INT(rx_accept.received, 1);
  T_ASSERT_EQ_INT(rx_accept.msg.ctrl, WAMBLE_CTRL_PROFILE_INFO);
  {
    const WambleMessageExtField *request_seq =
        find_ext_field(&rx_accept.msg, "request.seq_num");
    const WambleMessageExtField *tos_accepted =
        find_ext_field(&rx_accept.msg, "profile.tos_accepted");
    const WambleMessageExtField *session_caps =
        find_ext_field(&rx_accept.msg, "session.caps");
    T_ASSERT(request_seq != NULL);
    T_ASSERT(tos_accepted != NULL);
    T_ASSERT(session_caps != NULL);
    T_ASSERT_EQ_INT((int)request_seq->int_value, (int)accept.seq_num);
    T_ASSERT_EQ_INT((int)tos_accepted->int_value, 1);
    T_ASSERT(rx_accept.msg.board_id > 0);
    T_ASSERT(session_caps->int_value > 0);
  }

  {
    WambleProfileTermsAcceptance acceptance = {0};
    uint8_t expected_hash[WAMBLE_FRAGMENT_HASH_LENGTH] = {0};
    crypto_blake2b(expected_hash, sizeof(expected_hash),
                   (const uint8_t *)"profile terms v1",
                   strlen("profile terms v1"));
    T_ASSERT_EQ_INT(wamble_query_get_latest_profile_terms_acceptance(
                        rx_hello.msg.token, "p1", &acceptance),
                    DB_OK);
    T_ASSERT_STREQ(acceptance.profile_name, "p1");
    T_ASSERT(acceptance.tos_text != NULL);
    T_ASSERT_STREQ(acceptance.tos_text, "profile terms v1");
    T_ASSERT(memcmp(acceptance.tos_hash, expected_hash,
                    WAMBLE_FRAGMENT_HASH_LENGTH) == 0);
    wamble_profile_terms_acceptance_clear(&acceptance);
  }

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(server_protocol_terms_routes_allow_hidden_bound_profile) {
  const char *cfg_path = "build/test_network_hidden_profile_terms.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(defprofile p1 ((def port 19423) (def advertise 0) "
                    "(def tos-text \"private profile terms\")))\n";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 0, 'trust', 'test'), "
          "(0, 'protocol.ctrl', 'client_hello', '*', 'allow', 0, "
          "'hello_access', 'test'), "
          "(0, 'protocol.ctrl', 'get_profile_tos', '*', 'allow', 0, "
          "'get_profile_tos_access', 'test'), "
          "(0, 'protocol.ctrl', 'accept_profile_tos', '*', 'allow', 0, "
          "'accept_profile_tos_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  player_manager_init();
  board_manager_init();

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  struct WambleMsg hello = {0};
  hello.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  hello.header_version = WAMBLE_PROTO_VERSION;

  RecvOneCtx rx_hello = {.sock = cli};
  wamble_thread_t th_hello;
  T_ASSERT(
      wamble_thread_create(&th_hello, recv_one_and_ack_thread, &rx_hello) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &hello, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_hello, NULL));
  T_ASSERT_EQ_INT(rx_hello.received, 1);
  T_ASSERT_EQ_INT(rx_hello.msg.ctrl, WAMBLE_CTRL_SERVER_HELLO);

  struct WambleMsg tos_req = {0};
  tos_req.ctrl = WAMBLE_CTRL_GET_PROFILE_TOS;
  tos_req.header_version = WAMBLE_PROTO_VERSION;
  memcpy(tos_req.token, rx_hello.msg.token, TOKEN_LENGTH);
  memcpy(tos_req.text.profile_name, "p1", 2);
  tos_req.text.profile_name_len = 2;

  RecvTosFragmentsCtx rx_tos = {.sock = cli};
  wamble_thread_t th_tos;
  T_ASSERT(wamble_thread_create(&th_tos, recv_tos_fragments_and_ack_thread,
                                &rx_tos) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &tos_req, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_tos, NULL));
  T_ASSERT_EQ_INT(rx_tos.received, 1);
  T_ASSERT_EQ_INT(rx_tos.expected_chunks, 1);
  {
    char echoed_profile[PROFILE_NAME_MAX_LENGTH];
    size_t base_len = 0;
    T_ASSERT(parse_payload_string_ext(rx_tos.assembled, rx_tos.assembled_len,
                                      "profile.name", &base_len, echoed_profile,
                                      sizeof(echoed_profile)));
    T_ASSERT_EQ_INT((int)base_len, (int)strlen("private profile terms"));
    T_ASSERT(memcmp(rx_tos.assembled, "private profile terms", base_len) == 0);
    T_ASSERT_STREQ(echoed_profile, "p1");
  }

  struct WambleMsg accept = {0};
  accept.ctrl = WAMBLE_CTRL_ACCEPT_PROFILE_TOS;
  accept.header_version = WAMBLE_PROTO_VERSION;
  accept.seq_num = 102;
  memcpy(accept.token, rx_hello.msg.token, TOKEN_LENGTH);
  memcpy(accept.text.profile_name, "p1", 2);
  accept.text.profile_name_len = 2;

  RecvOneCtx rx_accept = {.sock = cli};
  wamble_thread_t th_accept;
  T_ASSERT(wamble_thread_create(&th_accept, recv_one_and_ack_thread,
                                &rx_accept) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &accept, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_accept, NULL));
  T_ASSERT_EQ_INT(rx_accept.received, 1);
  T_ASSERT_EQ_INT(rx_accept.msg.ctrl, WAMBLE_CTRL_PROFILE_INFO);
  {
    const WambleMessageExtField *request_seq =
        find_ext_field(&rx_accept.msg, "request.seq_num");
    const WambleMessageExtField *tos_accepted =
        find_ext_field(&rx_accept.msg, "profile.tos_accepted");
    T_ASSERT(request_seq != NULL);
    T_ASSERT(tos_accepted != NULL);
    T_ASSERT_EQ_INT((int)request_seq->int_value, (int)accept.seq_num);
    T_ASSERT_EQ_INT((int)tos_accepted->int_value, 1);
  }

  {
    WambleProfileTermsAcceptance acceptance = {0};
    T_ASSERT_EQ_INT(wamble_query_get_latest_profile_terms_acceptance(
                        rx_hello.msg.token, "p1", &acceptance),
                    DB_OK);
    T_ASSERT_STREQ(acceptance.profile_name, "p1");
    T_ASSERT(acceptance.tos_text != NULL);
    T_ASSERT_STREQ(acceptance.tos_text, "private profile terms");
    wamble_profile_terms_acceptance_clear(&acceptance);
  }

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(
    server_protocol_profile_terms_gate_session_for_profile_until_acceptance) {
  const char *cfg_path = "build/test_network_profile_terms_gate.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(defprofile p1 ((def port 19424) (def advertise 1) "
                    "(def tos-text \"profile terms v1\")))\n";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test'), "
          "(0, 'protocol.ctrl', 'client_hello', '*', 'allow', 0, "
          "'hello_access', 'test'), "
          "(0, 'protocol.ctrl', 'accept_profile_tos', '*', 'allow', 0, "
          "'accept_profile_tos_access', 'test'), "
          "(0, 'protocol.ctrl', 'get_profile_info', '*', 'allow', 0, "
          "'profile_info_access', 'test'), "
          "(0, 'protocol.ctrl', 'get_profile_tos', '*', 'allow', 0, "
          "'profile_tos_access', 'test'), "
          "(0, 'protocol.ctrl', 'get_player_stats', '*', 'allow', 0, "
          "'stats_access', 'test'), "
          "(0, 'stats.read', 'player', '*', 'allow', 0, "
          "'stats_read', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  player_manager_init();
  board_manager_init();

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  struct WambleMsg hello = {0};
  hello.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  hello.header_version = WAMBLE_PROTO_VERSION;

  RecvOneCtx rx_hello = {.sock = cli};
  wamble_thread_t th_hello;
  T_ASSERT(
      wamble_thread_create(&th_hello, recv_one_and_ack_thread, &rx_hello) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &hello, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_hello, NULL));
  T_ASSERT_EQ_INT(rx_hello.received, 1);
  T_ASSERT_EQ_INT(rx_hello.msg.ctrl, WAMBLE_CTRL_SERVER_HELLO);
  {
    const WambleMessageExtField *caps =
        find_ext_field(&rx_hello.msg, "session.caps");
    T_ASSERT(caps != NULL);
    T_ASSERT_EQ_INT(caps->value_type, WAMBLE_TREATMENT_VALUE_INT);
    T_ASSERT_EQ_INT((int)caps->int_value, 0);
  }

  struct WambleMsg post_join_req = {0};
  post_join_req.ctrl = WAMBLE_CTRL_GET_PLAYER_STATS;
  post_join_req.header_version = WAMBLE_PROTO_VERSION;
  memcpy(post_join_req.token, rx_hello.msg.token, TOKEN_LENGTH);

  RecvOneCtx rx_denied = {.sock = cli};
  wamble_thread_t th_denied;
  T_ASSERT(wamble_thread_create(&th_denied, recv_one_and_ack_thread,
                                &rx_denied) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &post_join_req, &cliaddr, 0, "p1"),
                  SERVER_ERR_FORBIDDEN);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_denied, NULL));
  T_ASSERT_EQ_INT(rx_denied.received, 1);
  T_ASSERT_EQ_INT(rx_denied.msg.ctrl, WAMBLE_CTRL_ERROR);
  T_ASSERT_EQ_INT(rx_denied.msg.view.error_code, WAMBLE_ERR_ACCESS_DENIED);
  T_ASSERT_STREQ(rx_denied.msg.view.error_reason, "terms acceptance required");

  struct WambleMsg accept = {0};
  accept.ctrl = WAMBLE_CTRL_ACCEPT_PROFILE_TOS;
  accept.header_version = WAMBLE_PROTO_VERSION;
  accept.seq_num = 103;
  memcpy(accept.token, rx_hello.msg.token, TOKEN_LENGTH);
  memcpy(accept.text.profile_name, "p1", 2);
  accept.text.profile_name_len = 2;

  RecvOneCtx rx_accept = {.sock = cli};
  wamble_thread_t th_accept;
  T_ASSERT(wamble_thread_create(&th_accept, recv_one_and_ack_thread,
                                &rx_accept) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &accept, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_accept, NULL));
  T_ASSERT_EQ_INT(rx_accept.received, 1);
  T_ASSERT_EQ_INT(rx_accept.msg.ctrl, WAMBLE_CTRL_PROFILE_INFO);
  {
    const WambleMessageExtField *request_seq =
        find_ext_field(&rx_accept.msg, "request.seq_num");
    const WambleMessageExtField *tos_accepted =
        find_ext_field(&rx_accept.msg, "profile.tos_accepted");
    const WambleMessageExtField *caps =
        find_ext_field(&rx_accept.msg, "session.caps");
    T_ASSERT(request_seq != NULL);
    T_ASSERT(tos_accepted != NULL);
    T_ASSERT(caps != NULL);
    T_ASSERT_EQ_INT((int)request_seq->int_value, (int)accept.seq_num);
    T_ASSERT_EQ_INT((int)tos_accepted->int_value, 1);
    T_ASSERT(caps->int_value != 0);
  }

  struct WambleMsg hello_after = {0};
  hello_after.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  hello_after.header_version = WAMBLE_PROTO_VERSION;
  memcpy(hello_after.token, rx_hello.msg.token, TOKEN_LENGTH);

  RecvOneCtx rx_hello_after = {.sock = cli};
  wamble_thread_t th_hello_after;
  T_ASSERT(wamble_thread_create(&th_hello_after, recv_one_and_ack_thread,
                                &rx_hello_after) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &hello_after, &cliaddr, 0, "p1"),
                  SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_hello_after, NULL));
  T_ASSERT_EQ_INT(rx_hello_after.received, 1);
  T_ASSERT_EQ_INT(rx_hello_after.msg.ctrl, WAMBLE_CTRL_SERVER_HELLO);
  {
    const WambleMessageExtField *caps =
        find_ext_field(&rx_hello_after.msg, "session.caps");
    T_ASSERT(caps != NULL);
    T_ASSERT_EQ_INT(caps->value_type, WAMBLE_TREATMENT_VALUE_INT);
    T_ASSERT(caps->int_value != 0);
  }
  {
    int token_nonzero = 0;
    for (int i = 0; i < TOKEN_LENGTH; i++) {
      if (rx_hello_after.msg.token[i] != 0) {
        token_nonzero = 1;
        break;
      }
    }
    T_ASSERT(token_nonzero);
  }
  memcpy(post_join_req.token, rx_hello_after.msg.token, TOKEN_LENGTH);

  RecvOneCtx rx_post_join = {.sock = cli};
  wamble_thread_t th_post_join;
  T_ASSERT(wamble_thread_create(&th_post_join, recv_one_and_ack_thread,
                                &rx_post_join) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &post_join_req, &cliaddr, 0, "p1"),
                  SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_post_join, NULL));
  T_ASSERT_EQ_INT(rx_post_join.received, 1);
  T_ASSERT_EQ_INT(rx_post_join.msg.ctrl, WAMBLE_CTRL_PLAYER_STATS_DATA);

  {
    struct WambleMsg profile_info_req = {0};
    profile_info_req.ctrl = WAMBLE_CTRL_GET_PROFILE_INFO;
    profile_info_req.header_version = WAMBLE_PROTO_VERSION;
    memcpy(profile_info_req.token, rx_hello_after.msg.token, TOKEN_LENGTH);
    memcpy(profile_info_req.text.profile_name, "p1", 2);
    profile_info_req.text.profile_name_len = 2;

    RecvOneCtx rx_profile_info = {.sock = cli};
    wamble_thread_t th_profile_info;
    T_ASSERT(wamble_thread_create(&th_profile_info, recv_one_and_ack_thread,
                                  &rx_profile_info) == 0);
    T_ASSERT_EQ_INT(handle_message(srv, &profile_info_req, &cliaddr, 0, "p1"),
                    SERVER_OK);
    T_ASSERT_STATUS_OK(wamble_thread_join(th_profile_info, NULL));
    T_ASSERT_EQ_INT(rx_profile_info.received, 1);
    T_ASSERT_EQ_INT(rx_profile_info.msg.ctrl, WAMBLE_CTRL_PROFILE_INFO);
    {
      const WambleMessageExtField *caps =
          find_ext_field(&rx_profile_info.msg, "profile.caps");
      const WambleMessageExtField *tos_available =
          find_ext_field(&rx_profile_info.msg, "profile.tos_available");
      const WambleMessageExtField *tos_accepted =
          find_ext_field(&rx_profile_info.msg, "profile.tos_accepted");
      T_ASSERT(caps != NULL);
      T_ASSERT(tos_available != NULL);
      T_ASSERT(tos_accepted != NULL);
      T_ASSERT((caps->int_value & WAMBLE_PROFILE_UI_CAP_TOS) != 0);
      T_ASSERT_EQ_INT((int)tos_available->int_value, 1);
      T_ASSERT_EQ_INT((int)tos_accepted->int_value, 1);
    }
  }

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(server_protocol_spectate_denial_reports_capacity_full_error_code) {
  const char *cfg_path = "build/test_network_spectate_denial_codes.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(def max-spectators 0)\n"
                    "(defprofile p1 ((def port 19424) (def advertise 1)))\n";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test'), "
          "(0, 'protocol.ctrl', 'spectate_game', '*', 'allow', 0, "
          "'spectate_game_access', 'test'), "
          "(0, 'protocol.ctrl', 'spectate_stop', '*', 'allow', 0, "
          "'spectate_stop_access', 'test'), "
          "(0, 'spectate.access', 'view', '*', 'allow', 0, "
          "'spectate_view_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  player_manager_init();
  board_manager_init();
  spectator_manager_init();

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  struct WambleMsg req = {0};
  req.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  req.header_version = WAMBLE_PROTO_VERSION;
  req.flags = WAMBLE_FLAG_UNRELIABLE;
  req.token[0] = 0x77;
  req.board_id = 0;

  RecvOneCtx rx = {.sock = cli};
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, recv_one_and_ack_thread, &rx) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &req, &cliaddr, 0, "p1"),
                  SERVER_ERR_SPECTATOR);
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));
  T_ASSERT_EQ_INT(rx.received, 1);
  T_ASSERT_EQ_INT(rx.msg.ctrl, WAMBLE_CTRL_ERROR);
  T_ASSERT_EQ_INT(rx.msg.view.error_code, WAMBLE_ERR_SPECTATE_FULL);

  spectator_manager_shutdown();
  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(server_protocol_reliable_spectate_focus_sends_terminal_before_ack) {
  const char *cfg_path = "build/test_network_spectate_focus_order.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(defprofile p1 ((def port 19424) (def advertise 1)))\n";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test'), "
          "(0, 'protocol.ctrl', 'spectate_game', '*', 'allow', 0, "
          "'spectate_game_access', 'test'), "
          "(0, 'protocol.ctrl', 'spectate_stop', '*', 'allow', 0, "
          "'spectate_stop_access', 'test'), "
          "(0, 'spectate.access', 'view', '*', 'allow', 0, "
          "'spectate_view_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  player_manager_init();
  board_manager_init();
  spectator_manager_init();

  WamblePlayer *player = create_new_player();
  T_ASSERT(player != NULL);
  WambleBoard *board = find_board_for_player(player);
  T_ASSERT(board != NULL);

  UdpLoopbackPair pair;
  T_ASSERT_STATUS_OK(init_udp_loopback_pair(&pair));

  HandleMessageCtx ctx = {0};
  ctx.sockfd = pair.srv;
  ctx.cliaddr = pair.cliaddr;
  ctx.trust_tier = 0;
  ctx.profile_name = "p1";
  ctx.msg.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  ctx.msg.header_version = WAMBLE_PROTO_VERSION;
  ctx.msg.seq_num = 401;
  ctx.msg.board_id = board->id;
  ctx.msg.token[0] = 0x81;

  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, handle_message_thread, &ctx) == 0);

  struct WambleMsg rx = {0};
  struct sockaddr_in from;
  T_ASSERT(recv_message_with_timeout(pair.cli, &rx, &from, 1000) > 0);
  T_ASSERT_EQ_INT(rx.ctrl, WAMBLE_CTRL_SPECTATE_UPDATE);
  T_ASSERT((rx.flags & WAMBLE_FLAG_UNRELIABLE) == 0);
  {
    const WambleMessageExtField *state = find_ext_field(&rx, "spectate.state");
    T_ASSERT(state != NULL);
    T_ASSERT_EQ_INT(state->value_type, WAMBLE_TREATMENT_VALUE_STRING);
    T_ASSERT(strcmp(state->string_value, "focus") == 0);
  }
  T_ASSERT_STATUS_OK(ack_terminal_and_expect_request_ack(pair.cli, &rx, &from,
                                                         ctx.msg.seq_num));

  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));
  T_ASSERT_EQ_INT(ctx.status, SERVER_OK);

  spectator_manager_shutdown();
  cleanup_udp_loopback_pair(&pair);
  return 0;
}

WAMBLE_TEST(
    server_protocol_reliable_spectate_denial_sends_terminal_before_ack) {
  const char *cfg_path = "build/test_network_spectate_denial_order.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(def max-spectators 0)\n"
                    "(defprofile p1 ((def port 19424) (def advertise 1)))\n";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test'), "
          "(0, 'protocol.ctrl', 'spectate_game', '*', 'allow', 0, "
          "'spectate_game_access', 'test'), "
          "(0, 'protocol.ctrl', 'spectate_stop', '*', 'allow', 0, "
          "'spectate_stop_access', 'test'), "
          "(0, 'spectate.access', 'view', '*', 'allow', 0, "
          "'spectate_view_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  player_manager_init();
  board_manager_init();
  spectator_manager_init();

  UdpLoopbackPair pair;
  T_ASSERT_STATUS_OK(init_udp_loopback_pair(&pair));

  HandleMessageCtx ctx = {0};
  ctx.sockfd = pair.srv;
  ctx.cliaddr = pair.cliaddr;
  ctx.trust_tier = 0;
  ctx.profile_name = "p1";
  ctx.msg.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  ctx.msg.header_version = WAMBLE_PROTO_VERSION;
  ctx.msg.seq_num = 402;
  ctx.msg.token[0] = 0x82;

  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, handle_message_thread, &ctx) == 0);

  struct WambleMsg rx = {0};
  struct sockaddr_in from;
  T_ASSERT(recv_message_with_timeout(pair.cli, &rx, &from, 1000) > 0);
  T_ASSERT_EQ_INT(rx.ctrl, WAMBLE_CTRL_ERROR);
  T_ASSERT_EQ_INT(rx.view.error_code, WAMBLE_ERR_SPECTATE_FULL);
  T_ASSERT_STATUS_OK(ack_terminal_and_expect_request_ack(pair.cli, &rx, &from,
                                                         ctx.msg.seq_num));

  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));
  T_ASSERT_EQ_INT(ctx.status, SERVER_ERR_SPECTATOR);

  spectator_manager_shutdown();
  cleanup_udp_loopback_pair(&pair);
  return 0;
}

WAMBLE_TEST(server_protocol_spectate_summary_returns_reliable_snapshot) {
  const char *cfg_path = "build/test_network_spectate_summary_snapshot.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(def spectator-summary-hz 0)\n"
                    "(defprofile p1 ((def port 19424) (def advertise 1)))\n"
                    "(defprofile p2 ((def port 19425) (def advertise 1)))\n";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test'), "
          "(0, 'protocol.ctrl', 'client_hello', '*', 'allow', 0, "
          "'hello_access', 'test'), "
          "(0, 'protocol.ctrl', 'spectate_game', '*', 'allow', 0, "
          "'spectate_game_access', 'test'), "
          "(0, 'protocol.ctrl', 'spectate_stop', '*', 'allow', 0, "
          "'spectate_stop_access', 'test'), "
          "(0, 'spectate.access', 'view', '*', 'allow', 0, "
          "'spectate_view_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  T_ASSERT_STATUS_OK(wamble_net_init());
  int started = 0;
  T_ASSERT_EQ_INT(start_profile_listeners(&started), PROFILE_START_OK);
  T_ASSERT_EQ_INT(started, 2);
  wamble_sleep_ms(50);

  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in dst;
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons(19424);

  struct WambleMsg hello = {0};
  hello.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  hello.header_version = WAMBLE_PROTO_VERSION;
  hello.flags = WAMBLE_FLAG_UNRELIABLE;
  hello.token[0] = 0x51;
  T_ASSERT_STATUS_OK(send_unreliable_packet(cli, &hello, &dst));

  struct WambleMsg rx = {0};
  struct sockaddr_in from;
  int board_id = 0;
  {
    fd_set rfds;
    struct timeval tv;
    FD_ZERO(&rfds);
    FD_SET(cli, &rfds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
#ifdef WAMBLE_PLATFORM_WINDOWS
    T_ASSERT(select(0, &rfds, NULL, NULL, &tv) > 0);
#else
    T_ASSERT(select(cli + 1, &rfds, NULL, NULL, &tv) > 0);
#endif
    T_ASSERT(receive_message(cli, &rx, &from) > 0);
    T_ASSERT_EQ_INT(rx.ctrl, WAMBLE_CTRL_SERVER_HELLO);
    board_id = (int)rx.board_id;
    send_ack(cli, &rx, &from);
  }
  T_ASSERT(board_id > 0);

  struct WambleMsg req = {0};
  req.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  req.header_version = WAMBLE_PROTO_VERSION;
  req.flags = WAMBLE_FLAG_UNRELIABLE;
  req.token[0] = 0x61;
  req.board_id = 0;
  T_ASSERT_STATUS_OK(send_unreliable_packet(cli, &req, &dst));

  int saw_state = 0;
  int saw_reset = 0;
  int quiet_polls = 0;
  while (quiet_polls < 3 && !(saw_state && saw_reset)) {
    fd_set rfds;
    struct timeval tv;
    FD_ZERO(&rfds);
    FD_SET(cli, &rfds);
    tv.tv_sec = 0;
    tv.tv_usec = 250 * 1000;
#ifdef WAMBLE_PLATFORM_WINDOWS
    int ready = select(0, &rfds, NULL, NULL, &tv);
#else
    int ready = select(cli + 1, &rfds, NULL, NULL, &tv);
#endif
    if (ready <= 0) {
      quiet_polls++;
      continue;
    }
    quiet_polls = 0;
    T_ASSERT(receive_message(cli, &rx, &from) > 0);
    T_ASSERT_EQ_INT(rx.ctrl, WAMBLE_CTRL_SPECTATE_UPDATE);
    T_ASSERT((rx.flags & WAMBLE_FLAG_UNRELIABLE) == 0);
    send_ack(cli, &rx, &from);
    const WambleMessageExtField *state = find_ext_field(&rx, "spectate.state");
    if (state && state->value_type == WAMBLE_TREATMENT_VALUE_STRING &&
        strcmp(state->string_value, "summary") == 0) {
      saw_state = 1;
    }
    if (wamble_msg_ext_find(&rx, "spectate.summary_generation") &&
        rx.board_id == 0 && rx.view.fen[0] == '\0') {
      saw_reset = 1;
    }
  }
  T_ASSERT(saw_state);
  T_ASSERT(saw_reset);

  stop_profile_listeners();
  wamble_net_cleanup();
  wamble_close_socket(cli);
  return 0;
}

WAMBLE_TEST(server_protocol_reliable_spectate_stop_sends_terminal_before_ack) {
  const char *cfg_path = "build/test_network_spectate_stop_order.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(defprofile p1 ((def port 19424) (def advertise 1)))\n";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test'), "
          "(0, 'protocol.ctrl', 'spectate_game', '*', 'allow', 0, "
          "'spectate_game_access', 'test'), "
          "(0, 'protocol.ctrl', 'spectate_stop', '*', 'allow', 0, "
          "'spectate_stop_access', 'test'), "
          "(0, 'spectate.access', 'view', '*', 'allow', 0, "
          "'spectate_view_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  player_manager_init();
  board_manager_init();
  spectator_manager_init();

  WamblePlayer *player = create_new_player();
  T_ASSERT(player != NULL);
  WambleBoard *board = find_board_for_player(player);
  T_ASSERT(board != NULL);

  UdpLoopbackPair pair;
  T_ASSERT_STATUS_OK(init_udp_loopback_pair(&pair));

  {
    struct WambleMsg focus = {0};
    SpectatorState state = SPECTATOR_STATE_IDLE;
    uint64_t focus_id = 0;
    focus.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
    focus.board_id = board->id;
    focus.token[0] = 0x83;
    T_ASSERT_EQ_INT(spectator_handle_request(&focus, &pair.cliaddr, 0, 0, 0,
                                             &state, &focus_id),
                    SPECTATOR_OK_FOCUS);
  }

  HandleMessageCtx ctx = {0};
  ctx.sockfd = pair.srv;
  ctx.cliaddr = pair.cliaddr;
  ctx.trust_tier = 0;
  ctx.profile_name = "p1";
  ctx.msg.ctrl = WAMBLE_CTRL_SPECTATE_STOP;
  ctx.msg.header_version = WAMBLE_PROTO_VERSION;
  ctx.msg.seq_num = 403;
  ctx.msg.token[0] = 0x83;

  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, handle_message_thread, &ctx) == 0);

  struct WambleMsg rx = {0};
  struct sockaddr_in from;
  T_ASSERT(recv_message_with_timeout(pair.cli, &rx, &from, 1000) > 0);
  T_ASSERT_EQ_INT(rx.ctrl, WAMBLE_CTRL_SPECTATE_UPDATE);
  T_ASSERT_EQ_INT((int)rx.board_id, 0);
  {
    const WambleMessageExtField *state = find_ext_field(&rx, "spectate.state");
    T_ASSERT(state != NULL);
    T_ASSERT_EQ_INT(state->value_type, WAMBLE_TREATMENT_VALUE_STRING);
    T_ASSERT(strcmp(state->string_value, "idle") == 0);
  }
  T_ASSERT_STATUS_OK(ack_terminal_and_expect_request_ack(pair.cli, &rx, &from,
                                                         ctx.msg.seq_num));

  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));
  T_ASSERT_EQ_INT(ctx.status, SERVER_OK);

  spectator_manager_shutdown();
  cleanup_udp_loopback_pair(&pair);
  return 0;
}

WAMBLE_TEST(server_protocol_spectate_stop_returns_reliable_idle_packet) {
  const char *cfg_path = "build/test_network_spectate_stop_packet.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(defprofile p1 ((def port 19424) (def advertise 1)))\n"
                    "(defprofile p2 ((def port 19425) (def advertise 1)))\n";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test'), "
          "(0, 'protocol.ctrl', 'client_hello', '*', 'allow', 0, "
          "'hello_access', 'test'), "
          "(0, 'protocol.ctrl', 'spectate_game', '*', 'allow', 0, "
          "'spectate_game_access', 'test'), "
          "(0, 'protocol.ctrl', 'spectate_stop', '*', 'allow', 0, "
          "'spectate_stop_access', 'test'), "
          "(0, 'spectate.access', 'view', '*', 'allow', 0, "
          "'spectate_view_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  T_ASSERT_STATUS_OK(wamble_net_init());
  int started = 0;
  T_ASSERT_EQ_INT(start_profile_listeners(&started), PROFILE_START_OK);
  T_ASSERT_EQ_INT(started, 2);
  wamble_sleep_ms(50);

  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in dst;
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons(19424);

  struct WambleMsg hello = {0};
  struct WambleMsg rx = {0};
  struct sockaddr_in from;
  hello.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  hello.header_version = WAMBLE_PROTO_VERSION;
  hello.flags = WAMBLE_FLAG_UNRELIABLE;
  hello.token[0] = 0x52;
  T_ASSERT_STATUS_OK(send_unreliable_packet(cli, &hello, &dst));

  {
    fd_set rfds;
    struct timeval tv;
    FD_ZERO(&rfds);
    FD_SET(cli, &rfds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
#ifdef WAMBLE_PLATFORM_WINDOWS
    T_ASSERT(select(0, &rfds, NULL, NULL, &tv) > 0);
#else
    T_ASSERT(select(cli + 1, &rfds, NULL, NULL, &tv) > 0);
#endif
    T_ASSERT(receive_message(cli, &rx, &from) > 0);
    T_ASSERT_EQ_INT(rx.ctrl, WAMBLE_CTRL_SERVER_HELLO);
    send_ack(cli, &rx, &from);
  }

  struct WambleMsg req = {0};
  req.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  req.header_version = WAMBLE_PROTO_VERSION;
  req.flags = WAMBLE_FLAG_UNRELIABLE;
  req.token[0] = 0x62;
  req.board_id = rx.board_id;
  T_ASSERT_STATUS_OK(send_unreliable_packet(cli, &req, &dst));

  {
    fd_set rfds;
    struct timeval tv;
    FD_ZERO(&rfds);
    FD_SET(cli, &rfds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
#ifdef WAMBLE_PLATFORM_WINDOWS
    T_ASSERT(select(0, &rfds, NULL, NULL, &tv) > 0);
#else
    T_ASSERT(select(cli + 1, &rfds, NULL, NULL, &tv) > 0);
#endif
    T_ASSERT(receive_message(cli, &rx, &from) > 0);
    T_ASSERT_EQ_INT(rx.ctrl, WAMBLE_CTRL_SPECTATE_UPDATE);
    send_ack(cli, &rx, &from);
  }

  struct WambleMsg stop = {0};
  stop.ctrl = WAMBLE_CTRL_SPECTATE_STOP;
  stop.header_version = WAMBLE_PROTO_VERSION;
  stop.flags = WAMBLE_FLAG_UNRELIABLE;
  stop.token[0] = 0x62;
  T_ASSERT_STATUS_OK(send_unreliable_packet(cli, &stop, &dst));

  {
    fd_set rfds;
    struct timeval tv;
    FD_ZERO(&rfds);
    FD_SET(cli, &rfds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
#ifdef WAMBLE_PLATFORM_WINDOWS
    T_ASSERT(select(0, &rfds, NULL, NULL, &tv) > 0);
#else
    T_ASSERT(select(cli + 1, &rfds, NULL, NULL, &tv) > 0);
#endif
    T_ASSERT(receive_message(cli, &rx, &from) > 0);
    T_ASSERT_EQ_INT(rx.ctrl, WAMBLE_CTRL_SPECTATE_UPDATE);
    T_ASSERT((rx.flags & WAMBLE_FLAG_UNRELIABLE) == 0);
    T_ASSERT_EQ_INT((int)rx.board_id, 0);
    send_ack(cli, &rx, &from);
  }
  {
    const WambleMessageExtField *state = find_ext_field(&rx, "spectate.state");
    T_ASSERT(state != NULL);
    T_ASSERT_EQ_INT(state->value_type, WAMBLE_TREATMENT_VALUE_STRING);
    T_ASSERT(strcmp(state->string_value, "idle") == 0);
  }

  stop_profile_listeners();
  wamble_net_cleanup();
  wamble_close_socket(cli);
  return 0;
}

WAMBLE_TEST(server_protocol_player_stats_scope_context_is_ignored) {
  const char *cfg_path = "build/test_network_player_stats_scope_policy.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(defprofile p1 ((def port 19424) (def advertise 1)))\n";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source, context_key, context_value) "
          "VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test', NULL, "
          "NULL), "
          "(0, 'protocol.ctrl', 'client_hello', '*', 'allow', 0, "
          "'hello_access', 'test', NULL, NULL), "
          "(0, 'protocol.ctrl', 'get_player_stats', '*', 'allow', 0, "
          "'stats_ctrl_access', 'test', NULL, NULL), "
          "(0, 'stats.read', 'player', '*', 'allow', 0, 'stats_self_access', "
          "'test', 'scope', 'self'), "
          "(0, 'stats.read', 'player', '*', 'deny', 0, 'stats_target_denied', "
          "'test', 'scope', 'target');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  player_manager_init();
  board_manager_init();

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  struct WambleMsg hello = {0};
  hello.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  hello.header_version = WAMBLE_PROTO_VERSION;
  RecvOneCtx rx_hello = {.sock = cli};
  wamble_thread_t th_hello;
  T_ASSERT(
      wamble_thread_create(&th_hello, recv_one_and_ack_thread, &rx_hello) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &hello, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_hello, NULL));
  T_ASSERT_EQ_INT(rx_hello.received, 1);
  T_ASSERT_EQ_INT(rx_hello.msg.ctrl, WAMBLE_CTRL_SERVER_HELLO);
  {
    const WambleMessageExtField *caps =
        find_ext_field(&rx_hello.msg, "session.caps");
    T_ASSERT(caps != NULL);
    T_ASSERT_EQ_INT(caps->value_type, WAMBLE_TREATMENT_VALUE_INT);
    T_ASSERT_EQ_INT((int)(caps->int_value & WAMBLE_SESSION_UI_CAP_STATS), 0);
  }

  uint64_t self_session_id = 0;
  T_ASSERT_EQ_INT(
      wamble_query_create_session(rx_hello.msg.token, 0, &self_session_id),
      DB_OK);
  T_ASSERT(self_session_id > 0);

  uint8_t target_token[TOKEN_LENGTH] = {0};
  target_token[0] = 0x91;
  target_token[1] = 0x33;
  uint64_t target_session_id = 0;
  T_ASSERT_EQ_INT(
      wamble_query_create_session(target_token, 0, &target_session_id), DB_OK);
  T_ASSERT(target_session_id > 0);
  T_ASSERT(target_session_id != self_session_id);

  {
    struct WambleMsg self_req = {0};
    self_req.ctrl = WAMBLE_CTRL_GET_PLAYER_STATS;
    self_req.header_version = WAMBLE_PROTO_VERSION;
    memcpy(self_req.token, rx_hello.msg.token, TOKEN_LENGTH);
    self_req.extensions.count = 1;
    snprintf(self_req.extensions.fields[0].key,
             sizeof(self_req.extensions.fields[0].key), "%s",
             "stats.request_id");
    self_req.extensions.fields[0].value_type = WAMBLE_TREATMENT_VALUE_INT;
    self_req.extensions.fields[0].int_value = 41;

    RecvOneCtx rx_self = {.sock = cli};
    wamble_thread_t th_self;
    T_ASSERT(
        wamble_thread_create(&th_self, recv_one_and_ack_thread, &rx_self) == 0);
    T_ASSERT_EQ_INT(handle_message(srv, &self_req, &cliaddr, 0, "p1"),
                    SERVER_ERR_FORBIDDEN);
    T_ASSERT_STATUS_OK(wamble_thread_join(th_self, NULL));
    T_ASSERT_EQ_INT(rx_self.received, 1);
    T_ASSERT_EQ_INT(rx_self.msg.ctrl, WAMBLE_CTRL_ERROR);
    T_ASSERT_EQ_INT(rx_self.msg.view.error_code, WAMBLE_ERR_ACCESS_DENIED);
    {
      const WambleMessageExtField *request_id =
          find_ext_field(&rx_self.msg, "stats.request_id");
      T_ASSERT(request_id != NULL);
      T_ASSERT_EQ_INT((int)request_id->int_value, 41);
    }
  }

  {
    struct WambleMsg target_req = {0};
    target_req.ctrl = WAMBLE_CTRL_GET_PLAYER_STATS;
    target_req.header_version = WAMBLE_PROTO_VERSION;
    memcpy(target_req.token, rx_hello.msg.token, TOKEN_LENGTH);
    target_req.extensions.count = 2;
    snprintf(target_req.extensions.fields[0].key,
             sizeof(target_req.extensions.fields[0].key), "%s",
             "stats.request_id");
    target_req.extensions.fields[0].value_type = WAMBLE_TREATMENT_VALUE_INT;
    target_req.extensions.fields[0].int_value = 42;
    snprintf(target_req.extensions.fields[1].key,
             sizeof(target_req.extensions.fields[1].key), "%s",
             "stats.target_session_id");
    target_req.extensions.fields[1].value_type = WAMBLE_TREATMENT_VALUE_INT;
    target_req.extensions.fields[1].int_value = (int64_t)target_session_id;

    RecvOneCtx rx_target = {.sock = cli};
    wamble_thread_t th_target;
    T_ASSERT(wamble_thread_create(&th_target, recv_one_and_ack_thread,
                                  &rx_target) == 0);
    T_ASSERT_EQ_INT(handle_message(srv, &target_req, &cliaddr, 0, "p1"),
                    SERVER_ERR_FORBIDDEN);
    T_ASSERT_STATUS_OK(wamble_thread_join(th_target, NULL));
    T_ASSERT_EQ_INT(rx_target.received, 1);
    T_ASSERT_EQ_INT(rx_target.msg.ctrl, WAMBLE_CTRL_ERROR);
    T_ASSERT_EQ_INT(rx_target.msg.view.error_code, WAMBLE_ERR_ACCESS_DENIED);
    {
      const WambleMessageExtField *request_id =
          find_ext_field(&rx_target.msg, "stats.request_id");
      T_ASSERT(request_id != NULL);
      T_ASSERT_EQ_INT((int)request_id->int_value, 42);
    }
  }

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(server_protocol_player_stats_self_read_does_not_create_session) {
  const char *cfg_path = "build/test_network_player_stats_no_create.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(defprofile p1 ((def port 19424) (def advertise 1)))\n";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source, context_key, context_value) "
          "VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test', NULL, "
          "NULL), "
          "(0, 'protocol.ctrl', 'client_hello', '*', 'allow', 0, "
          "'hello_access', 'test', NULL, NULL), "
          "(0, 'protocol.ctrl', 'get_player_stats', '*', 'allow', 0, "
          "'stats_ctrl_access', 'test', NULL, NULL), "
          "(0, 'stats.read', 'player', '*', 'allow', 0, 'stats_access', "
          "'test', NULL, NULL);") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  player_manager_init();
  board_manager_init();

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  struct WambleMsg hello = {0};
  hello.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  hello.header_version = WAMBLE_PROTO_VERSION;
  RecvOneCtx rx_hello = {.sock = cli};
  wamble_thread_t th_hello;
  T_ASSERT(
      wamble_thread_create(&th_hello, recv_one_and_ack_thread, &rx_hello) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &hello, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_hello, NULL));
  T_ASSERT_EQ_INT(rx_hello.received, 1);
  T_ASSERT_EQ_INT(rx_hello.msg.ctrl, WAMBLE_CTRL_SERVER_HELLO);

  {
    uint64_t sid = 0;
    T_ASSERT_EQ_INT(wamble_query_get_session_by_token(rx_hello.msg.token, &sid),
                    DB_NOT_FOUND);
  }

  {
    struct WambleMsg req = {0};
    req.ctrl = WAMBLE_CTRL_GET_PLAYER_STATS;
    req.header_version = WAMBLE_PROTO_VERSION;
    memcpy(req.token, rx_hello.msg.token, TOKEN_LENGTH);

    RecvOneCtx rx_stats = {.sock = cli};
    wamble_thread_t th_stats;
    T_ASSERT(wamble_thread_create(&th_stats, recv_one_and_ack_thread,
                                  &rx_stats) == 0);
    T_ASSERT_EQ_INT(handle_message(srv, &req, &cliaddr, 0, "p1"), SERVER_OK);
    T_ASSERT_STATUS_OK(wamble_thread_join(th_stats, NULL));
    T_ASSERT_EQ_INT(rx_stats.received, 1);
    T_ASSERT_EQ_INT(rx_stats.msg.ctrl, WAMBLE_CTRL_PLAYER_STATS_DATA);
  }

  {
    uint64_t sid = 0;
    T_ASSERT_EQ_INT(wamble_query_get_session_by_token(rx_hello.msg.token, &sid),
                    DB_NOT_FOUND);
  }

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(server_protocol_error_blocking_ext_marks_fatal_session_only) {
  const char *cfg_path = "build/test_network_error_blocking_ext.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(defprofile p1 ((def port 19424) (def advertise 1)))\n";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test'), "
          "(0, 'protocol.ctrl', 'client_hello', '*', 'allow', 0, "
          "'hello_access', 'test'), "
          "(0, 'protocol.ctrl', 'get_player_stats', '*', 'allow', 0, "
          "'stats_ctrl_access', 'test'), "
          "(0, 'protocol.ctrl', 'get_leaderboard', '*', 'allow', 0, "
          "'leaderboard_ctrl_access', 'test'), "
          "(0, 'stats.read', 'player', '*', 'allow', 0, 'stats_access', "
          "'test'), "
          "(0, 'leaderboard.read', 'global', '*', 'allow', 0, "
          "'leaderboard_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  player_manager_init();
  board_manager_init();

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  struct WambleMsg hello = {0};
  hello.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  hello.header_version = WAMBLE_PROTO_VERSION;

  RecvOneCtx rx_hello = {.sock = cli};
  wamble_thread_t th_hello;
  T_ASSERT(
      wamble_thread_create(&th_hello, recv_one_and_ack_thread, &rx_hello) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &hello, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_hello, NULL));
  T_ASSERT_EQ_INT(rx_hello.received, 1);
  T_ASSERT_EQ_INT(rx_hello.msg.ctrl, WAMBLE_CTRL_SERVER_HELLO);

  {
    struct WambleMsg req = {0};
    req.ctrl = WAMBLE_CTRL_GET_LEADERBOARD;
    req.header_version = WAMBLE_PROTO_VERSION;
    memcpy(req.token, rx_hello.msg.token, TOKEN_LENGTH);

    RecvOneCtx rx = {.sock = cli};
    wamble_thread_t th;
    T_ASSERT(wamble_thread_create(&th, recv_one_and_ack_thread, &rx) == 0);
    T_ASSERT_EQ_INT(handle_message(srv, &req, &cliaddr, 0, "p1"),
                    SERVER_ERR_INTERNAL);
    T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));
    T_ASSERT_EQ_INT(rx.received, 1);
    T_ASSERT_EQ_INT(rx.msg.ctrl, WAMBLE_CTRL_ERROR);
    T_ASSERT_EQ_INT(rx.msg.view.error_code, WAMBLE_ERR_UNKNOWN_PLAYER);
    {
      const WambleMessageExtField *blocking =
          find_ext_field(&rx.msg, "error.blocking");
      T_ASSERT(blocking != NULL);
      T_ASSERT_EQ_INT((int)blocking->int_value, 1);
    }
  }

  {
    struct WambleMsg req = {0};
    req.ctrl = WAMBLE_CTRL_GET_PLAYER_STATS;
    req.header_version = WAMBLE_PROTO_VERSION;
    memcpy(req.token, rx_hello.msg.token, TOKEN_LENGTH);
    req.extensions.count = 2;
    snprintf(req.extensions.fields[0].key, sizeof(req.extensions.fields[0].key),
             "%s", "stats.request_id");
    req.extensions.fields[0].value_type = WAMBLE_TREATMENT_VALUE_INT;
    req.extensions.fields[0].int_value = 88;
    snprintf(req.extensions.fields[1].key, sizeof(req.extensions.fields[1].key),
             "%s", "stats.target_handle");
    req.extensions.fields[1].value_type = WAMBLE_TREATMENT_VALUE_STRING;
    snprintf(req.extensions.fields[1].string_value,
             sizeof(req.extensions.fields[1].string_value), "%s",
             "h_missing999");

    RecvOneCtx rx = {.sock = cli};
    wamble_thread_t th;
    T_ASSERT(wamble_thread_create(&th, recv_one_and_ack_thread, &rx) == 0);
    T_ASSERT_EQ_INT(handle_message(srv, &req, &cliaddr, 0, "p1"),
                    SERVER_ERR_INTERNAL);
    T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));
    T_ASSERT_EQ_INT(rx.received, 1);
    T_ASSERT_EQ_INT(rx.msg.ctrl, WAMBLE_CTRL_ERROR);
    T_ASSERT_EQ_INT(rx.msg.view.error_code, WAMBLE_ERR_UNKNOWN_PLAYER);
    {
      const WambleMessageExtField *request_id =
          find_ext_field(&rx.msg, "stats.request_id");
      const WambleMessageExtField *blocking =
          find_ext_field(&rx.msg, "error.blocking");
      T_ASSERT(request_id != NULL);
      T_ASSERT_EQ_INT((int)request_id->int_value, 88);
      T_ASSERT(blocking == NULL);
    }
  }

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(server_protocol_player_stats_caps_follow_contextual_policy) {
  const char *cfg_path = "build/test_network_player_stats_context_caps.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(defprofile p1 ((def port 19424) (def advertise 1)))\n";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source, context_key, context_value) "
          "VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test', NULL, "
          "NULL), "
          "(0, 'protocol.ctrl', 'client_hello', '*', 'allow', 0, "
          "'hello_access', 'test', NULL, NULL), "
          "(0, 'protocol.ctrl', 'get_player_stats', '*', 'allow', 0, "
          "'stats_ctrl_access', 'test', NULL, NULL), "
          "(0, 'stats.read', 'player', '*', 'allow', 0, "
          "'stats_allow', 'test', NULL, NULL);") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  player_manager_init();
  board_manager_init();

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  struct WambleMsg hello = {0};
  hello.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  hello.header_version = WAMBLE_PROTO_VERSION;
  RecvOneCtx rx_hello = {.sock = cli};
  wamble_thread_t th_hello;
  T_ASSERT(
      wamble_thread_create(&th_hello, recv_one_and_ack_thread, &rx_hello) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &hello, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_hello, NULL));
  T_ASSERT_EQ_INT(rx_hello.received, 1);
  T_ASSERT_EQ_INT(rx_hello.msg.ctrl, WAMBLE_CTRL_SERVER_HELLO);
  {
    const WambleMessageExtField *caps =
        find_ext_field(&rx_hello.msg, "session.caps");
    T_ASSERT(caps != NULL);
    T_ASSERT_EQ_INT(caps->value_type, WAMBLE_TREATMENT_VALUE_INT);
    T_ASSERT((caps->int_value & WAMBLE_SESSION_UI_CAP_STATS) != 0);
  }

  {
    struct WambleMsg req = {0};
    req.ctrl = WAMBLE_CTRL_GET_PLAYER_STATS;
    req.header_version = WAMBLE_PROTO_VERSION;
    memcpy(req.token, rx_hello.msg.token, TOKEN_LENGTH);

    RecvOneCtx rx_stats = {.sock = cli};
    wamble_thread_t th_stats;
    T_ASSERT(wamble_thread_create(&th_stats, recv_one_and_ack_thread,
                                  &rx_stats) == 0);
    T_ASSERT_EQ_INT(handle_message(srv, &req, &cliaddr, 0, "p1"), SERVER_OK);
    T_ASSERT_STATUS_OK(wamble_thread_join(th_stats, NULL));
    T_ASSERT_EQ_INT(rx_stats.received, 1);
    T_ASSERT_EQ_INT(rx_stats.msg.ctrl, WAMBLE_CTRL_PLAYER_STATS_DATA);
  }

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(server_protocol_logout_allowed_before_profile_terms_acceptance) {
  const char *cfg_path = "build/test_network_profile_terms_logout_allowed.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(defprofile p1 ((def port 19424) (def advertise 1) "
                    "(def tos-text \"profile terms v1\")))\n";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test'), "
          "(0, 'protocol.ctrl', 'client_hello', '*', 'allow', 0, "
          "'hello_access', 'test'), "
          "(0, 'protocol.ctrl', 'logout', '*', 'allow', 0, "
          "'logout_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  player_manager_init();
  board_manager_init();

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  struct WambleMsg hello = {0};
  hello.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  hello.header_version = WAMBLE_PROTO_VERSION;

  RecvOneCtx rx_hello = {.sock = cli};
  wamble_thread_t th_hello;
  T_ASSERT(
      wamble_thread_create(&th_hello, recv_one_and_ack_thread, &rx_hello) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &hello, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_hello, NULL));
  T_ASSERT_EQ_INT(rx_hello.received, 1);
  T_ASSERT_EQ_INT(rx_hello.msg.ctrl, WAMBLE_CTRL_SERVER_HELLO);

  struct WambleMsg logout = {0};
  logout.ctrl = WAMBLE_CTRL_LOGOUT;
  logout.header_version = WAMBLE_PROTO_VERSION;
  memcpy(logout.token, rx_hello.msg.token, TOKEN_LENGTH);

  RecvOneCtx rx_ack = {.sock = cli};
  wamble_thread_t th_ack;
  T_ASSERT(wamble_thread_create(&th_ack, recv_one_thread, &rx_ack) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &logout, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_ack, NULL));
  T_ASSERT_EQ_INT(rx_ack.received, 1);
  T_ASSERT_EQ_INT(rx_ack.msg.ctrl, WAMBLE_CTRL_ACK);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(server_protocol_player_stats_target_handle_with_tag_policy) {
  const char *cfg_path = "build/test_network_player_stats_identity_target.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(defprofile p1 ((def port 19424) (def advertise 1)))\n";
  uint8_t target_token_newer[TOKEN_LENGTH] = {
      0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
      0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0x10};
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_identities (public_key) VALUES "
          "(decode('11223344556677889900aabbccddeeff00112233445566778899aabbcc"
          "ddeeff', 'hex')) ON CONFLICT (public_key) DO NOTHING;"
          "INSERT INTO players (public_key, rating) VALUES "
          "(decode('11223344556677889900aabbccddeeff00112233445566778899aabbcc"
          "ddeeff', 'hex'), 1000) ON CONFLICT (public_key) DO NOTHING;"
          "INSERT INTO sessions (token, player_id, global_identity_id, "
          "total_score, games_played) VALUES "
          "(decode('a1a2a3a4a5a6a7a8a9aaabacadaeaf10', 'hex'), "
          "(SELECT id FROM players WHERE public_key = "
          "decode('112233445566778899"
          "00aabbccddeeff00112233445566778899aabbccddeeff', 'hex')), "
          "(SELECT id FROM global_identities WHERE public_key = "
          "decode('11223344"
          "556677889900aabbccddeeff00112233445566778899aabbccddeeff', "
          "'hex')), "
          "7.0, 3) ON CONFLICT DO NOTHING;"
          "INSERT INTO sessions (token, player_id, global_identity_id, "
          "total_score, games_played) VALUES "
          "(decode('b1b2b3b4b5b6b7b8b9babbbcbdbebf10', 'hex'), "
          "(SELECT id FROM players WHERE public_key = "
          "decode('112233445566778899"
          "00aabbccddeeff00112233445566778899aabbccddeeff', 'hex')), "
          "(SELECT id FROM global_identities WHERE public_key = "
          "decode('11223344"
          "556677889900aabbccddeeff00112233445566778899aabbccddeeff', "
          "'hex')), "
          "4.0, 2) ON CONFLICT DO NOTHING;"
          "INSERT INTO boards (id, fen, status) VALUES "
          "(9001, '8/8/8/8/8/8/8/8 w - - 0 1', 'ARCHIVED') "
          "ON CONFLICT DO NOTHING;"
          "INSERT INTO boards (id, fen, status) VALUES "
          "(9002, '8/8/8/8/8/8/8/8 w - - 0 1', 'ARCHIVED') "
          "ON CONFLICT DO NOTHING;"
          "INSERT INTO board_mode_variants (board_id, game_mode, "
          "mode_variant_id) VALUES "
          "(9001, 'chess960', 17), (9002, 'chess960', 24) "
          "ON CONFLICT DO NOTHING;"
          "INSERT INTO moves (board_id, session_id, move_uci, move_number) "
          "VALUES "
          "(9001, (SELECT id FROM sessions WHERE token = "
          "decode('a1a2a3a4a5a6a7a8a9aaabacadaeaf10', 'hex')), 'e2e4', 1), "
          "(9002, (SELECT id FROM sessions WHERE token = "
          "decode('b1b2b3b4b5b6b7b8b9babbbcbdbebf10', 'hex')), 'd2d4', 1) "
          "ON CONFLICT DO NOTHING;"
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source, context_key, context_value) "
          "VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test', NULL, "
          "NULL), "
          "(0, 'protocol.ctrl', 'client_hello', '*', 'allow', 0, "
          "'hello_access', 'test', NULL, NULL), "
          "(0, 'protocol.ctrl', 'get_player_stats', '*', 'allow', 0, "
          "'stats_ctrl_access', 'test', NULL, NULL), "
          "(0, 'stats.read', 'player', '*', 'deny', 0, "
          "'stats_no_tag_denied', 'test', 'target.identity_tag', 'none'), "
          "(0, 'stats.read', 'player', '*', 'allow', 0, "
          "'stats_vip_allowed', 'test', 'target.identity_tag', 'vip');"
          "INSERT INTO global_identity_tags (global_identity_id, tag) VALUES "
          "((SELECT global_identity_id FROM sessions WHERE token = "
          "decode('a1a2a3a4a5a6a7a8a9aaabacadaeaf10', 'hex')), 'vip') "
          "ON CONFLICT DO NOTHING;") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  player_manager_init();
  board_manager_init();

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  struct WambleMsg hello = {0};
  hello.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  hello.header_version = WAMBLE_PROTO_VERSION;
  RecvOneCtx rx_hello = {.sock = cli};
  wamble_thread_t th_hello;
  T_ASSERT(
      wamble_thread_create(&th_hello, recv_one_and_ack_thread, &rx_hello) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &hello, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_hello, NULL));
  T_ASSERT_EQ_INT(rx_hello.received, 1);
  T_ASSERT_EQ_INT(rx_hello.msg.ctrl, WAMBLE_CTRL_SERVER_HELLO);

  {
    struct WambleMsg self_req = {0};
    self_req.ctrl = WAMBLE_CTRL_GET_PLAYER_STATS;
    self_req.header_version = WAMBLE_PROTO_VERSION;
    memcpy(self_req.token, rx_hello.msg.token, TOKEN_LENGTH);

    RecvOneCtx rx_self = {.sock = cli};
    wamble_thread_t th_self;
    T_ASSERT(
        wamble_thread_create(&th_self, recv_one_and_ack_thread, &rx_self) == 0);
    T_ASSERT_EQ_INT(handle_message(srv, &self_req, &cliaddr, 0, "p1"),
                    SERVER_ERR_FORBIDDEN);
    T_ASSERT_STATUS_OK(wamble_thread_join(th_self, NULL));
    T_ASSERT_EQ_INT(rx_self.received, 1);
    T_ASSERT_EQ_INT(rx_self.msg.ctrl, WAMBLE_CTRL_ERROR);
    T_ASSERT_EQ_INT(rx_self.msg.view.error_code, WAMBLE_ERR_ACCESS_DENIED);
  }

  {
    struct WambleMsg req_pub = {0};
    req_pub.ctrl = WAMBLE_CTRL_GET_PLAYER_STATS;
    req_pub.header_version = WAMBLE_PROTO_VERSION;
    memcpy(req_pub.token, rx_hello.msg.token, TOKEN_LENGTH);
    req_pub.extensions.count = 1;
    snprintf(req_pub.extensions.fields[0].key,
             sizeof(req_pub.extensions.fields[0].key), "%s",
             "stats.target_public_key");
    req_pub.extensions.fields[0].value_type = WAMBLE_TREATMENT_VALUE_STRING;
    snprintf(
        req_pub.extensions.fields[0].string_value,
        sizeof(req_pub.extensions.fields[0].string_value), "%s",
        "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff");

    RecvOneCtx rx_pub = {.sock = cli};
    wamble_thread_t th_pub;
    T_ASSERT(wamble_thread_create(&th_pub, recv_one_and_ack_thread, &rx_pub) ==
             0);
    T_ASSERT_EQ_INT(handle_message(srv, &req_pub, &cliaddr, 0, "p1"),
                    SERVER_ERR_FORBIDDEN);
    T_ASSERT_STATUS_OK(wamble_thread_join(th_pub, NULL));
    T_ASSERT_EQ_INT(rx_pub.received, 1);
    T_ASSERT_EQ_INT(rx_pub.msg.ctrl, WAMBLE_CTRL_ERROR);
    T_ASSERT_EQ_INT(rx_pub.msg.view.error_code, WAMBLE_ERR_ACCESS_DENIED);
  }

  {
    uint8_t target_token_older[TOKEN_LENGTH] = {
        0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
        0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0x10};
    uint64_t target_session_older = 0;
    uint64_t target_identity_id = 0;
    char target_handle[WAMBLE_MESSAGE_EXT_STRING_MAX] = {0};
    T_ASSERT_EQ_INT(wamble_query_get_session_by_token(target_token_older,
                                                      &target_session_older),
                    DB_OK);
    T_ASSERT(target_session_older > 0);
    T_ASSERT_EQ_INT(wamble_query_get_session_global_identity_id(
                        target_session_older, &target_identity_id),
                    DB_OK);
    T_ASSERT(target_identity_id > 0);
    T_ASSERT_EQ_INT(wamble_query_get_identity_handle(target_identity_id,
                                                     target_handle,
                                                     sizeof(target_handle)),
                    DB_OK);
    T_ASSERT(target_handle[0] != '\0');
    struct WambleMsg req = {0};
    req.ctrl = WAMBLE_CTRL_GET_PLAYER_STATS;
    req.header_version = WAMBLE_PROTO_VERSION;
    memcpy(req.token, rx_hello.msg.token, TOKEN_LENGTH);
    req.extensions.count = 2;
    snprintf(req.extensions.fields[0].key, sizeof(req.extensions.fields[0].key),
             "%s", "stats.request_id");
    req.extensions.fields[0].value_type = WAMBLE_TREATMENT_VALUE_INT;
    req.extensions.fields[0].int_value = 77;
    snprintf(req.extensions.fields[1].key, sizeof(req.extensions.fields[1].key),
             "%s", "stats.target_handle");
    req.extensions.fields[1].value_type = WAMBLE_TREATMENT_VALUE_STRING;
    snprintf(req.extensions.fields[1].string_value,
             sizeof(req.extensions.fields[1].string_value), "%s",
             target_handle);

    RecvOneCtx rx = {.sock = cli};
    wamble_thread_t th;
    T_ASSERT(wamble_thread_create(&th, recv_one_and_ack_thread, &rx) == 0);
    T_ASSERT_EQ_INT(handle_message(srv, &req, &cliaddr, 0, "p1"), SERVER_OK);
    T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));
    T_ASSERT_EQ_INT(rx.received, 1);
    T_ASSERT_EQ_INT(rx.msg.ctrl, WAMBLE_CTRL_PLAYER_STATS_DATA);
    {
      double expected_score = 0.0;
      int expected_games = 0;
      int expected_960_games = 0;
      T_ASSERT_EQ_INT(wamble_query_get_identity_total_score(target_identity_id,
                                                            &expected_score),
                      DB_OK);
      T_ASSERT_EQ_INT(wamble_query_get_identity_games_played(target_identity_id,
                                                             &expected_games),
                      DB_OK);
      T_ASSERT_EQ_INT(wamble_query_get_identity_chess960_games_played(
                          target_identity_id, &expected_960_games),
                      DB_OK);
      T_ASSERT(fabs(rx.msg.stats.player_stats.score - expected_score) < 1e-9);
      T_ASSERT_EQ_INT((int)rx.msg.stats.player_stats.games_played,
                      expected_games);
      T_ASSERT_EQ_INT((int)rx.msg.stats.player_stats.chess960_games_played,
                      expected_960_games);
    }
    {
      const WambleMessageExtField *request_id =
          find_ext_field(&rx.msg, "stats.request_id");
      T_ASSERT(request_id != NULL);
      T_ASSERT_EQ_INT((int)request_id->int_value, 77);
    }
    {
      uint64_t target_session_id = 0;
      T_ASSERT_EQ_INT(wamble_query_get_session_by_token(target_token_newer,
                                                        &target_session_id),
                      DB_OK);
      T_ASSERT(target_session_id > 0);
      const WambleMessageExtField *sid =
          find_ext_field(&rx.msg, "stats.target_session_id");
      T_ASSERT(sid != NULL);
      T_ASSERT_EQ_INT((uint64_t)sid->int_value, target_session_id);
    }
    {
      const WambleMessageExtField *has_id =
          find_ext_field(&rx.msg, "stats.target_has_identity");
      T_ASSERT(has_id != NULL);
      T_ASSERT_EQ_INT((int)has_id->int_value, 1);
    }
    {
      const WambleMessageExtField *handle =
          find_ext_field(&rx.msg, "stats.target_handle");
      T_ASSERT(handle != NULL);
      T_ASSERT_EQ_INT(handle->value_type, WAMBLE_TREATMENT_VALUE_STRING);
      T_ASSERT(strcmp(handle->string_value, target_handle) == 0);
    }
  }

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(server_protocol_get_active_reservations_identity_query) {
  const char *cfg_path =
      "build/test_network_get_active_reservations_identity.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(defprofile p1 ((def port 19424) (def advertise 1)))\n";
  const uint8_t target_pub[WAMBLE_PUBLIC_KEY_LENGTH] = {
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xaa,
      0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
      0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_identities (public_key) VALUES "
          "(decode('11223344556677889900aabbccddeeff00112233445566778899aabbcc"
          "ddeeff', 'hex')) ON CONFLICT (public_key) DO NOTHING;"
          "INSERT INTO players (public_key, rating) VALUES "
          "(decode('11223344556677889900aabbccddeeff00112233445566778899aabbcc"
          "ddeeff', 'hex'), 1000) ON CONFLICT (public_key) DO NOTHING;"
          "INSERT INTO sessions (token, player_id, global_identity_id) VALUES "
          "(decode('c1c2c3c4c5c6c7c8c9cacbcccdcecfd0', 'hex'), "
          "(SELECT id FROM players WHERE public_key = "
          "decode('11223344556677889900aabbccddeeff00112233445566778899aabbcc"
          "ddeeff', 'hex')), "
          "(SELECT id FROM global_identities WHERE public_key = "
          "decode('11223344556677889900aabbccddeeff00112233445566778899aabbcc"
          "ddeeff', 'hex'))) ON CONFLICT DO NOTHING;"
          "INSERT INTO boards (id, fen, status, reservation_started_at, "
          "reserved_for_white) VALUES "
          "(777, '8/8/8/8/8/8/8/8 w - - 0 1', 'RESERVED', "
          "NOW() - INTERVAL '30 seconds', TRUE) ON CONFLICT DO NOTHING;"
          "INSERT INTO reservations (board_id, session_id, expires_at, "
          "started_at,"
          " reserved_for_white) VALUES "
          "(777, (SELECT id FROM sessions WHERE token = "
          "decode('c1c2c3c4c5c6c7c8c9cacbcccdcecfd0', 'hex')), "
          "NOW() + INTERVAL '120 seconds', NOW() - INTERVAL '30 seconds', "
          "TRUE) "
          "ON CONFLICT (board_id) DO UPDATE SET "
          "session_id = EXCLUDED.session_id, "
          "expires_at = EXCLUDED.expires_at, "
          "started_at = EXCLUDED.started_at, "
          "reserved_for_white = EXCLUDED.reserved_for_white;"
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test'), "
          "(0, 'protocol.ctrl', 'client_hello', '*', 'allow', 0, "
          "'hello_access', 'test'), "
          "(0, 'protocol.ctrl', 'get_active_reservations', '*', 'allow', 0, "
          "'reservations_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  player_manager_init();
  board_manager_init();

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  struct WambleMsg hello = {0};
  hello.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  hello.header_version = WAMBLE_PROTO_VERSION;
  RecvOneCtx rx_hello = {.sock = cli};
  wamble_thread_t th_hello;
  T_ASSERT(
      wamble_thread_create(&th_hello, recv_one_and_ack_thread, &rx_hello) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &hello, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_hello, NULL));
  T_ASSERT_EQ_INT(rx_hello.received, 1);
  T_ASSERT_EQ_INT(rx_hello.msg.ctrl, WAMBLE_CTRL_SERVER_HELLO);

  T_ASSERT(attach_persistent_identity(rx_hello.msg.token, target_pub) != NULL);

  struct WambleMsg req = {0};
  req.ctrl = WAMBLE_CTRL_GET_ACTIVE_RESERVATIONS;
  req.header_version = WAMBLE_PROTO_VERSION;
  memcpy(req.token, rx_hello.msg.token, TOKEN_LENGTH);

  RecvOneCtx rx = {.sock = cli};
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, recv_one_and_ack_thread, &rx) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &req, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));
  T_ASSERT_EQ_INT(rx.received, 1);
  T_ASSERT_EQ_INT(rx.msg.ctrl, WAMBLE_CTRL_ACTIVE_RESERVATIONS_DATA);
  T_ASSERT(rx.msg.fragment.fragment_data_len >= 30);
  {
    uint16_t count_be = 0;
    uint64_t board_be = 0;
    uint64_t expires_be = 0;
    uint64_t live_board_be = 0;
    uint64_t live_expires_be = 0;
    uint8_t available = 0;
    uint8_t profile_len = 0;
    uint8_t live_available = 0;
    uint8_t live_profile_len = 0;
    memcpy(&count_be, rx.msg.fragment.fragment_data, 2);
    memcpy(&board_be, rx.msg.fragment.fragment_data + 2, 8);
    memcpy(&expires_be, rx.msg.fragment.fragment_data + 18, 8);
    available = rx.msg.fragment.fragment_data[26];
    profile_len = rx.msg.fragment.fragment_data[27];
    memcpy(&live_board_be, rx.msg.fragment.fragment_data + 28, 8);
    memcpy(&live_expires_be, rx.msg.fragment.fragment_data + 44, 8);
    live_available = rx.msg.fragment.fragment_data[52];
    live_profile_len = rx.msg.fragment.fragment_data[53];
    T_ASSERT_EQ_INT((int)ntohs(count_be), 2);
    T_ASSERT_EQ_INT((int)wamble_net_to_host64(board_be), 777);
    T_ASSERT(wamble_net_to_host64(expires_be) > 0);
    T_ASSERT_EQ_INT((int)available, 0);
    T_ASSERT_EQ_INT((int)profile_len, 0);
    T_ASSERT_EQ_INT((int)wamble_net_to_host64(live_board_be),
                    (int)rx_hello.msg.board_id);
    T_ASSERT(wamble_net_to_host64(live_expires_be) > 0);
    T_ASSERT_EQ_INT((int)live_available, 1);
    T_ASSERT_EQ_INT((int)live_profile_len, 2);
    T_ASSERT(memcmp(rx.msg.fragment.fragment_data + 54, "p1", 2) == 0);
  }
  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(
    server_protocol_get_active_reservations_includes_live_attached_board) {
  const char *cfg_path =
      "build/test_network_get_active_reservations_live_attach.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(def reservation-timeout 120)\n"
                    "(defprofile p1 ((def port 19426) (def advertise 1)))\n";
  const uint8_t target_pub[WAMBLE_PUBLIC_KEY_LENGTH] = {
      0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
      0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
      0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40};
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test'), "
          "(0, 'protocol.ctrl', 'client_hello', '*', 'allow', 0, "
          "'hello_access', 'test'), "
          "(0, 'protocol.ctrl', 'get_active_reservations', '*', 'allow', 0, "
          "'reservations_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  player_manager_init();
  board_manager_init();

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  struct WambleMsg hello = {0};
  hello.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  hello.header_version = WAMBLE_PROTO_VERSION;
  RecvOneCtx rx_hello = {.sock = cli};
  wamble_thread_t th_hello;
  T_ASSERT(
      wamble_thread_create(&th_hello, recv_one_and_ack_thread, &rx_hello) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &hello, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_hello, NULL));
  T_ASSERT_EQ_INT(rx_hello.received, 1);
  T_ASSERT_EQ_INT(rx_hello.msg.ctrl, WAMBLE_CTRL_SERVER_HELLO);
  T_ASSERT(
      board_is_reserved_for_player(rx_hello.msg.board_id, rx_hello.msg.token));

  T_ASSERT(attach_persistent_identity(rx_hello.msg.token, target_pub) != NULL);

  struct WambleMsg req = {0};
  req.ctrl = WAMBLE_CTRL_GET_ACTIVE_RESERVATIONS;
  req.header_version = WAMBLE_PROTO_VERSION;
  memcpy(req.token, rx_hello.msg.token, TOKEN_LENGTH);

  RecvOneCtx rx = {.sock = cli};
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, recv_one_and_ack_thread, &rx) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &req, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));
  T_ASSERT_EQ_INT(rx.received, 1);
  T_ASSERT_EQ_INT(rx.msg.ctrl, WAMBLE_CTRL_ACTIVE_RESERVATIONS_DATA);
  T_ASSERT(rx.msg.fragment.fragment_data_len >= 30);
  {
    uint16_t count_be = 0;
    uint64_t board_be = 0;
    uint64_t expires_be = 0;
    uint8_t available = 0;
    uint8_t profile_len = 0;
    memcpy(&count_be, rx.msg.fragment.fragment_data, 2);
    memcpy(&board_be, rx.msg.fragment.fragment_data + 2, 8);
    memcpy(&expires_be, rx.msg.fragment.fragment_data + 18, 8);
    available = rx.msg.fragment.fragment_data[26];
    profile_len = rx.msg.fragment.fragment_data[27];
    T_ASSERT_EQ_INT((int)ntohs(count_be), 1);
    T_ASSERT_EQ_INT((int)wamble_net_to_host64(board_be), rx_hello.msg.board_id);
    T_ASSERT(wamble_net_to_host64(expires_be) > 0);
    T_ASSERT_EQ_INT((int)available, 1);
    T_ASSERT_EQ_INT((int)profile_len, 2);
    T_ASSERT(memcmp(rx.msg.fragment.fragment_data + 28, "p1", 2) == 0);
  }

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(server_protocol_get_active_reservations_caps_payload_count) {
  const char *cfg_path =
      "build/test_network_get_active_reservations_caps_count.conf";
  const uint8_t target_pub[WAMBLE_PUBLIC_KEY_LENGTH] = {
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xaa,
      0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
      0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(defprofile p1 ((def port 19425) (def advertise 1)))\n";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_identities (public_key) VALUES "
          "(decode('11223344556677889900aabbccddeeff00112233445566778899aabbcc"
          "ddeeff', 'hex')) ON CONFLICT (public_key) DO NOTHING;"
          "INSERT INTO players (public_key, rating) VALUES "
          "(decode('11223344556677889900aabbccddeeff00112233445566778899aabbcc"
          "ddeeff', 'hex'), 1000) ON CONFLICT (public_key) DO NOTHING;"
          "INSERT INTO sessions (token, player_id, global_identity_id) VALUES "
          "(decode('c1c2c3c4c5c6c7c8c9cacbcccdcecfd0', 'hex'), "
          "(SELECT id FROM players WHERE public_key = "
          "decode('11223344556677889900aabbccddeeff00112233445566778899aabbcc"
          "ddeeff', 'hex')), "
          "(SELECT id FROM global_identities WHERE public_key = "
          "decode('11223344556677889900aabbccddeeff00112233445566778899aabbcc"
          "ddeeff', 'hex'))) ON CONFLICT DO NOTHING;"
          "INSERT INTO boards (id, fen, status, reservation_started_at, "
          "reserved_for_white) "
          "SELECT 8000 + g, '8/8/8/8/8/8/8/8 w - - 0 1', 'RESERVED', "
          "NOW() - INTERVAL '30 seconds', TRUE "
          "FROM generate_series(1, 40) AS g "
          "ON CONFLICT (id) DO UPDATE SET "
          "status = EXCLUDED.status, "
          "reservation_started_at = EXCLUDED.reservation_started_at, "
          "reserved_for_white = EXCLUDED.reserved_for_white;"
          "INSERT INTO reservations (board_id, session_id, expires_at, "
          "started_at, "
          "reserved_for_white) "
          "SELECT 8000 + g, "
          "(SELECT id FROM sessions WHERE token = "
          "decode('c1c2c3c4c5c6c7c8c9cacbcccdcecfd0', 'hex')), "
          "NOW() + ((1000 + g)::text || ' seconds')::interval, "
          "NOW() - INTERVAL '30 seconds', TRUE "
          "FROM generate_series(1, 40) AS g "
          "ON CONFLICT (board_id) DO UPDATE SET "
          "session_id = EXCLUDED.session_id, "
          "expires_at = EXCLUDED.expires_at, "
          "started_at = EXCLUDED.started_at, "
          "reserved_for_white = EXCLUDED.reserved_for_white;"
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test'), "
          "(0, 'protocol.ctrl', 'client_hello', '*', 'allow', 0, "
          "'hello_access', 'test'), "
          "(0, 'protocol.ctrl', 'get_active_reservations', '*', 'allow', 0, "
          "'reservations_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  player_manager_init();
  board_manager_init();

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  struct WambleMsg hello = {0};
  hello.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  hello.header_version = WAMBLE_PROTO_VERSION;
  RecvOneCtx rx_hello = {.sock = cli};
  wamble_thread_t th_hello;
  T_ASSERT(
      wamble_thread_create(&th_hello, recv_one_and_ack_thread, &rx_hello) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &hello, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_hello, NULL));
  T_ASSERT_EQ_INT(rx_hello.received, 1);
  T_ASSERT_EQ_INT(rx_hello.msg.ctrl, WAMBLE_CTRL_SERVER_HELLO);

  T_ASSERT(attach_persistent_identity(rx_hello.msg.token, target_pub) != NULL);

  struct WambleMsg req = {0};
  req.ctrl = WAMBLE_CTRL_GET_ACTIVE_RESERVATIONS;
  req.header_version = WAMBLE_PROTO_VERSION;
  memcpy(req.token, rx_hello.msg.token, TOKEN_LENGTH);

  RecvOneCtx rx = {.sock = cli};
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, recv_one_and_ack_thread, &rx) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &req, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));
  T_ASSERT_EQ_INT(rx.received, 1);
  T_ASSERT_EQ_INT(rx.msg.ctrl, WAMBLE_CTRL_ACTIVE_RESERVATIONS_DATA);
  T_ASSERT(rx.msg.fragment.fragment_data_len >= 2);
  {
    uint16_t count_be = 0;
    memcpy(&count_be, rx.msg.fragment.fragment_data, 2);
    T_ASSERT_EQ_INT((int)ntohs(count_be), 41);
  }
  T_ASSERT_EQ_INT((int)rx.msg.session.active_count, 41);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(server_protocol_get_active_reservations_db_failure_is_internal) {
  const char *cfg_path =
      "build/test_network_get_active_reservations_db_failure.conf";
  const uint8_t target_pub[WAMBLE_PUBLIC_KEY_LENGTH] = {
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xaa,
      0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
      0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(defprofile p1 ((def port 19426) (def advertise 1)))\n";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_identities (public_key) VALUES "
          "(decode('11223344556677889900aabbccddeeff00112233445566778899aabbcc"
          "ddeeff', 'hex')) ON CONFLICT (public_key) DO NOTHING;"
          "INSERT INTO players (public_key, rating) VALUES "
          "(decode('11223344556677889900aabbccddeeff00112233445566778899aabbcc"
          "ddeeff', 'hex'), 1000) ON CONFLICT (public_key) DO NOTHING;"
          "INSERT INTO sessions (token, player_id, global_identity_id) VALUES "
          "(decode('c1c2c3c4c5c6c7c8c9cacbcccdcecfd0', 'hex'), "
          "(SELECT id FROM players WHERE public_key = "
          "decode('11223344556677889900aabbccddeeff00112233445566778899aabbcc"
          "ddeeff', 'hex')), "
          "(SELECT id FROM global_identities WHERE public_key = "
          "decode('11223344556677889900aabbccddeeff00112233445566778899aabbcc"
          "ddeeff', 'hex'))) ON CONFLICT DO NOTHING;"
          "INSERT INTO boards (id, fen, status, reservation_started_at, "
          "reserved_for_white) VALUES "
          "(8777, '8/8/8/8/8/8/8/8 w - - 0 1', 'RESERVED', "
          "NOW() - INTERVAL '30 seconds', TRUE) ON CONFLICT DO NOTHING;"
          "INSERT INTO reservations (board_id, session_id, expires_at, "
          "started_at,"
          " reserved_for_white) VALUES "
          "(8777, (SELECT id FROM sessions WHERE token = "
          "decode('c1c2c3c4c5c6c7c8c9cacbcccdcecfd0', 'hex')), "
          "NOW() + INTERVAL '120 seconds', NOW() - INTERVAL '30 seconds', "
          "TRUE) "
          "ON CONFLICT (board_id) DO UPDATE SET "
          "session_id = EXCLUDED.session_id, "
          "expires_at = EXCLUDED.expires_at, "
          "started_at = EXCLUDED.started_at, "
          "reserved_for_white = EXCLUDED.reserved_for_white;"
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test'), "
          "(0, 'protocol.ctrl', 'client_hello', '*', 'allow', 0, "
          "'hello_access', 'test'), "
          "(0, 'protocol.ctrl', 'get_active_reservations', '*', 'allow', 0, "
          "'reservations_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  player_manager_init();
  board_manager_init();

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  struct WambleMsg hello = {0};
  hello.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  hello.header_version = WAMBLE_PROTO_VERSION;
  RecvOneCtx rx_hello = {.sock = cli};
  wamble_thread_t th_hello;
  T_ASSERT(
      wamble_thread_create(&th_hello, recv_one_and_ack_thread, &rx_hello) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &hello, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_hello, NULL));
  T_ASSERT_EQ_INT(rx_hello.received, 1);
  T_ASSERT_EQ_INT(rx_hello.msg.ctrl, WAMBLE_CTRL_SERVER_HELLO);
  T_ASSERT(attach_persistent_identity(rx_hello.msg.token, target_pub) != NULL);

  struct WambleMsg req = {0};
  req.ctrl = WAMBLE_CTRL_GET_ACTIVE_RESERVATIONS;
  req.header_version = WAMBLE_PROTO_VERSION;
  memcpy(req.token, rx_hello.msg.token, TOKEN_LENGTH);

  T_ASSERT_STATUS_OK(
      test_db_apply_sql("ALTER TABLE reservations "
                        "RENAME TO reservations_test_unavailable;"));

  RecvOneCtx rx = {.sock = cli};
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, recv_one_and_ack_thread, &rx) == 0);
  int handle_status = handle_message(srv, &req, &cliaddr, 0, "p1");
  int join_status = wamble_thread_join(th, NULL);
  int rx_received = rx.received;
  int restore_status =
      test_db_apply_sql("ALTER TABLE reservations_test_unavailable "
                        "RENAME TO reservations;");
  T_ASSERT_EQ_INT(join_status, 0);
  T_ASSERT_EQ_INT(restore_status, 0);
  T_ASSERT_EQ_INT(handle_status, SERVER_ERR_INTERNAL);
  T_ASSERT_EQ_INT(rx_received, 1);
  T_ASSERT_EQ_INT(rx.msg.ctrl, WAMBLE_CTRL_ERROR);
  T_ASSERT_EQ_INT(rx.msg.view.error_code, WAMBLE_ERR_RESERVATIONS_FAILED);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(server_protocol_accept_profile_tos_long_profile_name_persists) {
  const char *cfg_path = "build/test_network_accept_profile_tos_long_name.conf";
  char profile_name[96];
  memset(profile_name, 'n', sizeof(profile_name));
  profile_name[0] = 'p';
  profile_name[sizeof(profile_name) - 1] = '\0';
  size_t profile_name_len = strlen(profile_name);

  char cfg[1024];
  snprintf(cfg, sizeof(cfg),
           "(def rate-limit-requests-per-sec 100)\n"
           "(defprofile %s ((def port 19423) (def advertise 1) "
           "(def tos-text \"profile terms long\")))\n",
           profile_name);

  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test'), "
          "(0, 'protocol.ctrl', 'client_hello', '*', 'allow', 0, "
          "'hello_access', 'test'), "
          "(0, 'protocol.ctrl', 'accept_profile_tos', '*', 'allow', 0, "
          "'accept_profile_tos_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  player_manager_init();
  board_manager_init();

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  struct WambleMsg hello = {0};
  hello.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  hello.header_version = WAMBLE_PROTO_VERSION;

  RecvOneCtx rx_hello = {.sock = cli};
  wamble_thread_t th_hello;
  T_ASSERT(
      wamble_thread_create(&th_hello, recv_one_and_ack_thread, &rx_hello) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &hello, &cliaddr, 0, profile_name),
                  SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_hello, NULL));
  T_ASSERT_EQ_INT(rx_hello.received, 1);
  T_ASSERT_EQ_INT(rx_hello.msg.ctrl, WAMBLE_CTRL_SERVER_HELLO);

  struct WambleMsg accept = {0};
  accept.ctrl = WAMBLE_CTRL_ACCEPT_PROFILE_TOS;
  accept.header_version = WAMBLE_PROTO_VERSION;
  accept.seq_num = 104;
  memcpy(accept.token, rx_hello.msg.token, TOKEN_LENGTH);
  memcpy(accept.text.profile_name, profile_name, profile_name_len);
  accept.text.profile_name_len = (uint8_t)profile_name_len;

  RecvOneCtx rx_accept = {.sock = cli};
  wamble_thread_t th_accept;
  T_ASSERT(wamble_thread_create(&th_accept, recv_one_and_ack_thread,
                                &rx_accept) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &accept, &cliaddr, 0, profile_name),
                  SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_accept, NULL));
  T_ASSERT_EQ_INT(rx_accept.received, 1);
  T_ASSERT_EQ_INT(rx_accept.msg.ctrl, WAMBLE_CTRL_PROFILE_INFO);
  {
    const WambleMessageExtField *request_seq =
        find_ext_field(&rx_accept.msg, "request.seq_num");
    const WambleMessageExtField *tos_accepted =
        find_ext_field(&rx_accept.msg, "profile.tos_accepted");
    T_ASSERT(request_seq != NULL);
    T_ASSERT(tos_accepted != NULL);
    T_ASSERT_EQ_INT((int)request_seq->int_value, (int)accept.seq_num);
    T_ASSERT_EQ_INT((int)tos_accepted->int_value, 1);
  }

  {
    WambleProfileTermsAcceptance acceptance = {0};
    T_ASSERT_EQ_INT(wamble_query_get_latest_profile_terms_acceptance(
                        rx_hello.msg.token, profile_name, &acceptance),
                    DB_OK);
    T_ASSERT_STREQ(acceptance.profile_name, profile_name);
    wamble_profile_terms_acceptance_clear(&acceptance);
  }

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(server_protocol_login_uses_ed25519_challenge_response) {
  const char *cfg_path = "build/test_network_login_ed25519.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(defprofile p1 ((def port 19424) (def advertise 1)))\n";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test'), "
          "(0, 'protocol.ctrl', 'login_request', '*', 'allow', 0, "
          "'login_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  player_manager_init();
  board_manager_init();

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  WamblePlayer *player = create_new_player();
  T_ASSERT(player != NULL);

  uint8_t seed[32] = {0};
  uint8_t secret_key[64] = {0};
  uint8_t public_key[32] = {0};
  for (int i = 0; i < 32; i++)
    seed[i] = (uint8_t)(0x20 + i);
  wamble_client_keygen(seed, public_key, secret_key);

  struct WambleMsg challenge_req = {0};
  challenge_req.ctrl = WAMBLE_CTRL_LOGIN_REQUEST;
  memcpy(challenge_req.token, player->token, TOKEN_LENGTH);
  memcpy(challenge_req.login.public_key, public_key, WAMBLE_PUBLIC_KEY_LENGTH);

  RecvOneCtx rx_challenge = {.sock = cli};
  wamble_thread_t th_challenge;
  T_ASSERT(wamble_thread_create(&th_challenge, recv_one_and_ack_thread,
                                &rx_challenge) == 0);
  ServerStatus st = handle_message(srv, &challenge_req, &cliaddr, 0, "p1");
  T_ASSERT_STATUS_OK(wamble_thread_join(th_challenge, NULL));
  T_ASSERT_EQ_INT(st, SERVER_OK);
  T_ASSERT_EQ_INT(rx_challenge.received, 1);
  T_ASSERT_EQ_INT(rx_challenge.msg.ctrl, WAMBLE_CTRL_LOGIN_CHALLENGE);

  uint8_t bad_signature[WAMBLE_LOGIN_SIGNATURE_LENGTH] = {0};
  T_ASSERT(wamble_client_sign_challenge(secret_key, player->token, public_key,
                                        rx_challenge.msg.login.challenge,
                                        bad_signature) == 0);
  bad_signature[0] ^= 0x80;

  struct WambleMsg bad_req = {0};
  bad_req.ctrl = WAMBLE_CTRL_LOGIN_REQUEST;
  bad_req.login.has_signature = 1;
  memcpy(bad_req.token, player->token, TOKEN_LENGTH);
  memcpy(bad_req.login.public_key, public_key, WAMBLE_PUBLIC_KEY_LENGTH);
  memcpy(bad_req.login.signature, bad_signature, WAMBLE_LOGIN_SIGNATURE_LENGTH);

  RecvOneCtx rx_bad = {.sock = cli};
  wamble_thread_t th_bad;
  T_ASSERT(wamble_thread_create(&th_bad, recv_one_and_ack_thread, &rx_bad) ==
           0);
  ServerStatus bad_st = handle_message(srv, &bad_req, &cliaddr, 0, "p1");
  T_ASSERT_STATUS_OK(wamble_thread_join(th_bad, NULL));
  T_ASSERT_EQ_INT(bad_st, SERVER_ERR_LOGIN_FAILED);
  T_ASSERT_EQ_INT(rx_bad.received, 1);
  T_ASSERT_EQ_INT(rx_bad.msg.ctrl, WAMBLE_CTRL_LOGIN_FAILED);

  RecvOneCtx rx_challenge_2 = {.sock = cli};
  wamble_thread_t th_challenge_2;
  T_ASSERT(wamble_thread_create(&th_challenge_2, recv_one_and_ack_thread,
                                &rx_challenge_2) == 0);
  st = handle_message(srv, &challenge_req, &cliaddr, 0, "p1");
  T_ASSERT_STATUS_OK(wamble_thread_join(th_challenge_2, NULL));
  T_ASSERT_EQ_INT(st, SERVER_OK);
  T_ASSERT_EQ_INT(rx_challenge_2.received, 1);
  T_ASSERT_EQ_INT(rx_challenge_2.msg.ctrl, WAMBLE_CTRL_LOGIN_CHALLENGE);

  uint8_t good_signature[WAMBLE_LOGIN_SIGNATURE_LENGTH] = {0};
  T_ASSERT(wamble_client_sign_challenge(secret_key, player->token, public_key,
                                        rx_challenge_2.msg.login.challenge,
                                        good_signature) == 0);

  struct WambleMsg good_req = {0};
  good_req.ctrl = WAMBLE_CTRL_LOGIN_REQUEST;
  good_req.login.has_signature = 1;
  memcpy(good_req.token, player->token, TOKEN_LENGTH);
  memcpy(good_req.login.public_key, public_key, WAMBLE_PUBLIC_KEY_LENGTH);
  memcpy(good_req.login.signature, good_signature,
         WAMBLE_LOGIN_SIGNATURE_LENGTH);

  RecvOneCtx rx_ok = {.sock = cli};
  wamble_thread_t th_ok;
  T_ASSERT(wamble_thread_create(&th_ok, recv_one_and_ack_thread, &rx_ok) == 0);
  ServerStatus ok_st = handle_message(srv, &good_req, &cliaddr, 0, "p1");
  T_ASSERT_STATUS_OK(wamble_thread_join(th_ok, NULL));
  T_ASSERT_EQ_INT(ok_st, SERVER_OK);
  T_ASSERT_EQ_INT(rx_ok.received, 1);
  T_ASSERT_EQ_INT(rx_ok.msg.ctrl, WAMBLE_CTRL_LOGIN_SUCCESS);
  {
    const WambleMessageExtField *caps =
        find_ext_field(&rx_ok.msg, "session.caps");
    const WambleMessageExtField *reserved_at =
        find_ext_field(&rx_ok.msg, "reservation.reserved_at");
    T_ASSERT(caps != NULL);
    T_ASSERT(reserved_at != NULL);
    T_ASSERT(rx_ok.msg.board_id > 0);
    T_ASSERT(rx_ok.msg.view.fen[0] != '\0');
    T_ASSERT((caps->int_value & WAMBLE_SESSION_UI_CAP_ATTACH_IDENTITY) != 0);
    T_ASSERT(find_ext_field(&rx_ok.msg, "trust.tier") == NULL);
  }

  WamblePlayer *after = get_player_by_token(player->token);
  T_ASSERT(after != NULL);
  T_ASSERT(after->has_persistent_identity);
  T_ASSERT(memcmp(after->public_key, public_key, WAMBLE_PUBLIC_KEY_LENGTH) ==
           0);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(server_protocol_profile_tos_fragmented_with_hash) {
  char tos_text[WAMBLE_FRAGMENT_DATA_MAX + 128 + 1];
  size_t tos_text_len = (size_t)WAMBLE_FRAGMENT_DATA_MAX + 128;
  for (size_t i = 0; i < tos_text_len; i++)
    tos_text[i] = (char)('a' + (i % 26));
  tos_text[tos_text_len] = '\0';

  char cfg[WAMBLE_FRAGMENT_DATA_MAX + 1024];
  int wrote_cfg = snprintf(cfg, sizeof(cfg),
                           "(def rate-limit-requests-per-sec 100)\n"
                           "(defprofile p1 ((def port 19426) (def advertise 1) "
                           "(def tos-text \"%s\")))\n",
                           tos_text);
  T_ASSERT(wrote_cfg > 0);
  T_ASSERT(wrote_cfg < (int)sizeof(cfg));

  const char *cfg_path = "build/test_network_profile_tos_fragmented.conf";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test'), "
          "(0, 'protocol.ctrl', 'get_profile_tos', '*', 'allow', 0, "
          "'tos_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  player_manager_init();

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_STATUS_OK(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)));

  struct sockaddr_in cliaddr;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(cliaddr);
  T_ASSERT_STATUS_OK(getsockname(cli, (struct sockaddr *)&cliaddr, &slen));

  WamblePlayer *player = create_new_player();
  T_ASSERT(player != NULL);

  struct WambleMsg req = {0};
  req.ctrl = WAMBLE_CTRL_GET_PROFILE_TOS;
  memcpy(req.token, player->token, TOKEN_LENGTH);
  req.text.profile_name_len = 2;
  memcpy(req.text.profile_name, "p1", 2);

  RecvTosFragmentsCtx rx = {.sock = cli};
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, recv_tos_fragments_and_ack_thread, &rx) ==
           0);

  ServerStatus st = handle_message(srv, &req, &cliaddr, 0, "p1");
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));
  T_ASSERT_EQ_INT(st, SERVER_OK);
  T_ASSERT_EQ_INT(rx.received, 1);
  T_ASSERT(rx.expected_chunks > 1);
  T_ASSERT_EQ_INT(rx.chunk_count, rx.expected_chunks);
  {
    char echoed_profile[PROFILE_NAME_MAX_LENGTH];
    size_t base_len = 0;
    T_ASSERT(parse_payload_string_ext(rx.assembled, rx.assembled_len,
                                      "profile.name", &base_len, echoed_profile,
                                      sizeof(echoed_profile)));
    T_ASSERT_EQ_INT((int)base_len, (int)strlen(tos_text));
    T_ASSERT_EQ_INT((int)rx.total_len, (int)rx.assembled_len);
    T_ASSERT(memcmp(rx.assembled, tos_text, strlen(tos_text)) == 0);
    T_ASSERT_STREQ(echoed_profile, "p1");
  }
  uint8_t computed_hash[WAMBLE_FRAGMENT_HASH_LENGTH] = {0};
  crypto_blake2b(computed_hash, WAMBLE_FRAGMENT_HASH_LENGTH, rx.assembled,
                 rx.assembled_len);
  T_ASSERT_EQ_INT((int)rx.hash_algo, WAMBLE_FRAGMENT_HASH_BLAKE2B_256);
  T_ASSERT(rx.transfer_id != 0);
  T_ASSERT(memcmp(computed_hash, rx.hash, WAMBLE_FRAGMENT_HASH_LENGTH) == 0);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(get_profile_tos_roundtrip) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);
  struct sockaddr_in dst = {0};
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons((uint16_t)wamble_socket_bound_port(srv));

  struct WambleMsg out = {0};
  const char *name = "canary";
  out.ctrl = WAMBLE_CTRL_GET_PROFILE_TOS;
  out.text.profile_name_len = (uint8_t)strlen(name);
  memcpy(out.text.profile_name, name, strlen(name));
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(i + 5);

  T_ASSERT_STATUS_OK(send_unreliable_packet(cli, &out, &dst));

  struct WambleMsg in = {0};
  struct sockaddr_in from;
  int rc = receive_message(srv, &in, &from);
  T_ASSERT(rc > 0);
  T_ASSERT_EQ_INT(in.ctrl, WAMBLE_CTRL_GET_PROFILE_TOS);
  T_ASSERT_EQ_INT((int)in.text.profile_name_len, (int)strlen(name));
  T_ASSERT_STREQ(in.text.profile_name, name);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(accept_profile_tos_roundtrip) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);
  struct sockaddr_in dst = {0};
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons((uint16_t)wamble_socket_bound_port(srv));

  struct WambleMsg out = {0};
  const char *name = "canary";
  out.ctrl = WAMBLE_CTRL_ACCEPT_PROFILE_TOS;
  out.text.profile_name_len = (uint8_t)strlen(name);
  memcpy(out.text.profile_name, name, strlen(name));
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(i + 9);

  T_ASSERT_STATUS_OK(send_unreliable_packet(cli, &out, &dst));

  struct WambleMsg in = {0};
  struct sockaddr_in from;
  int rc = receive_message(srv, &in, &from);
  T_ASSERT(rc > 0);
  T_ASSERT_EQ_INT(in.ctrl, WAMBLE_CTRL_ACCEPT_PROFILE_TOS);
  T_ASSERT_EQ_INT((int)in.text.profile_name_len, (int)strlen(name));
  T_ASSERT_STREQ(in.text.profile_name, name);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TESTS_BEGIN_NAMED(wamble_register_tests_network)
WAMBLE_TESTS_ADD_SM(token_base64url_roundtrip, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_SM(spectate_update_roundtrip, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_SM(outbound_extension_roundtrip, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_SM(leaderboard_data_roundtrip, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_SM(
    leaderboard_data_score_type_roundtrip_without_fragment_marker,
    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_SM(player_stats_data_roundtrip, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_SM(login_challenge_roundtrip, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_SM(login_request_with_signature_roundtrip,
                    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_SM(profile_tos_data_fragment_roundtrip,
                    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_SM(server_notification_ext_auto_fragment_unreliable,
                    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_SM(server_notification_ext_auto_fragment_reliable,
                    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_SM(fragment_reassembly_api_complete_with_integrity_ok,
                    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_SM(fragment_reassembly_api_reports_hash_mismatch,
                    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_SM(fragment_reassembly_api_switches_transfers,
                    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_SM(submit_prediction_roundtrip, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_SM(prediction_data_roundtrip, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_SM(get_active_reservations_roundtrip, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_SM(active_reservations_data_roundtrip, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_DB_SM(reliable_ack_success, WAMBLE_SUITE_FUNCTIONAL,
                       "network");
WAMBLE_TESTS_ADD_DB_SM(reliable_ack_rejects_wrong_source_and_preserves_packets,
                       WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_SM(malformed_tiny_packet_rejected, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_SM(unknown_ctrl_rejected, WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_SM(player_move_uci_len_guard, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_SM(zero_token_rejected, WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_SM(zero_token_hello_allowed, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_SM(zero_token_reliable_list_profiles_isolation_by_client_addr,
                    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_SM(player_move_valid_uci_accept, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_SM(get_profile_info_long_name_roundtrip,
                    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_SM(profile_info_roundtrip, WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_SM(profile_info_endpoint_ext_roundtrip,
                    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_SM(profiles_list_roundtrip, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_DB_SM(server_protocol_client_hello_requires_policy,
                       WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_DB_SM(server_protocol_client_hello_advertises_session_caps,
                       WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_DB_SM(
    server_protocol_client_hello_reuses_existing_reserved_board,
    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_DB_SM(server_protocol_profile_info_advertises_profile_caps,
                       WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_DB_SM(
    server_protocol_profile_info_omits_tos_cap_when_text_empty,
    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_DB_SM(server_protocol_accept_profile_tos_persists_terms,
                       WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_DB_SM(server_protocol_terms_routes_allow_hidden_bound_profile,
                       WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_DB_SM(
    server_protocol_profile_terms_gate_session_for_profile_until_acceptance,
    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_DB_SM(
    server_protocol_logout_allowed_before_profile_terms_acceptance,
    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_DB_SM(
    server_protocol_spectate_denial_reports_capacity_full_error_code,
    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_DB_SM(
    server_protocol_reliable_spectate_focus_sends_terminal_before_ack,
    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_DB_SM(
    server_protocol_reliable_spectate_denial_sends_terminal_before_ack,
    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_DB_SM(
    server_protocol_spectate_summary_returns_reliable_snapshot,
    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_DB_SM(
    server_protocol_reliable_spectate_stop_sends_terminal_before_ack,
    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_DB_SM(
    server_protocol_spectate_stop_returns_reliable_idle_packet,
    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_DB_SM(server_protocol_player_stats_scope_context_is_ignored,
                       WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_DB_SM(
    server_protocol_player_stats_self_read_does_not_create_session,
    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_DB_SM(
    server_protocol_error_blocking_ext_marks_fatal_session_only,
    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_DB_SM(
    server_protocol_player_stats_caps_follow_contextual_policy,
    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_DB_SM(
    server_protocol_player_stats_target_handle_with_tag_policy,
    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_DB_SM(server_protocol_get_active_reservations_identity_query,
                       WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_DB_SM(
    server_protocol_get_active_reservations_includes_live_attached_board,
    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_DB_SM(
    server_protocol_get_active_reservations_caps_payload_count,
    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_DB_SM(
    server_protocol_get_active_reservations_db_failure_is_internal,
    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_DB_SM(
    server_protocol_accept_profile_tos_long_profile_name_persists,
    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_DB_SM(server_protocol_login_uses_ed25519_challenge_response,
                       WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_DB_SM(server_protocol_profile_tos_fragmented_with_hash,
                       WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_SM(spectate_stop_accept, WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_SM(reserved_nonzero_rejected, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_SM(legal_moves_count_guard, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_EX_SM(perf_unreliable_throughput_local,
                       WAMBLE_SUITE_PERFORMANCE, "network", NULL, NULL, 10000);
WAMBLE_TESTS_ADD_DB_EX_SM(perf_reliable_ack_latency, WAMBLE_SUITE_PERFORMANCE,
                          "network", NULL, NULL, 10000);
WAMBLE_TESTS_ADD_EX_SM(stress_unreliable_burst, WAMBLE_SUITE_STRESS, "network",
                       NULL, NULL, 60000);
WAMBLE_TESTS_ADD_SM(speed_token_encode_decode, WAMBLE_SUITE_SPEED, "network");
WAMBLE_TESTS_ADD_SM(token_base64url_invalid, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_SM(token_base64url_wrong_length, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_SM(get_profile_tos_roundtrip, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_SM(accept_profile_tos_roundtrip, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_END()
