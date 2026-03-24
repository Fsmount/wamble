#include "common/wamble_test.h"
#include "common/wamble_test_helpers.h"
#include "wamble/wamble.h"
#include "wamble/wamble_client.h"
#include "wamble/wamble_db.h"

void crypto_blake2b(uint8_t *hash, size_t hash_size, const uint8_t *msg,
                    size_t msg_size);

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
        in.fragment_version != WAMBLE_FRAGMENT_VERSION)
      continue;
    if (c->expected_chunks == 0) {
      c->expected_chunks = (int)in.fragment_chunk_count;
      c->total_len = in.fragment_total_len;
      c->transfer_id = in.fragment_transfer_id;
      c->hash_algo = in.fragment_hash_algo;
      memcpy(c->hash, in.fragment_hash, WAMBLE_FRAGMENT_HASH_LENGTH);
    } else if (in.fragment_transfer_id != c->transfer_id ||
               in.fragment_hash_algo != c->hash_algo ||
               in.fragment_chunk_count != (uint16_t)c->expected_chunks ||
               in.fragment_total_len != c->total_len) {
      continue;
    }
    if (in.fragment_chunk_count == 0 ||
        in.fragment_chunk_index >= in.fragment_chunk_count ||
        in.fragment_data_len > WAMBLE_FRAGMENT_DATA_MAX) {
      continue;
    }
    size_t off =
        (size_t)in.fragment_chunk_index * (size_t)WAMBLE_FRAGMENT_DATA_MAX;
    if (off + in.fragment_data_len > sizeof(c->assembled))
      continue;
    if (in.fragment_data_len) {
      memcpy(c->assembled + off, in.fragment_data, in.fragment_data_len);
    }
    size_t end = off + in.fragment_data_len;
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
  msg->ext_count = 5;
  for (uint8_t i = 0; i < msg->ext_count; i++) {
    WambleMessageExtField *field = &msg->ext[i];
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
  for (uint8_t i = 0; i < msg->ext_count; i++) {
    if (strcmp(msg->ext[i].key, key) == 0)
      return &msg->ext[i];
  }
  return NULL;
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
  strncpy(out.fen, "fen-io", FEN_MAX_LENGTH);

  T_ASSERT_STATUS_OK(send_unreliable_packet(srv, &out, &cliaddr));
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  T_ASSERT_EQ_INT(ctx.received, 1);
  T_ASSERT_EQ_INT(ctx.msg.ctrl, WAMBLE_CTRL_SPECTATE_UPDATE);
  T_ASSERT_EQ_INT(ctx.msg.board_id, 1234);
  T_ASSERT((ctx.msg.flags & WAMBLE_FLAG_UNRELIABLE) != 0);
  T_ASSERT_EQ_INT(ctx.msg.seq_num, 0);
  T_ASSERT_EQ_INT(ctx.msg.header_version, WAMBLE_PROTO_VERSION);
  T_ASSERT_STREQ(ctx.msg.fen, "fen-io");

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
  strncpy(out.fen, "payload-ext", FEN_MAX_LENGTH);
  out.ext_count = 3;
  snprintf(out.ext[0].key, sizeof(out.ext[0].key), "%s", "note");
  out.ext[0].value_type = WAMBLE_TREATMENT_VALUE_STRING;
  snprintf(out.ext[0].string_value, sizeof(out.ext[0].string_value), "%s",
           "hello");
  snprintf(out.ext[1].key, sizeof(out.ext[1].key), "%s", "points");
  out.ext[1].value_type = WAMBLE_TREATMENT_VALUE_DOUBLE;
  out.ext[1].double_value = 12.5;
  snprintf(out.ext[2].key, sizeof(out.ext[2].key), "%s", "active");
  out.ext[2].value_type = WAMBLE_TREATMENT_VALUE_BOOL;
  out.ext[2].bool_value = 1;

  T_ASSERT_STATUS_OK(send_unreliable_packet(srv, &out, &cliaddr));
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  T_ASSERT_EQ_INT(ctx.received, 1);
  T_ASSERT_EQ_INT(ctx.msg.ctrl, WAMBLE_CTRL_SERVER_NOTIFICATION);
  T_ASSERT((ctx.msg.flags & WAMBLE_FLAG_UNRELIABLE) != 0);
  T_ASSERT((ctx.msg.flags & WAMBLE_FLAG_EXT_PAYLOAD) != 0);
  T_ASSERT_STREQ(ctx.msg.fen, "payload-ext");
  T_ASSERT_EQ_INT(ctx.msg.ext_count, 3);
  T_ASSERT_STREQ(ctx.msg.ext[0].key, "note");
  T_ASSERT_EQ_INT(ctx.msg.ext[0].value_type, WAMBLE_TREATMENT_VALUE_STRING);
  T_ASSERT_STREQ(ctx.msg.ext[0].string_value, "hello");
  T_ASSERT_STREQ(ctx.msg.ext[1].key, "points");
  T_ASSERT_EQ_INT(ctx.msg.ext[1].value_type, WAMBLE_TREATMENT_VALUE_DOUBLE);
  T_ASSERT(fabs(ctx.msg.ext[1].double_value - 12.5) < 1e-9);
  T_ASSERT_STREQ(ctx.msg.ext[2].key, "active");
  T_ASSERT_EQ_INT(ctx.msg.ext[2].value_type, WAMBLE_TREATMENT_VALUE_BOOL);
  T_ASSERT_EQ_INT(ctx.msg.ext[2].bool_value, 1);

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
  out.leaderboard_type = WAMBLE_LEADERBOARD_RATING;
  out.leaderboard_self_rank = 9;
  out.leaderboard_count = 2;
  out.leaderboard[0].rank = 1;
  out.leaderboard[0].session_id = 101;
  out.leaderboard[0].score = 150.5;
  out.leaderboard[0].rating = 1210.0;
  out.leaderboard[0].games_played = 12;
  out.leaderboard[1].rank = 2;
  out.leaderboard[1].session_id = 102;
  out.leaderboard[1].score = 120.0;
  out.leaderboard[1].rating = 1188.25;
  out.leaderboard[1].games_played = 8;

  T_ASSERT_STATUS_OK(send_unreliable_packet(srv, &out, &cliaddr));
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  T_ASSERT_EQ_INT(ctx.received, 1);
  T_ASSERT_EQ_INT(ctx.msg.ctrl, WAMBLE_CTRL_LEADERBOARD_DATA);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard_type, WAMBLE_LEADERBOARD_RATING);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard_self_rank, 9);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard_count, 2);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard[0].rank, 1);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard[0].session_id, 101);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard[0].games_played, 12);
  T_ASSERT(fabs(ctx.msg.leaderboard[0].score - 150.5) < 1e-9);
  T_ASSERT(fabs(ctx.msg.leaderboard[0].rating - 1210.0) < 1e-9);

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
  out.leaderboard_type = WAMBLE_LEADERBOARD_SCORE;
  out.leaderboard_self_rank = 11;
  out.leaderboard_count = 2;
  out.leaderboard[0].rank = 1;
  out.leaderboard[0].session_id = 2001;
  out.leaderboard[0].score = 321.25;
  out.leaderboard[0].rating = 1432.5;
  out.leaderboard[0].games_played = 21;
  out.leaderboard[1].rank = 2;
  out.leaderboard[1].session_id = 2002;
  out.leaderboard[1].score = 300.0;
  out.leaderboard[1].rating = 1411.0;
  out.leaderboard[1].games_played = 19;

  T_ASSERT_STATUS_OK(send_unreliable_packet(srv, &out, &cliaddr));
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  T_ASSERT_EQ_INT(ctx.received, 1);
  T_ASSERT_EQ_INT(ctx.msg.ctrl, WAMBLE_CTRL_LEADERBOARD_DATA);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard_type, WAMBLE_LEADERBOARD_SCORE);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard_self_rank, 11);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard_count, 2);
  T_ASSERT((ctx.msg.flags & WAMBLE_FLAG_FRAGMENT_PAYLOAD) == 0);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard[0].rank, 1);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard[0].session_id, 2001);
  T_ASSERT_EQ_INT((int)ctx.msg.leaderboard[0].games_played, 21);
  T_ASSERT(fabs(ctx.msg.leaderboard[0].score - 321.25) < 1e-9);
  T_ASSERT(fabs(ctx.msg.leaderboard[0].rating - 1432.5) < 1e-9);

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
  out.player_stats_score = 42.5;
  out.player_stats_games_played = 18;
  out.player_stats_chess960_games_played = 7;

  T_ASSERT_STATUS_OK(send_unreliable_packet(srv, &out, &cliaddr));
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  T_ASSERT_EQ_INT(ctx.received, 1);
  T_ASSERT_EQ_INT(ctx.msg.ctrl, WAMBLE_CTRL_PLAYER_STATS_DATA);
  T_ASSERT(fabs(ctx.msg.player_stats_score - 42.5) < 1e-9);
  T_ASSERT_EQ_INT((int)ctx.msg.player_stats_games_played, 18);
  T_ASSERT_EQ_INT((int)ctx.msg.player_stats_chess960_games_played, 7);

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
    out.login_challenge[i] = (uint8_t)(0xa0 + i);

  T_ASSERT_STATUS_OK(send_unreliable_packet(srv, &out, &cliaddr));
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  T_ASSERT_EQ_INT(ctx.received, 1);
  T_ASSERT_EQ_INT(ctx.msg.ctrl, WAMBLE_CTRL_LOGIN_CHALLENGE);
  for (int i = 0; i < WAMBLE_LOGIN_CHALLENGE_LENGTH; i++) {
    T_ASSERT_EQ_INT((int)ctx.msg.login_challenge[i], (int)(0xa0 + i));
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
  out.login_has_signature = 1;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(0x73 + i);
  for (int i = 0; i < WAMBLE_PUBLIC_KEY_LENGTH; i++)
    out.login_pubkey[i] = (uint8_t)(0x10 + i);
  for (int i = 0; i < WAMBLE_LOGIN_SIGNATURE_LENGTH; i++)
    out.login_signature[i] = (uint8_t)(0x80 + i);

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
  T_ASSERT_EQ_INT((int)in.login_has_signature, 1);
  for (int i = 0; i < WAMBLE_PUBLIC_KEY_LENGTH; i++) {
    T_ASSERT_EQ_INT((int)in.login_pubkey[i], (int)(0x10 + i));
  }
  for (int i = 0; i < WAMBLE_LOGIN_SIGNATURE_LENGTH; i++) {
    T_ASSERT_EQ_INT((int)in.login_signature[i], (int)(0x80 + i));
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
  out.fragment_data_len = (uint16_t)strlen(fragment);
  memcpy(out.fragment_data, fragment, out.fragment_data_len);
  out.fragment_version = WAMBLE_FRAGMENT_VERSION;
  out.fragment_hash_algo = WAMBLE_FRAGMENT_HASH_BLAKE2B_256;
  out.fragment_chunk_index = 1;
  out.fragment_chunk_count = 3;
  out.fragment_total_len = 200;
  out.fragment_transfer_id = 77;
  for (int i = 0; i < WAMBLE_FRAGMENT_HASH_LENGTH; i++)
    out.fragment_hash[i] = (uint8_t)(0xa0 + i);

  T_ASSERT_STATUS_OK(send_unreliable_packet(srv, &out, &cliaddr));
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  T_ASSERT_EQ_INT(ctx.received, 1);
  T_ASSERT_EQ_INT(ctx.msg.ctrl, WAMBLE_CTRL_PROFILE_TOS_DATA);
  T_ASSERT((ctx.msg.flags & WAMBLE_FLAG_FRAGMENT_PAYLOAD) != 0);
  T_ASSERT_EQ_INT((int)ctx.msg.fragment_version, WAMBLE_FRAGMENT_VERSION);
  T_ASSERT_EQ_INT((int)ctx.msg.fragment_hash_algo,
                  WAMBLE_FRAGMENT_HASH_BLAKE2B_256);
  T_ASSERT_EQ_INT((int)ctx.msg.fragment_chunk_index, 1);
  T_ASSERT_EQ_INT((int)ctx.msg.fragment_chunk_count, 3);
  T_ASSERT_EQ_INT((int)ctx.msg.fragment_total_len, 200);
  T_ASSERT_EQ_INT((int)ctx.msg.fragment_transfer_id, 77);
  T_ASSERT_EQ_INT((int)ctx.msg.fragment_data_len, (int)strlen(fragment));
  T_ASSERT(memcmp(ctx.msg.fragment_data, fragment, strlen(fragment)) == 0);
  for (int i = 0; i < WAMBLE_FRAGMENT_HASH_LENGTH; i++)
    T_ASSERT_EQ_INT((int)ctx.msg.fragment_hash[i], (int)(0xa0 + i));

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
  strncpy(out.fen, "oversized-fragmented-notice", sizeof(out.fen) - 1);
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
  T_ASSERT_EQ_INT((int)rx.assembled[0], (int)out.notification_type);
  size_t base_len = strlen(out.fen);
  T_ASSERT(memcmp(rx.assembled + 1, out.fen, base_len) == 0);
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
  strncpy(out.fen, "oversized-fragmented-reliable", sizeof(out.fen) - 1);
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
  T_ASSERT_EQ_INT((int)rx.assembled[0], (int)out.notification_type);
  size_t base_len = strlen(out.fen);
  T_ASSERT(memcmp(rx.assembled + 1, out.fen, base_len) == 0);
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
    frag.fragment_version = WAMBLE_FRAGMENT_VERSION;
    frag.fragment_hash_algo = WAMBLE_FRAGMENT_HASH_BLAKE2B_256;
    frag.fragment_chunk_index = idx;
    frag.fragment_chunk_count = 3;
    frag.fragment_total_len = (uint32_t)full_len;
    frag.fragment_transfer_id = 101;
    memcpy(frag.fragment_hash, hash, WAMBLE_FRAGMENT_HASH_LENGTH);
    frag.fragment_data_len = (uint16_t)len;
    memcpy(frag.fragment_data, full + off, len);

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
    frag.fragment_version = WAMBLE_FRAGMENT_VERSION;
    frag.fragment_hash_algo = WAMBLE_FRAGMENT_HASH_BLAKE2B_256;
    frag.fragment_chunk_index = idx;
    frag.fragment_chunk_count = 2;
    frag.fragment_total_len = (uint32_t)full_len;
    frag.fragment_transfer_id = 102;
    memcpy(frag.fragment_hash, hash, WAMBLE_FRAGMENT_HASH_LENGTH);
    frag.fragment_data_len = (uint16_t)len;
    memcpy(frag.fragment_data, full + off, len);

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
  first.fragment_version = WAMBLE_FRAGMENT_VERSION;
  first.fragment_hash_algo = WAMBLE_FRAGMENT_HASH_BLAKE2B_256;
  first.fragment_chunk_index = 0;
  first.fragment_chunk_count = 2;
  first.fragment_total_len = (uint32_t)sizeof(a);
  first.fragment_transfer_id = 200;
  memcpy(first.fragment_hash, hash_a, WAMBLE_FRAGMENT_HASH_LENGTH);
  first.fragment_data_len = (uint16_t)WAMBLE_FRAGMENT_DATA_MAX;
  memcpy(first.fragment_data, a, (size_t)first.fragment_data_len);

  T_ASSERT_EQ_INT(wamble_fragment_reassembly_push(&reassembly, &first),
                  WAMBLE_FRAGMENT_REASSEMBLY_IN_PROGRESS);
  T_ASSERT_EQ_INT((int)reassembly.transfer_id, 200);

  struct WambleMsg second = {0};
  second.ctrl = WAMBLE_CTRL_PROFILE_TOS_DATA;
  second.fragment_version = WAMBLE_FRAGMENT_VERSION;
  second.fragment_hash_algo = WAMBLE_FRAGMENT_HASH_BLAKE2B_256;
  second.fragment_chunk_index = 0;
  second.fragment_chunk_count = 1;
  second.fragment_total_len = (uint32_t)strlen(b);
  second.fragment_transfer_id = 201;
  memcpy(second.fragment_hash, hash_b, WAMBLE_FRAGMENT_HASH_LENGTH);
  second.fragment_data_len = (uint16_t)strlen(b);
  memcpy(second.fragment_data, b, (size_t)second.fragment_data_len);

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
  out.prediction_parent_id = 1234;
  strcpy(out.uci, "e2e4");
  out.uci_len = 4;
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
  T_ASSERT_EQ_INT((int)in.prediction_parent_id, 1234);
  T_ASSERT_EQ_INT((int)in.uci_len, 4);
  T_ASSERT_STREQ(in.uci, "e2e4");

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
  out.prediction_count = 2;
  out.predictions[0].id = 1;
  out.predictions[0].parent_id = 0;
  memcpy(out.predictions[0].token, out.token, TOKEN_LENGTH);
  out.predictions[0].points_awarded = 1.5;
  out.predictions[0].target_ply = 4;
  out.predictions[0].depth = 0;
  out.predictions[0].status = WAMBLE_PREDICTION_STATUS_CORRECT;
  out.predictions[0].uci_len = 4;
  memcpy(out.predictions[0].uci, "e2e4", 4);
  out.predictions[1].id = 2;
  out.predictions[1].parent_id = 1;
  memcpy(out.predictions[1].token, out.token, TOKEN_LENGTH);
  out.predictions[1].points_awarded = 0.0;
  out.predictions[1].target_ply = 5;
  out.predictions[1].depth = 1;
  out.predictions[1].status = WAMBLE_PREDICTION_STATUS_PENDING;
  out.predictions[1].uci_len = 4;
  memcpy(out.predictions[1].uci, "e7e5", 4);

  T_ASSERT_STATUS_OK(send_unreliable_packet(srv, &out, &cliaddr));
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  T_ASSERT_EQ_INT(ctx.received, 1);
  T_ASSERT_EQ_INT(ctx.msg.ctrl, WAMBLE_CTRL_PREDICTION_DATA);
  T_ASSERT_EQ_INT((int)ctx.msg.prediction_count, 2);
  T_ASSERT_EQ_INT((int)ctx.msg.predictions[0].id, 1);
  T_ASSERT_EQ_INT((int)ctx.msg.predictions[1].parent_id, 1);
  T_ASSERT_EQ_INT((int)ctx.msg.predictions[1].depth, 1);
  T_ASSERT_EQ_INT((int)ctx.msg.predictions[0].status,
                  WAMBLE_PREDICTION_STATUS_CORRECT);
  T_ASSERT_EQ_INT((int)ctx.msg.predictions[1].status,
                  WAMBLE_PREDICTION_STATUS_PENDING);
  T_ASSERT(fabs(ctx.msg.predictions[0].points_awarded - 1.5) < 1e-9);

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
  strncpy(msg.fen, "fen-data", FEN_MAX_LENGTH);
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
  strncpy(msg.fen, "fen-data", FEN_MAX_LENGTH);
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
    snprintf(out.fen, FEN_MAX_LENGTH, "fen-%d", i);
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
  strncpy(msg.fen, "fen-data", FEN_MAX_LENGTH);
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
      snprintf(out.fen, FEN_MAX_LENGTH, "c%d-m%d", i, m);
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
  out.uci_len = (uint8_t)strlen(uci);
  memcpy(out.uci, uci, out.uci_len);
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
  T_ASSERT_EQ_INT(in.uci_len, (int)strlen(uci));
  T_ASSERT_STREQ(in.uci, uci);

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
  out.profile_name_len = (uint8_t)strlen(name);
  memcpy(out.profile_name, name, strlen(name));
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(i + 1);

  T_ASSERT_STATUS_OK(send_unreliable_packet(cli, &out, &dst));

  struct WambleMsg in = {0};
  struct sockaddr_in from;
  int rc = receive_message(srv, &in, &from);
  T_ASSERT(rc > 0);
  T_ASSERT_EQ_INT(in.ctrl, WAMBLE_CTRL_GET_PROFILE_INFO);
  T_ASSERT_EQ_INT((int)in.profile_name_len, (int)strlen(name));
  T_ASSERT_STREQ(in.profile_name, name);

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
  snprintf(out.profile_info, sizeof(out.profile_info), "%s", "alpha;8888;1;0");
  out.profile_info_len = (uint16_t)strlen(out.profile_info);

  T_ASSERT_STATUS_OK(send_unreliable_packet(srv, &out, &cliaddr));
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  T_ASSERT_EQ_INT(ctx.received, 1);
  T_ASSERT_EQ_INT(ctx.msg.ctrl, WAMBLE_CTRL_PROFILE_INFO);
  T_ASSERT_EQ_INT((int)ctx.msg.profile_info_len, (int)strlen("alpha;8888;1;0"));
  T_ASSERT_STREQ(ctx.msg.profile_info, "alpha;8888;1;0");

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
  snprintf(out.profile_info, sizeof(out.profile_info), "%s", "alpha;8888;1;0");
  out.profile_info_len = (uint16_t)strlen(out.profile_info);

  out.ext_count = 3;
  snprintf(out.ext[0].key, sizeof(out.ext[0].key), "%s", "profile.caps");
  out.ext[0].value_type = WAMBLE_TREATMENT_VALUE_INT;
  out.ext[0].int_value = WAMBLE_PROFILE_UI_CAP_TOS;
  snprintf(out.ext[1].key, sizeof(out.ext[1].key), "%s",
           "profile.websocket_port");
  out.ext[1].value_type = WAMBLE_TREATMENT_VALUE_INT;
  out.ext[1].int_value = 19421;
  snprintf(out.ext[2].key, sizeof(out.ext[2].key), "%s",
           "profile.websocket_path");
  out.ext[2].value_type = WAMBLE_TREATMENT_VALUE_STRING;
  snprintf(out.ext[2].string_value, sizeof(out.ext[2].string_value), "%s",
           "/proxy/p1/ws");

  T_ASSERT_EQ_INT(wamble_packet_serialize(&out, buffer, sizeof(buffer),
                                          &serialized, WAMBLE_FLAG_UNRELIABLE),
                  NET_OK);
  T_ASSERT_EQ_INT(wamble_packet_deserialize(buffer, serialized, &in, &flags),
                  NET_OK);
  T_ASSERT((flags & WAMBLE_FLAG_UNRELIABLE) != 0);
  T_ASSERT((flags & WAMBLE_FLAG_EXT_PAYLOAD) != 0);
  T_ASSERT_EQ_INT(in.ctrl, WAMBLE_CTRL_PROFILE_INFO);
  T_ASSERT_STREQ(in.profile_info, out.profile_info);
  T_ASSERT_EQ_INT((int)in.ext_count, 3);

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
  snprintf(out.profiles_list, sizeof(out.profiles_list), "%s",
           "alpha,beta,canary");
  out.profiles_list_len = (uint16_t)strlen(out.profiles_list);

  T_ASSERT_STATUS_OK(send_unreliable_packet(srv, &out, &cliaddr));
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  T_ASSERT_EQ_INT(ctx.received, 1);
  T_ASSERT_EQ_INT(ctx.msg.ctrl, WAMBLE_CTRL_PROFILES_LIST);
  T_ASSERT_EQ_INT((int)ctx.msg.profiles_list_len,
                  (int)strlen("alpha,beta,canary"));
  T_ASSERT_STREQ(ctx.msg.profiles_list, "alpha,beta,canary");

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
    T_ASSERT_EQ_INT(rx1.msg.error_code, WAMBLE_ERR_ACCESS_DENIED);
    T_ASSERT_EQ_INT(rx1.msg.error_reason[0], '\0');
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
  req.profile_name_len = 2;
  memcpy(req.profile_name, "p1", 2);

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
  req.profile_name_len = 2;
  memcpy(req.profile_name, "p1", 2);

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
  memcpy(accept.token, rx_hello.msg.token, TOKEN_LENGTH);
  memcpy(accept.profile_name, "p1", 2);
  accept.profile_name_len = 2;

  RecvOneCtx rx_ack = {.sock = cli};
  wamble_thread_t th_ack;
  T_ASSERT(wamble_thread_create(&th_ack, recv_one_thread, &rx_ack) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &accept, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_ack, NULL));
  T_ASSERT_EQ_INT(rx_ack.received, 1);
  T_ASSERT_EQ_INT(rx_ack.msg.ctrl, WAMBLE_CTRL_ACK);

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
  memcpy(tos_req.profile_name, "p1", 2);
  tos_req.profile_name_len = 2;

  RecvOneCtx rx_tos = {.sock = cli};
  wamble_thread_t th_tos;
  T_ASSERT(wamble_thread_create(&th_tos, recv_one_and_ack_thread, &rx_tos) ==
           0);
  T_ASSERT_EQ_INT(handle_message(srv, &tos_req, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_tos, NULL));
  T_ASSERT_EQ_INT(rx_tos.received, 1);
  T_ASSERT_EQ_INT(rx_tos.msg.ctrl, WAMBLE_CTRL_PROFILE_TOS_DATA);
  T_ASSERT_STREQ(rx_tos.msg.profile_info, "private profile terms");

  struct WambleMsg accept = {0};
  accept.ctrl = WAMBLE_CTRL_ACCEPT_PROFILE_TOS;
  accept.header_version = WAMBLE_PROTO_VERSION;
  memcpy(accept.token, rx_hello.msg.token, TOKEN_LENGTH);
  memcpy(accept.profile_name, "p1", 2);
  accept.profile_name_len = 2;

  RecvOneCtx rx_ack = {.sock = cli};
  wamble_thread_t th_ack;
  T_ASSERT(wamble_thread_create(&th_ack, recv_one_thread, &rx_ack) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &accept, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_ack, NULL));
  T_ASSERT_EQ_INT(rx_ack.received, 1);
  T_ASSERT_EQ_INT(rx_ack.msg.ctrl, WAMBLE_CTRL_ACK);

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
  T_ASSERT_EQ_INT(rx_denied.msg.error_code, WAMBLE_ERR_ACCESS_DENIED);
  T_ASSERT_STREQ(rx_denied.msg.error_reason, "terms acceptance required");

  struct WambleMsg accept = {0};
  accept.ctrl = WAMBLE_CTRL_ACCEPT_PROFILE_TOS;
  accept.header_version = WAMBLE_PROTO_VERSION;
  memcpy(accept.token, rx_hello.msg.token, TOKEN_LENGTH);
  memcpy(accept.profile_name, "p1", 2);
  accept.profile_name_len = 2;

  RecvOneCtx rx_ack = {.sock = cli};
  wamble_thread_t th_ack;
  T_ASSERT(wamble_thread_create(&th_ack, recv_one_thread, &rx_ack) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &accept, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_ack, NULL));
  T_ASSERT_EQ_INT(rx_ack.received, 1);
  T_ASSERT_EQ_INT(rx_ack.msg.ctrl, WAMBLE_CTRL_ACK);

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

  RecvOneCtx rx_post_join = {.sock = cli};
  wamble_thread_t th_post_join;
  T_ASSERT(wamble_thread_create(&th_post_join, recv_one_and_ack_thread,
                                &rx_post_join) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &post_join_req, &cliaddr, 0, "p1"),
                  SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_post_join, NULL));
  T_ASSERT_EQ_INT(rx_post_join.received, 1);
  T_ASSERT_EQ_INT(rx_post_join.msg.ctrl, WAMBLE_CTRL_PLAYER_STATS_DATA);

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
  memcpy(accept.token, rx_hello.msg.token, TOKEN_LENGTH);
  memcpy(accept.profile_name, profile_name, profile_name_len);
  accept.profile_name_len = (uint8_t)profile_name_len;

  RecvOneCtx rx_ack = {.sock = cli};
  wamble_thread_t th_ack;
  T_ASSERT(wamble_thread_create(&th_ack, recv_one_thread, &rx_ack) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &accept, &cliaddr, 0, profile_name),
                  SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_ack, NULL));
  T_ASSERT_EQ_INT(rx_ack.received, 1);
  T_ASSERT_EQ_INT(rx_ack.msg.ctrl, WAMBLE_CTRL_ACK);

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
  memcpy(challenge_req.login_pubkey, public_key, WAMBLE_PUBLIC_KEY_LENGTH);

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
                                        rx_challenge.msg.login_challenge,
                                        bad_signature) == 0);
  bad_signature[0] ^= 0x80;

  struct WambleMsg bad_req = {0};
  bad_req.ctrl = WAMBLE_CTRL_LOGIN_REQUEST;
  bad_req.login_has_signature = 1;
  memcpy(bad_req.token, player->token, TOKEN_LENGTH);
  memcpy(bad_req.login_pubkey, public_key, WAMBLE_PUBLIC_KEY_LENGTH);
  memcpy(bad_req.login_signature, bad_signature, WAMBLE_LOGIN_SIGNATURE_LENGTH);

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
                                        rx_challenge_2.msg.login_challenge,
                                        good_signature) == 0);

  struct WambleMsg good_req = {0};
  good_req.ctrl = WAMBLE_CTRL_LOGIN_REQUEST;
  good_req.login_has_signature = 1;
  memcpy(good_req.token, player->token, TOKEN_LENGTH);
  memcpy(good_req.login_pubkey, public_key, WAMBLE_PUBLIC_KEY_LENGTH);
  memcpy(good_req.login_signature, good_signature,
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
    T_ASSERT(caps != NULL);
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
  req.profile_name_len = 2;
  memcpy(req.profile_name, "p1", 2);

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
  T_ASSERT_EQ_INT((int)rx.total_len, (int)strlen(tos_text));
  T_ASSERT_EQ_INT((int)rx.assembled_len, (int)strlen(tos_text));
  T_ASSERT(memcmp(rx.assembled, tos_text, strlen(tos_text)) == 0);
  uint8_t computed_hash[WAMBLE_FRAGMENT_HASH_LENGTH] = {0};
  crypto_blake2b(computed_hash, WAMBLE_FRAGMENT_HASH_LENGTH,
                 (const uint8_t *)tos_text, strlen(tos_text));
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
  out.profile_name_len = (uint8_t)strlen(name);
  memcpy(out.profile_name, name, strlen(name));
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(i + 5);

  T_ASSERT_STATUS_OK(send_unreliable_packet(cli, &out, &dst));

  struct WambleMsg in = {0};
  struct sockaddr_in from;
  int rc = receive_message(srv, &in, &from);
  T_ASSERT(rc > 0);
  T_ASSERT_EQ_INT(in.ctrl, WAMBLE_CTRL_GET_PROFILE_TOS);
  T_ASSERT_EQ_INT((int)in.profile_name_len, (int)strlen(name));
  T_ASSERT_STREQ(in.profile_name, name);

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
  out.profile_name_len = (uint8_t)strlen(name);
  memcpy(out.profile_name, name, strlen(name));
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(i + 9);

  T_ASSERT_STATUS_OK(send_unreliable_packet(cli, &out, &dst));

  struct WambleMsg in = {0};
  struct sockaddr_in from;
  int rc = receive_message(srv, &in, &from);
  T_ASSERT(rc > 0);
  T_ASSERT_EQ_INT(in.ctrl, WAMBLE_CTRL_ACCEPT_PROFILE_TOS);
  T_ASSERT_EQ_INT((int)in.profile_name_len, (int)strlen(name));
  T_ASSERT_STREQ(in.profile_name, name);

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
