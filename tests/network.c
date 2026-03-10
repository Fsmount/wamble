#include "common/wamble_net_helpers.h"
#include "common/wamble_test.h"
#include "common/wamble_test_helpers.h"
#include "wamble/wamble.h"
#include "wamble/wamble_db.h"

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

  T_ASSERT_STATUS_OK(send_unreliable_packet(srv, &out, &cliaddr));
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  T_ASSERT_EQ_INT(ctx.received, 1);
  T_ASSERT_EQ_INT(ctx.msg.ctrl, WAMBLE_CTRL_PLAYER_STATS_DATA);
  T_ASSERT(fabs(ctx.msg.player_stats_score - 42.5) < 1e-9);
  T_ASSERT_EQ_INT((int)ctx.msg.player_stats_games_played, 18);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
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
    T_ASSERT(strstr(rx1.msg.error_reason, "protocol.ctrl/client_hello") !=
             NULL);
  }

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TESTS_BEGIN_NAMED(wamble_register_tests_network)
WAMBLE_TESTS_ADD_SM(token_base64url_roundtrip, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_SM(spectate_update_roundtrip, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_SM(leaderboard_data_roundtrip, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
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
WAMBLE_TESTS_ADD_SM(player_move_valid_uci_accept, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_SM(get_profile_info_long_name_roundtrip,
                    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_SM(profile_info_roundtrip, WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_SM(profiles_list_roundtrip, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_DB_SM(server_protocol_client_hello_requires_policy,
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
WAMBLE_TESTS_END()
