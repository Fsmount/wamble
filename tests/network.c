#include "common/wamble_test.h"
#include "wamble/wamble.h"
#include "wamble/wamble_db.h"

static void sleep_ms(int ms) {
  struct timeval tv;
  tv.tv_sec = ms / 1000;
  tv.tv_usec = (ms % 1000) * 1000;
  select(0, NULL, NULL, NULL, &tv);
}

static int g_mock_rate_bypass = 0;
static int g_mock_discover_override = 0;

static int fill_server_addr(wamble_socket_t srv, struct sockaddr_in *out);

static DbStatus
mock_resolve_policy_decision(const uint8_t *token, const char *profile,
                             const char *action, const char *resource,
                             const char *context_key, const char *context_value,
                             WamblePolicyDecision *out) {
  (void)token;
  (void)profile;
  (void)context_key;
  (void)context_value;
  if (!action || !resource || !out)
    return DB_ERR_BAD_DATA;
  memset(out, 0, sizeof(*out));
  snprintf(out->action, sizeof(out->action), "%s", action);
  snprintf(out->resource, sizeof(out->resource), "%s", resource);
  snprintf(out->effect, sizeof(out->effect), "%s", "deny");
  snprintf(out->policy_version, sizeof(out->policy_version), "%s", "test");
  snprintf(out->scope, sizeof(out->scope), "%s", "*");
  out->allowed = 0;
  out->permission_level = 0;

  if (strcmp(action, "protocol.ctrl") == 0 &&
      (strcmp(resource, "list_profiles") == 0 ||
       strcmp(resource, "get_profile_info") == 0 ||
       strcmp(resource, "submit_prediction") == 0 ||
       strcmp(resource, "get_predictions") == 0)) {
    out->allowed = 1;
    out->rule_id = 1;
    snprintf(out->effect, sizeof(out->effect), "%s", "allow");
    return DB_OK;
  }

  if (strcmp(action, "rate_limit.bypass") == 0 &&
      strcmp(resource, "request") == 0 && g_mock_rate_bypass) {
    out->allowed = 1;
    out->rule_id = 2;
    snprintf(out->effect, sizeof(out->effect), "%s", "allow");
    return DB_OK;
  }

  if (strcmp(action, "profile.discover.override") == 0 &&
      g_mock_discover_override && strcmp(resource, "profile:hidden") == 0) {
    out->allowed = 1;
    out->rule_id = 3;
    snprintf(out->effect, sizeof(out->effect), "%s", "allow");
    return DB_OK;
  }

  if (strcmp(action, "trust.tier") == 0 && strcmp(resource, "tier") == 0) {
    out->allowed = 1;
    out->permission_level = 0;
    out->rule_id = 4;
    snprintf(out->effect, sizeof(out->effect), "%s", "allow");
    return DB_OK;
  }
  if (strcmp(action, "prediction.submit") == 0 ||
      strcmp(action, "prediction.read") == 0) {
    out->allowed = 1;
    out->permission_level = 2;
    out->rule_id = 5;
    snprintf(out->effect, sizeof(out->effect), "%s", "allow");
    return DB_OK;
  }
  return DB_OK;
}

typedef struct {
  wamble_socket_t sock;
  struct sockaddr_in from;
  struct WambleMsg msg;
  int received;
} RecvAckCtx;

static void *recv_ack_one(void *arg) {
  network_init_thread_state();
  RecvAckCtx *c = (RecvAckCtx *)arg;
  for (int i = 0; i < 300; i++) {
    int rc = receive_message(c->sock, &c->msg, &c->from);
    if (rc > 0) {
      c->received = 1;
      send_ack(c->sock, &c->msg, &c->from);
      break;
    }
    sleep_ms(2);
  }
  return NULL;
}

static void setup_mock_query_service(void) {
  static WambleQueryService svc;
  memset(&svc, 0, sizeof(svc));
  svc.resolve_policy_decision = mock_resolve_policy_decision;
  wamble_set_query_service(&svc);
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
} RecvCtx;

static void *recv_one(void *arg) {
  network_init_thread_state();
  RecvCtx *c = (RecvCtx *)arg;
  for (int i = 0; i < 200; i++) {
    int rc = receive_message(c->sock, &c->msg, &c->from);
    if (rc > 0) {
      c->received = 1;
      break;
    }
    sleep_ms(2);
  }
  return NULL;
}

WAMBLE_TEST(spectate_update_roundtrip) {
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

  RecvCtx ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.sock = cli;
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, (wamble_thread_func_t)recv_one, &ctx) ==
           0);

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

  RecvCtx ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.sock = cli;
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, (wamble_thread_func_t)recv_one, &ctx) ==
           0);

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

WAMBLE_TEST(submit_prediction_roundtrip) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);
  struct sockaddr_in dst;
  T_ASSERT_STATUS_OK(fill_server_addr(srv, &dst));

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
  int got = -1;
  for (int i = 0; i < 200; i++) {
    int rc = receive_message(srv, &in, &from);
    if (rc > 0) {
      got = rc;
      break;
    }
    sleep_ms(2);
  }
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

  RecvCtx ctx = {0};
  ctx.sock = cli;
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, (wamble_thread_func_t)recv_one, &ctx) ==
           0);

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

typedef struct {
  wamble_socket_t sock;
  struct sockaddr_in from;
} AckPeer;

static void *ack_peer(void *arg) {
  network_init_thread_state();
  AckPeer *p = (AckPeer *)arg;
  struct WambleMsg in;
  struct sockaddr_in src;
  for (int i = 0; i < 200; i++) {
    int rc = receive_message(p->sock, &in, &src);
    if (rc > 0) {
      send_ack(p->sock, &in, &src);
      break;
    }
    sleep_ms(2);
  }
  return NULL;
}

WAMBLE_TEST(reliable_ack_success) {
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

  AckPeer peer;
  memset(&peer, 0, sizeof(peer));
  peer.sock = cli;
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, (wamble_thread_func_t)ack_peer, &peer) ==
           0);

  struct WambleMsg msg;
  memset(&msg, 0, sizeof(msg));
  msg.ctrl = WAMBLE_CTRL_BOARD_UPDATE;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    msg.token[i] = (uint8_t)(0x10 + i);
  msg.board_id = 77;
  strncpy(msg.fen, "fen-data", FEN_MAX_LENGTH);

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
  int target;
  int count;
  uint64_t deadline_ms;
} RecvManyCtx;

static void *recv_many(void *arg) {
  network_init_thread_state();
  RecvManyCtx *c = (RecvManyCtx *)arg;
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
    sleep_ms(1);
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

  RecvManyCtx ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.sock = cli;
  ctx.target = 1000;
  ctx.deadline_ms = wamble_now_mono_millis() + 5000;

  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, (wamble_thread_func_t)recv_many, &ctx) ==
           0);

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
      sleep_ms(1);
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

static void *ack_peer_many(void *arg) {
  network_init_thread_state();
  AckPeerManyCtx *p = (AckPeerManyCtx *)arg;
  struct WambleMsg in;
  struct sockaddr_in src;
  while (p->count < p->target) {
    int rc = receive_message(p->sock, &in, &src);
    if (rc > 0) {
      send_ack(p->sock, &in, &src);
      p->count++;
    } else {
      sleep_ms(1);
    }
  }
  return NULL;
}

WAMBLE_TEST(perf_reliable_ack_latency) {
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

  const int iters = 200;
  AckPeerManyCtx peer;
  memset(&peer, 0, sizeof(peer));
  peer.sock = cli;
  peer.target = iters;

  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, (wamble_thread_func_t)ack_peer_many,
                                &peer) == 0);

  struct WambleMsg msg;
  memset(&msg, 0, sizeof(msg));
  msg.ctrl = WAMBLE_CTRL_BOARD_UPDATE;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    msg.token[i] = (uint8_t)(0x10 + i);
  msg.board_id = 77;
  strncpy(msg.fen, "fen-data", FEN_MAX_LENGTH);

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

  T_ASSERT(elapsed_ns < (uint64_t)3000 * 1000000ULL);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

typedef struct {
  wamble_socket_t sock;
  int count;
  volatile int stop;
} StressRecvCtx;

static void *stress_recv_loop(void *arg) {
  network_init_thread_state();
  StressRecvCtx *c = (StressRecvCtx *)arg;
  struct WambleMsg in;
  struct sockaddr_in from;
  while (!c->stop) {
    int rc = receive_message(c->sock, &in, &from);
    if (rc > 0) {
      c->count++;
    } else {
      sleep_ms(1);
    }
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
    T_ASSERT(wamble_thread_create(
                 &th[i], (wamble_thread_func_t)stress_recv_loop, &ctx[i]) == 0);
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
      sleep_ms(1);
  }

  int drain_ms = (get_config()->select_timeout_usec / 1000) * 2;
  if (drain_ms <= 0)
    drain_ms = 200;
  sleep_ms(drain_ms);
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

static int fill_server_addr(wamble_socket_t srv, struct sockaddr_in *out) {
  struct sockaddr_in srvbind;
  wamble_socklen_t sl = (wamble_socklen_t)sizeof(srvbind);
  if (getsockname(srv, (struct sockaddr *)&srvbind, &sl) != 0)
    return 1;
  memset(out, 0, sizeof(*out));
  out->sin_family = AF_INET;
  out->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  out->sin_port = srvbind.sin_port;
  return 0;
}

WAMBLE_TEST(malformed_tiny_packet_rejected) {
  config_load(NULL, NULL, NULL, 0);
  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);
  struct sockaddr_in dst;
  T_ASSERT_STATUS_OK(fill_server_addr(srv, &dst));
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
  struct sockaddr_in dst;
  T_ASSERT_STATUS_OK(fill_server_addr(srv, &dst));
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
  struct sockaddr_in dst;
  T_ASSERT_STATUS_OK(fill_server_addr(srv, &dst));

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
  struct sockaddr_in dst;
  T_ASSERT_STATUS_OK(fill_server_addr(srv, &dst));

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
  struct sockaddr_in dst;
  T_ASSERT_STATUS_OK(fill_server_addr(srv, &dst));

  enum { H = 34 };
  enum { MC = WAMBLE_MAX_LEGAL_MOVES + 1 };
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
  struct sockaddr_in dst;
  T_ASSERT_STATUS_OK(fill_server_addr(srv, &dst));
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
  struct sockaddr_in dst;
  T_ASSERT_STATUS_OK(fill_server_addr(srv, &dst));
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
  struct sockaddr_in dst;
  T_ASSERT_STATUS_OK(fill_server_addr(srv, &dst));

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
  int got = -1;
  for (int i = 0; i < 200; i++) {
    int rc = receive_message(srv, &in, &from);
    if (rc > 0) {
      got = rc;
      break;
    }
    sleep_ms(2);
  }
  T_ASSERT(got > 0);
  T_ASSERT_EQ_INT(in.ctrl, WAMBLE_CTRL_PLAYER_MOVE);
  T_ASSERT_EQ_INT(in.uci_len, (int)strlen(uci));
  T_ASSERT_STREQ(in.uci, uci);

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
  struct sockaddr_in dst;
  T_ASSERT_STATUS_OK(fill_server_addr(srv, &dst));
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

WAMBLE_TEST(server_protocol_rate_limit_enforced_and_bypassable) {
  const char *cfg_path = "build/test_network_rate_limit.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 1)\n"
                    "(defprofile p1 ((def port 19400) (def advertise 1)))\n";
  FILE *f = fopen(cfg_path, "w");
  T_ASSERT(f != NULL);
  fwrite(cfg, 1, strlen(cfg), f);
  fclose(f);
  T_ASSERT_STATUS(config_load(cfg_path, NULL, NULL, 0), CONFIG_LOAD_OK);

  setup_mock_query_service();
  g_mock_discover_override = 0;
  g_mock_rate_bypass = 0;

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
  req.ctrl = WAMBLE_CTRL_LIST_PROFILES;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    req.token[i] = (uint8_t)(0x70 + i);

  RecvAckCtx rx1 = {0};
  rx1.sock = cli;
  wamble_thread_t th1;
  T_ASSERT(wamble_thread_create(&th1, (wamble_thread_func_t)recv_ack_one,
                                &rx1) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &req, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th1, NULL));
  T_ASSERT_EQ_INT(rx1.received, 1);
  T_ASSERT_EQ_INT(rx1.msg.ctrl, WAMBLE_CTRL_PROFILES_LIST);

  RecvAckCtx rx2 = {0};
  rx2.sock = cli;
  wamble_thread_t th2;
  T_ASSERT(wamble_thread_create(&th2, (wamble_thread_func_t)recv_ack_one,
                                &rx2) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &req, &cliaddr, 0, "p1"),
                  SERVER_ERR_FORBIDDEN);
  T_ASSERT_STATUS_OK(wamble_thread_join(th2, NULL));
  T_ASSERT_EQ_INT(rx2.received, 1);
  T_ASSERT_EQ_INT(rx2.msg.ctrl, WAMBLE_CTRL_ERROR);
  T_ASSERT_STREQ(rx2.msg.error_reason, "rate_limited");

  g_mock_rate_bypass = 1;
  RecvAckCtx rx3 = {0};
  rx3.sock = cli;
  wamble_thread_t th3;
  T_ASSERT(wamble_thread_create(&th3, (wamble_thread_func_t)recv_ack_one,
                                &rx3) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &req, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th3, NULL));
  T_ASSERT_EQ_INT(rx3.received, 1);
  T_ASSERT_EQ_INT(rx3.msg.ctrl, WAMBLE_CTRL_PROFILES_LIST);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(server_protocol_profile_discover_override_lists_hidden) {
  const char *cfg_path = "build/test_network_discover_override.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(defprofile public ((def port 19410) (def advertise 1) "
                    "(def visibility 0)))\n"
                    "(defprofile hidden ((def port 19411) (def advertise 0) "
                    "(def visibility 100)))\n";
  FILE *f = fopen(cfg_path, "w");
  T_ASSERT(f != NULL);
  fwrite(cfg, 1, strlen(cfg), f);
  fclose(f);
  T_ASSERT_STATUS(config_load(cfg_path, NULL, NULL, 0), CONFIG_LOAD_OK);

  setup_mock_query_service();
  g_mock_rate_bypass = 1;
  g_mock_discover_override = 1;

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
  req.ctrl = WAMBLE_CTRL_LIST_PROFILES;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    req.token[i] = (uint8_t)(0x20 + i);

  RecvAckCtx rx = {0};
  rx.sock = cli;
  wamble_thread_t th;
  T_ASSERT(wamble_thread_create(&th, (wamble_thread_func_t)recv_ack_one, &rx) ==
           0);
  T_ASSERT_EQ_INT(handle_message(srv, &req, &cliaddr, 0, "public"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));
  T_ASSERT_EQ_INT(rx.received, 1);
  T_ASSERT_EQ_INT(rx.msg.ctrl, WAMBLE_CTRL_PROFILES_LIST);
  T_ASSERT(strstr(rx.msg.fen, "public") != NULL);
  T_ASSERT(strstr(rx.msg.fen, "hidden") != NULL);

  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(server_protocol_prediction_submit_and_read) {
  T_ASSERT_STATUS(config_load(NULL, NULL, NULL, 0), CONFIG_LOAD_DEFAULTS);
  player_manager_init();
  board_manager_init();
  prediction_manager_init();
  setup_mock_query_service();
  g_mock_rate_bypass = 1;

  WamblePlayer *player = create_new_player();
  T_ASSERT(player != NULL);
  WambleBoard *board = find_board_for_player(player);
  T_ASSERT(board != NULL);
  memcpy(board->reservation_player_token, player->token, TOKEN_LENGTH);
  board->reserved_for_white = (board->board.turn == 'w');

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

  struct WambleMsg submit = {0};
  submit.ctrl = WAMBLE_CTRL_SUBMIT_PREDICTION;
  memcpy(submit.token, player->token, TOKEN_LENGTH);
  submit.board_id = board->id;
  submit.uci_len = 4;
  memcpy(submit.uci, "e2e4", 4);

  RecvAckCtx rx_submit = {0};
  rx_submit.sock = cli;
  wamble_thread_t th_submit;
  T_ASSERT(wamble_thread_create(&th_submit, (wamble_thread_func_t)recv_ack_one,
                                &rx_submit) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &submit, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_submit, NULL));
  T_ASSERT_EQ_INT(rx_submit.received, 1);
  T_ASSERT_EQ_INT(rx_submit.msg.ctrl, WAMBLE_CTRL_PREDICTION_DATA);
  T_ASSERT_EQ_INT((int)rx_submit.msg.prediction_count, 1);
  T_ASSERT_EQ_INT((int)rx_submit.msg.predictions[0].uci_len, 4);

  struct WambleMsg getp = {0};
  getp.ctrl = WAMBLE_CTRL_GET_PREDICTIONS;
  memcpy(getp.token, player->token, TOKEN_LENGTH);
  getp.board_id = board->id;
  getp.prediction_depth = 2;
  getp.prediction_limit = 8;

  RecvAckCtx rx_get = {0};
  rx_get.sock = cli;
  wamble_thread_t th_get;
  T_ASSERT(wamble_thread_create(&th_get, (wamble_thread_func_t)recv_ack_one,
                                &rx_get) == 0);
  T_ASSERT_EQ_INT(handle_message(srv, &getp, &cliaddr, 0, "p1"), SERVER_OK);
  T_ASSERT_STATUS_OK(wamble_thread_join(th_get, NULL));
  T_ASSERT_EQ_INT(rx_get.received, 1);
  T_ASSERT_EQ_INT(rx_get.msg.ctrl, WAMBLE_CTRL_PREDICTION_DATA);
  T_ASSERT_EQ_INT((int)rx_get.msg.prediction_count, 1);
  T_ASSERT_EQ_INT((int)rx_get.msg.predictions[0].id, 1);

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
WAMBLE_TESTS_ADD_SM(reliable_ack_success, WAMBLE_SUITE_FUNCTIONAL, "network");
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
WAMBLE_TESTS_ADD_SM(server_protocol_rate_limit_enforced_and_bypassable,
                    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_SM(server_protocol_profile_discover_override_lists_hidden,
                    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_SM(server_protocol_prediction_submit_and_read,
                    WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_SM(spectate_stop_accept, WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_SM(reserved_nonzero_rejected, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_SM(legal_moves_count_guard, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_EX_SM(perf_unreliable_throughput_local,
                       WAMBLE_SUITE_PERFORMANCE, "network", NULL, NULL, 10000);
WAMBLE_TESTS_ADD_EX_SM(perf_reliable_ack_latency, WAMBLE_SUITE_PERFORMANCE,
                       "network", NULL, NULL, 10000);
WAMBLE_TESTS_ADD_EX_SM(stress_unreliable_burst, WAMBLE_SUITE_STRESS, "network",
                       NULL, NULL, 60000);
WAMBLE_TESTS_ADD_SM(speed_token_encode_decode, WAMBLE_SUITE_SPEED, "network");
WAMBLE_TESTS_ADD_SM(token_base64url_invalid, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_SM(token_base64url_wrong_length, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_END()
