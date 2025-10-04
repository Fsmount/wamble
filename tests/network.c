#include "common/wamble_test.h"
#include "wamble/wamble.h"

static void sleep_ms(int ms) {
  struct timeval tv;
  tv.tv_sec = ms / 1000;
  tv.tv_usec = (ms % 1000) * 1000;
  select(0, NULL, NULL, NULL, &tv);
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

  uint64_t start_ms = wamble_now_mono_millis();
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

  uint64_t end_ms = wamble_now_mono_millis();
  uint64_t elapsed = end_ms - start_ms;
  double throughput =
      (elapsed > 0) ? ((double)ctx.count * 1000.0 / (double)elapsed) : 0.0;
  wamble_metric("perf_unreliable_throughput",
                "msgs=%d received=%d elapsed_ms=%llu throughput=%.2f msg/s",
                ctx.target, ctx.count, (unsigned long long)elapsed, throughput);
  T_ASSERT(ctx.count >= (ctx.target * 98) / 100);
  T_ASSERT(elapsed < 2500);

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

  uint64_t start_ms = wamble_now_mono_millis();
  for (int i = 0; i < iters; i++) {
    int rc =
        send_reliable_message(srv, &msg, &cliaddr, get_config()->timeout_ms,
                              get_config()->max_retries);
    T_ASSERT_STATUS_OK(rc);
  }
  uint64_t end_ms = wamble_now_mono_millis();
  T_ASSERT_STATUS_OK(wamble_thread_join(th, NULL));

  uint64_t elapsed = end_ms - start_ms;
  double avg_ms = (iters > 0) ? ((double)elapsed / (double)iters) : 0.0;
  double tput =
      (elapsed > 0) ? ((double)iters * 1000.0 / (double)elapsed) : 0.0;
  wamble_metric("perf_reliable_ack_latency",
                "iters=%d elapsed_ms=%llu avg_ms=%.3f throughput=%.2f msg/s",
                iters, (unsigned long long)elapsed, avg_ms, tput);

  T_ASSERT(elapsed < 3000);

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
  double start = (double)wamble_now_wall();
  int iters = 20000;
  for (int i = 0; i < iters; i++) {
    format_token_for_url(token, url);
    T_ASSERT_STATUS_OK(decode_token_from_url(url, out));
    T_ASSERT_EQ_INT((int)strlen(url), 22);
  }
  double end = (double)wamble_now_wall();
  double ms = (end - start) * 1000.0;
  double ops_per_sec = (ms > 0.0) ? ((double)iters * 1000.0 / ms) : 0.0;
  wamble_metric("speed_token_encode_decode",
                "iters=%d elapsed_ms=%.2f ops_per_sec=%.2f", iters, ms,
                ops_per_sec);
  T_ASSERT(ms < 2000.0);
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

WAMBLE_TESTS_BEGIN()
WAMBLE_TESTS_ADD_SM(token_base64url_roundtrip, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_SM(spectate_update_roundtrip, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_SM(reliable_ack_success, WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_SM(malformed_tiny_packet_rejected, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_SM(unknown_ctrl_rejected, WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_SM(player_move_uci_len_guard, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_SM(zero_token_rejected, WAMBLE_SUITE_FUNCTIONAL, "network");
WAMBLE_TESTS_ADD_SM(player_move_valid_uci_accept, WAMBLE_SUITE_FUNCTIONAL,
                    "network");
WAMBLE_TESTS_ADD_EX_SM(perf_unreliable_throughput_local,
                       WAMBLE_SUITE_PERFORMANCE, "network", NULL, NULL, 10000);
WAMBLE_TESTS_ADD_EX_SM(perf_reliable_ack_latency, WAMBLE_SUITE_PERFORMANCE,
                       "network", NULL, NULL, 10000);
WAMBLE_TESTS_ADD_EX_SM(stress_unreliable_burst, WAMBLE_SUITE_STRESS, "network",
                       NULL, NULL, 60000);
WAMBLE_TESTS_ADD_SM(speed_token_encode_decode, WAMBLE_SUITE_SPEED, "network");
WAMBLE_TESTS_END()
