#ifdef TEST_NETWORK

#include "../../include/wamble/wamble.h"
#include "../network.c"
#include <string.h>

static int g_stub_player_enabled = 0;
static WamblePlayer g_stub_player;
WamblePlayer *get_player_by_token(const uint8_t *token) {
  (void)token;
  return g_stub_player_enabled ? &g_stub_player : NULL;
}

typedef struct {
  wamble_socket_t server;
  struct sockaddr_in client_addr;
  int behavior;
  struct {
    uint8_t last_flags;
    struct WambleMsg last_msg;
  } out;
} PeerCtx;

#ifdef WAMBLE_PLATFORM_WINDOWS
static DWORD WINAPI client_peer(void *arg)
#else
static void *client_peer(void *arg)
#endif
{
  PeerCtx *ctx = (PeerCtx *)arg;
  wamble_socket_t cs = socket(AF_INET, SOCK_DGRAM, 0);
  (void)wamble_set_nonblocking(cs);
  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  bind(cs, (struct sockaddr *)&bindaddr, sizeof(bindaddr));
  wamble_socklen_t slen = sizeof(ctx->client_addr);
  getsockname(cs, (struct sockaddr *)&ctx->client_addr, &slen);
  for (int i = 0; i < 4; i++) {
    uint8_t buf[WAMBLE_MAX_PACKET_SIZE];
    struct sockaddr_in from;
    wamble_socklen_t flen = sizeof(from);
    ssize_t n = recvfrom(cs, (char *)buf, sizeof(buf), 0,
                         (struct sockaddr *)&from, &flen);
    if (n <= 0) {
      struct timespec ts = {.tv_sec = 0, .tv_nsec = 2000000};
      nanosleep(&ts, NULL);
      continue;
    }
    struct WambleMsg m = {0};
    uint8_t flags = 0;
    if (deserialize_wamble_msg(buf, (size_t)n, &m, &flags) != 0)
      continue;
    ctx->out.last_flags = flags;
    ctx->out.last_msg = m;
    if (m.ctrl != WAMBLE_CTRL_ACK && (flags & WAMBLE_FLAG_UNRELIABLE) == 0) {
      struct WambleMsg ack = {0};
      ack.ctrl = WAMBLE_CTRL_ACK;
      memcpy(ack.token, m.token, TOKEN_LENGTH);
      ack.board_id = m.board_id;
      ack.seq_num = m.seq_num;
      uint8_t sbuf[WAMBLE_MAX_PACKET_SIZE];
      size_t ssz = 0;
      if (ctx->behavior == 1) {
        ack.seq_num = m.seq_num + 1;
        serialize_wamble_msg(&ack, sbuf, sizeof sbuf, &ssz, 0);
        sendto(cs, (const char *)sbuf, (size_t)ssz, 0, (struct sockaddr *)&from,
               sizeof(from));
        ack.seq_num = m.seq_num;
      }
      serialize_wamble_msg(&ack, sbuf, sizeof sbuf, &ssz, 0);
      sendto(cs, (const char *)sbuf, (size_t)ssz, 0, (struct sockaddr *)&from,
             sizeof(from));
    }
  }
  wamble_close_socket(cs);
#ifdef WAMBLE_PLATFORM_WINDOWS
  return 0;
#else
  return NULL;
#endif
}

static void test_sleep_ms(int ms) {
  struct timeval tv;
  tv.tv_sec = ms / 1000;
  tv.tv_usec = (ms % 1000) * 1000;
  select(0, NULL, NULL, NULL, &tv);
}

static int test_reliable_ack_success(void) {
  PeerCtx ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.behavior = 0;
  wamble_socket_t srv = create_and_bind_socket(0);
  if (srv == WAMBLE_INVALID_SOCKET) {
    printf("reliable_ack_success FAILED: server bind\n");
    return 0;
  }
  ctx.server = srv;
  wamble_thread_t th;
  wamble_thread_create(&th, (wamble_thread_func_t)client_peer, &ctx);
  struct WambleMsg out = {0};
  out.ctrl = WAMBLE_CTRL_BOARD_UPDATE;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(i + 1);
  out.board_id = 77;
  strncpy(out.fen, "fen-data", FEN_MAX_LENGTH);
  for (int i = 0; i < 50 && ctx.client_addr.sin_port == 0; i++) {
    test_sleep_ms(2);
  }
  int rc = send_reliable_message(srv, &out, &ctx.client_addr,
                                 get_config()->timeout_ms,
                                 get_config()->max_retries);
  wamble_close_socket(srv);
  wamble_thread_join(th, NULL);
  if (rc != 0) {
    printf("reliable_ack_success FAILED: rc=%d\n", rc);
    return 0;
  }
  return 1;
}

static int test_reliable_bad_then_good_ack(void) {
  PeerCtx ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.behavior = 1;
  wamble_socket_t srv = create_and_bind_socket(0);
  if (srv == WAMBLE_INVALID_SOCKET) {
    printf("bad_then_good FAILED: server bind\n");
    return 0;
  }
  ctx.server = srv;
  wamble_thread_t th;
  wamble_thread_create(&th, (wamble_thread_func_t)client_peer, &ctx);
  struct WambleMsg out = {0};
  out.ctrl = WAMBLE_CTRL_SERVER_HELLO;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(0x10 + i);
  out.board_id = 99;
  strncpy(out.fen, "fen-2", FEN_MAX_LENGTH);
  for (int i = 0; i < 50 && ctx.client_addr.sin_port == 0; i++) {
    test_sleep_ms(2);
  }
  int rc = send_reliable_message(srv, &out, &ctx.client_addr,
                                 get_config()->timeout_ms,
                                 get_config()->max_retries);
  wamble_close_socket(srv);
  wamble_thread_join(th, NULL);
  if (rc != 0) {
    printf("bad_then_good FAILED: rc=%d\n", rc);
    return 0;
  }
  return 1;
}

static int test_unreliable_spectate_update_io(void) {
  PeerCtx ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.behavior = 2;
  wamble_socket_t srv = create_and_bind_socket(0);
  if (srv == WAMBLE_INVALID_SOCKET) {
    printf("unreliable_io FAILED: bind\n");
    return 0;
  }
  ctx.server = srv;
  wamble_thread_t th;
  wamble_thread_create(&th, (wamble_thread_func_t)client_peer, &ctx);
  struct WambleMsg out = {0};
  out.ctrl = WAMBLE_CTRL_SPECTATE_UPDATE;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    out.token[i] = (uint8_t)(0x20 + i);
  out.board_id = 1234;
  out.seq_num = 0;
  out.flags = WAMBLE_FLAG_UNRELIABLE;
  strncpy(out.fen, "fen-io", FEN_MAX_LENGTH);
  for (int i = 0; i < 50 && ctx.client_addr.sin_port == 0; i++) {
    test_sleep_ms(2);
  }
  int rc = send_unreliable_packet(srv, &out, &ctx.client_addr);
  wamble_close_socket(srv);
  wamble_thread_join(th, NULL);
  if (rc != 0)
    return printf("unreliable_io FAILED: send rc=%d\n", rc), 0;
  if (ctx.out.last_msg.ctrl != WAMBLE_CTRL_SPECTATE_UPDATE ||
      ctx.out.last_msg.board_id != 1234)
    return printf("unreliable_io FAILED: recv mismatch\n"), 0;
  if (ctx.out.last_flags != WAMBLE_FLAG_UNRELIABLE)
    return printf("unreliable_io FAILED: flags\n"), 0;
  return 1;
}

static int test_spectate_update_roundtrip(void) {
  struct WambleMsg in = {0};
  in.ctrl = WAMBLE_CTRL_SPECTATE_UPDATE;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    in.token[i] = (uint8_t)(i + 1);
  in.board_id = 123456789ULL;
  in.seq_num = 0;
  strncpy(in.fen, "startpos", FEN_MAX_LENGTH);

  uint8_t buf[WAMBLE_MAX_PACKET_SIZE];
  size_t out_len = 0;
  if (serialize_wamble_msg(&in, buf, sizeof buf, &out_len,
                           WAMBLE_FLAG_UNRELIABLE) != 0) {
    printf("spectate_update_roundtrip FAILED: serialize error\n");
    return 0;
  }

  struct WambleMsg out = {0};
  uint8_t flags = 0;
  if (deserialize_wamble_msg(buf, out_len, &out, &flags) != 0) {
    printf("spectate_update_roundtrip FAILED: deserialize error\n");
    return 0;
  }
  if (out.ctrl != WAMBLE_CTRL_SPECTATE_UPDATE) {
    printf("spectate_update_roundtrip FAILED: ctrl mismatch\n");
    return 0;
  }
  if (out.board_id != 123456789ULL) {
    printf("spectate_update_roundtrip FAILED: board_id mismatch\n");
    return 0;
  }
  if (flags != WAMBLE_FLAG_UNRELIABLE) {
    printf("spectate_update_roundtrip FAILED: flags mismatch\n");
    return 0;
  }
  if (strncmp(out.fen, "startpos", FEN_MAX_LENGTH) != 0) {
    printf("spectate_update_roundtrip FAILED: fen mismatch\n");
    return 0;
  }
  return 1;
}

static int test_spectate_game_empty_payload(void) {
  struct WambleMsg in = {0};
  in.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    in.token[i] = (uint8_t)(i + 1);
  in.board_id = 0;
  in.seq_num = 42;

  uint8_t buf[WAMBLE_MAX_PACKET_SIZE];
  size_t out_len = 0;
  if (serialize_wamble_msg(&in, buf, sizeof buf, &out_len, 0) != 0) {
    printf("spectate_game_empty_payload FAILED: serialize error\n");
    return 0;
  }
  struct WambleMsg out = {0};
  if (deserialize_wamble_msg(buf, out_len, &out, NULL) != 0) {
    printf("spectate_game_empty_payload FAILED: deserialize error\n");
    return 0;
  }
  if (out.ctrl != WAMBLE_CTRL_SPECTATE_GAME || out.board_id != 0) {
    printf("spectate_game_empty_payload FAILED: header mismatch\n");
    return 0;
  }
  if (out.fen[0] != '\0') {
    printf("spectate_game_empty_payload FAILED: expected empty fen payload\n");
    return 0;
  }
  return 1;
}

static int test_player_move_uci_len_guard(void) {
  uint8_t buf[WAMBLE_MAX_PACKET_SIZE];
  struct WambleMsg in = {0};
  in.ctrl = WAMBLE_CTRL_PLAYER_MOVE;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    in.token[i] = 1;
  in.board_id = 7;
  in.seq_num = 1;
  in.uci_len = (uint8_t)(MAX_UCI_LENGTH + 1);
  memset(in.uci, 'a', sizeof in.uci);

  size_t out_len = 0;

  if (serialize_wamble_msg(&in, buf, sizeof buf, &out_len, 0) != 0) {
    printf("player_move_uci_len_guard FAILED: serialize error\n");
    return 0;
  }
  struct WambleMsg out = {0};

  if (deserialize_wamble_msg(buf, out_len, &out, NULL) == 0) {
    printf("player_move_uci_len_guard FAILED: expected deserialize failure\n");
    return 0;
  }
  return 1;
}

static int test_server_and_board_update_roundtrip(void) {
  struct {
    uint8_t ctrl;
    const char *fen;
  } cases[] = {{WAMBLE_CTRL_SERVER_HELLO, "hello-fen"},
               {WAMBLE_CTRL_BOARD_UPDATE, "board-fen"}};
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    struct WambleMsg in = {0};
    in.ctrl = cases[i].ctrl;
    in.board_id = 55 + (uint64_t)i;
    strncpy(in.fen, cases[i].fen, FEN_MAX_LENGTH);
    uint8_t buf[WAMBLE_MAX_PACKET_SIZE];
    size_t out_len = 0;
    if (serialize_wamble_msg(&in, buf, sizeof buf, &out_len, 0) != 0) {
      printf("server_board_update_roundtrip FAILED: serialize error\n");
      return 0;
    }
    struct WambleMsg out = {0};
    if (deserialize_wamble_msg(buf, out_len, &out, NULL) != 0) {
      printf("server_board_update_roundtrip FAILED: deserialize error\n");
      return 0;
    }
    if (out.ctrl != cases[i].ctrl || out.board_id != (55 + (uint64_t)i) ||
        strcmp(out.fen, cases[i].fen) != 0) {
      printf("server_board_update_roundtrip FAILED: mismatch case %zu\n", i);
      return 0;
    }
  }
  return 1;
}

static int test_profiles_payloads(void) {

  struct WambleMsg in = {0};
  in.ctrl = WAMBLE_CTRL_PROFILE_INFO;
  strncpy(in.fen, "name;8891;1;0", FEN_MAX_LENGTH);
  uint8_t buf[WAMBLE_MAX_PACKET_SIZE];
  size_t out_len = 0;
  if (serialize_wamble_msg(&in, buf, sizeof buf, &out_len, 0) != 0)
    return printf("profiles_payloads FAILED: serialize profile_info\n"), 0;
  struct WambleMsg out = {0};
  if (deserialize_wamble_msg(buf, out_len, &out, NULL) != 0)
    return printf("profiles_payloads FAILED: deserialize profile_info\n"), 0;
  if (strcmp(out.fen, "name;8891;1;0") != 0)
    return printf("profiles_payloads FAILED: profile_info mismatch\n"), 0;

  memset(&in, 0, sizeof in);
  in.ctrl = WAMBLE_CTRL_PROFILES_LIST;
  strncpy(in.fen, "alpha,beta,gamma", FEN_MAX_LENGTH);
  if (serialize_wamble_msg(&in, buf, sizeof buf, &out_len, 0) != 0)
    return printf("profiles_payloads FAILED: serialize profiles_list\n"), 0;
  memset(&out, 0, sizeof out);
  if (deserialize_wamble_msg(buf, out_len, &out, NULL) != 0)
    return printf("profiles_payloads FAILED: deserialize profiles_list\n"), 0;
  if (strcmp(out.fen, "alpha,beta,gamma") != 0)
    return printf("profiles_payloads FAILED: profiles_list mismatch\n"), 0;

  memset(&in, 0, sizeof in);
  in.ctrl = WAMBLE_CTRL_GET_PROFILE_INFO;
  const char *name = "delta";
  in.uci_len = (uint8_t)strlen(name);
  memcpy(in.uci, name, in.uci_len);
  if (serialize_wamble_msg(&in, buf, sizeof buf, &out_len, 0) != 0)
    return printf("profiles_payloads FAILED: serialize get_profile_info\n"), 0;
  memset(&out, 0, sizeof out);
  if (deserialize_wamble_msg(buf, out_len, &out, NULL) != 0)
    return printf("profiles_payloads FAILED: deserialize get_profile_info\n"),
           0;
  if (out.ctrl != WAMBLE_CTRL_GET_PROFILE_INFO || out.uci_len != strlen(name) ||
      memcmp(out.uci, name, out.uci_len) != 0)
    return printf("profiles_payloads FAILED: get_profile_info mismatch\n"), 0;

  return 1;
}

static int test_login_payloads(void) {

  struct WambleMsg in = {0};
  in.ctrl = WAMBLE_CTRL_LOGIN_REQUEST;
  for (int i = 0; i < 32; i++)
    in.login_pubkey[i] = (uint8_t)(i + 10);
  uint8_t buf[WAMBLE_MAX_PACKET_SIZE];
  size_t out_len = 0;
  if (serialize_wamble_msg(&in, buf, sizeof buf, &out_len, 0) != 0)
    return printf("login_payloads FAILED: serialize login_request\n"), 0;
  struct WambleMsg out = {0};
  if (deserialize_wamble_msg(buf, out_len, &out, NULL) != 0)
    return printf("login_payloads FAILED: deserialize login_request\n"), 0;
  if (memcmp(out.login_pubkey, in.login_pubkey, 32) != 0)
    return printf("login_payloads FAILED: login_pubkey mismatch\n"), 0;

  memset(&in, 0, sizeof in);
  in.ctrl = WAMBLE_CTRL_LOGIN_FAILED;
  in.error_code = 7;
  strncpy(in.error_reason, "nope", sizeof in.error_reason);
  if (serialize_wamble_msg(&in, buf, sizeof buf, &out_len, 0) != 0)
    return printf("login_payloads FAILED: serialize login_failed\n"), 0;
  memset(&out, 0, sizeof out);
  if (deserialize_wamble_msg(buf, out_len, &out, NULL) != 0)
    return printf("login_payloads FAILED: deserialize login_failed\n"), 0;
  if (out.error_code != 7 || strcmp(out.error_reason, "nope") != 0)
    return printf("login_payloads FAILED: login_failed mismatch\n"), 0;
  return 1;
}

static int test_player_stats_data_serialize(void) {

  memset(&g_stub_player, 0, sizeof g_stub_player);
  g_stub_player.score = 1234.5;
  g_stub_player.games_played = 42;
  g_stub_player_enabled = 1;

  struct WambleMsg in = {0};
  in.ctrl = WAMBLE_CTRL_PLAYER_STATS_DATA;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    in.token[i] = (uint8_t)(i + 1);

  uint8_t buf[WAMBLE_MAX_PACKET_SIZE];
  size_t out_len = 0;
  if (serialize_wamble_msg(&in, buf, sizeof buf, &out_len, 0) != 0) {
    printf("player_stats_data_serialize FAILED: serialize error\n");
    g_stub_player_enabled = 0;
    return 0;
  }

  if (out_len < WAMBLE_HEADER_SIZE + 12) {
    printf("player_stats_data_serialize FAILED: payload too small\n");
    g_stub_player_enabled = 0;
    return 0;
  }
  const uint8_t *payload = buf + WAMBLE_HEADER_SIZE;

  uint64_t bits = 0;
  memcpy(&bits, &g_stub_player.score, sizeof(double));
  uint64_t be = host_to_net64(bits);
  for (int i = 0; i < 8; i++) {
    if (payload[i] != (uint8_t)((be >> (8 * (7 - i))) & 0xFF)) {
      printf("player_stats_data_serialize FAILED: score bytes mismatch\n");
      g_stub_player_enabled = 0;
      return 0;
    }
  }
  uint32_t gp_be = htonl((uint32_t)g_stub_player.games_played);
  if (memcmp(payload + 8, &gp_be, 4) != 0) {
    printf("player_stats_data_serialize FAILED: games bytes mismatch\n");
    g_stub_player_enabled = 0;
    return 0;
  }
  g_stub_player_enabled = 0;
  return 1;
}

static int test_error_payload_roundtrip_short(void) {
  struct WambleMsg in = {0};
  in.ctrl = WAMBLE_CTRL_ERROR;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    in.token[i] = (uint8_t)(i + 3);
  in.error_code = 1234;
  strncpy(in.error_reason, "hello world", sizeof in.error_reason);

  uint8_t buf[WAMBLE_MAX_PACKET_SIZE];
  size_t out_len = 0;
  if (serialize_wamble_msg(&in, buf, sizeof buf, &out_len, 0) != 0) {
    printf("error_payload_roundtrip_short FAILED: serialize error\n");
    return 0;
  }
  struct WambleMsg out = {0};
  if (deserialize_wamble_msg(buf, out_len, &out, NULL) != 0) {
    printf("error_payload_roundtrip_short FAILED: deserialize error\n");
    return 0;
  }
  if (out.ctrl != WAMBLE_CTRL_ERROR || out.error_code != 1234) {
    printf("error_payload_roundtrip_short FAILED: header/code mismatch\n");
    return 0;
  }
  if (strcmp(out.error_reason, "hello world") != 0) {
    printf("error_payload_roundtrip_short FAILED: reason mismatch\n");
    return 0;
  }
  return 1;
}

static int test_error_payload_truncation(void) {
  struct WambleMsg in = {0};
  in.ctrl = WAMBLE_CTRL_ERROR;
  in.error_code = 42;

  char big[600];
  for (int i = 0; i < (int)sizeof(big) - 1; i++)
    big[i] = 'a';
  big[sizeof(big) - 1] = '\0';
  strncpy(in.error_reason, big, sizeof in.error_reason);

  uint8_t buf[WAMBLE_MAX_PACKET_SIZE];
  size_t out_len = 0;
  if (serialize_wamble_msg(&in, buf, sizeof buf, &out_len, 0) != 0) {
    printf("error_payload_truncation FAILED: serialize error\n");
    return 0;
  }
  struct WambleMsg out = {0};
  if (deserialize_wamble_msg(buf, out_len, &out, NULL) != 0) {
    printf("error_payload_truncation FAILED: deserialize error\n");
    return 0;
  }

  int expect_len = FEN_MAX_LENGTH - 1;
  if ((int)strlen(out.error_reason) != expect_len) {
    printf("error_payload_truncation FAILED: expected len %d, got %zu\n",
           expect_len, strlen(out.error_reason));
    return 0;
  }
  for (int i = 0; i < expect_len; i++) {
    if (out.error_reason[i] != 'a') {
      printf("error_payload_truncation FAILED: content mismatch at %d\n", i);
      return 0;
    }
  }
  return 1;
}

static int test_server_notification_unreliable_flag(void) {
  struct WambleMsg in = {0};
  in.ctrl = WAMBLE_CTRL_SERVER_NOTIFICATION;
  strncpy(in.fen, "hi there!", FEN_MAX_LENGTH);

  uint8_t buf[WAMBLE_MAX_PACKET_SIZE];
  size_t out_len = 0;
  if (serialize_wamble_msg(&in, buf, sizeof buf, &out_len,
                           WAMBLE_FLAG_UNRELIABLE) != 0) {
    printf("server_notification_unreliable_flag FAILED: serialize error\n");
    return 0;
  }
  struct WambleMsg out = {0};
  uint8_t flags = 0;
  if (deserialize_wamble_msg(buf, out_len, &out, &flags) != 0) {
    printf("server_notification_unreliable_flag FAILED: deserialize error\n");
    return 0;
  }
  if (out.ctrl != WAMBLE_CTRL_SERVER_NOTIFICATION) {
    printf("server_notification_unreliable_flag FAILED: ctrl mismatch\n");
    return 0;
  }
  if (flags != WAMBLE_FLAG_UNRELIABLE) {
    printf("server_notification_unreliable_flag FAILED: flags mismatch\n");
    return 0;
  }
  if (strcmp(out.fen, "hi there!") != 0) {
    printf("server_notification_unreliable_flag FAILED: text mismatch\n");
    return 0;
  }
  return 1;
}

static int test_capability_flags_roundtrip(void) {
  struct WambleMsg in = {0};
  in.ctrl = WAMBLE_CTRL_SERVER_HELLO;
  in.flags = (uint8_t)(WAMBLE_CAP_HOT_RELOAD | WAMBLE_CAP_PROFILE_STATE);
  in.header_version = 3;
  strncpy(in.fen, "cap", FEN_MAX_LENGTH);

  uint8_t buf[WAMBLE_MAX_PACKET_SIZE];
  size_t out_len = 0;
  if (serialize_wamble_msg(&in, buf, sizeof buf, &out_len, in.flags) != 0) {
    printf("capability_flags_roundtrip FAILED: serialize error\n");
    return 0;
  }
  struct WambleMsg out = {0};
  uint8_t flags = 0;
  if (deserialize_wamble_msg(buf, out_len, &out, &flags) != 0) {
    printf("capability_flags_roundtrip FAILED: deserialize error\n");
    return 0;
  }
  uint8_t expected =
      (uint8_t)(WAMBLE_CAP_HOT_RELOAD | WAMBLE_CAP_PROFILE_STATE);
  if (flags != expected) {
    printf(
        "capability_flags_roundtrip FAILED: expected flags 0x%02x got 0x%02x\n",
        expected, flags);
    return 0;
  }
  if (out.ctrl != WAMBLE_CTRL_SERVER_HELLO) {
    printf("capability_flags_roundtrip FAILED: ctrl mismatch\n");
    return 0;
  }
  if (out.header_version != 3) {
    printf("capability_flags_roundtrip FAILED: header version mismatch\n");
    return 0;
  }
  return 1;
}

static int test_get_legal_moves_roundtrip(void) {
  struct WambleMsg in = {0};
  in.ctrl = WAMBLE_CTRL_GET_LEGAL_MOVES;
  in.board_id = 314;
  in.move_square = 27;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    in.token[i] = (uint8_t)(0x20 + i);

  uint8_t buf[WAMBLE_MAX_PACKET_SIZE];
  size_t out_len = 0;
  if (serialize_wamble_msg(&in, buf, sizeof buf, &out_len, 0) != 0) {
    printf("get_legal_moves_roundtrip FAILED: serialize error\n");
    return 0;
  }

  struct WambleMsg out = {0};
  if (deserialize_wamble_msg(buf, out_len, &out, NULL) != 0) {
    printf("get_legal_moves_roundtrip FAILED: deserialize error\n");
    return 0;
  }
  if (out.ctrl != WAMBLE_CTRL_GET_LEGAL_MOVES || out.board_id != in.board_id ||
      out.move_square != in.move_square) {
    printf("get_legal_moves_roundtrip FAILED: header mismatch\n");
    return 0;
  }
  if (memcmp(out.token, in.token, TOKEN_LENGTH) != 0) {
    printf("get_legal_moves_roundtrip FAILED: token mismatch\n");
    return 0;
  }
  return 1;
}

static int test_legal_moves_payload_roundtrip(void) {
  struct WambleMsg in = {0};
  in.ctrl = WAMBLE_CTRL_LEGAL_MOVES;
  in.board_id = 2718;
  in.move_square = 12;
  in.move_count = 3;
  in.moves[0].from = 12;
  in.moves[0].to = 20;
  in.moves[0].promotion = 0;
  in.moves[1].from = 12;
  in.moves[1].to = 28;
  in.moves[1].promotion = 0;
  in.moves[2].from = 12;
  in.moves[2].to = 21;
  in.moves[2].promotion = 'q';
  for (int i = 0; i < TOKEN_LENGTH; i++)
    in.token[i] = (uint8_t)(0xA0 + i);

  uint8_t buf[WAMBLE_MAX_PACKET_SIZE];
  size_t out_len = 0;
  if (serialize_wamble_msg(&in, buf, sizeof buf, &out_len, 0) != 0) {
    printf("legal_moves_payload_roundtrip FAILED: serialize error\n");
    return 0;
  }

  struct WambleMsg out = {0};
  if (deserialize_wamble_msg(buf, out_len, &out, NULL) != 0) {
    printf("legal_moves_payload_roundtrip FAILED: deserialize error\n");
    return 0;
  }
  if (out.ctrl != WAMBLE_CTRL_LEGAL_MOVES || out.board_id != in.board_id ||
      out.move_square != in.move_square || out.move_count != in.move_count) {
    printf("legal_moves_payload_roundtrip FAILED: header mismatch\n");
    return 0;
  }
  for (uint8_t i = 0; i < out.move_count; i++) {
    if (out.moves[i].from != in.moves[i].from ||
        out.moves[i].to != in.moves[i].to ||
        out.moves[i].promotion != in.moves[i].promotion) {
      printf("legal_moves_payload_roundtrip FAILED: move %u mismatch\n", i);
      return 0;
    }
  }
  if (memcmp(out.token, in.token, TOKEN_LENGTH) != 0) {
    printf("legal_moves_payload_roundtrip FAILED: token mismatch\n");
    return 0;
  }
  return 1;
}

static int test_ack_roundtrip(void) {
  struct WambleMsg in = {0};
  in.ctrl = WAMBLE_CTRL_ACK;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    in.token[i] = (uint8_t)(0xAA + i);
  in.board_id = 999;
  in.seq_num = 7777;

  uint8_t buf[WAMBLE_MAX_PACKET_SIZE];
  size_t out_len = 0;
  if (serialize_wamble_msg(&in, buf, sizeof buf, &out_len, 0) != 0) {
    printf("ack_roundtrip FAILED: serialize error\n");
    return 0;
  }
  struct WambleMsg out = {0};
  if (deserialize_wamble_msg(buf, out_len, &out, NULL) != 0) {
    printf("ack_roundtrip FAILED: deserialize error\n");
    return 0;
  }
  if (out.ctrl != WAMBLE_CTRL_ACK || out.seq_num != 7777 ||
      out.board_id != 999) {
    printf("ack_roundtrip FAILED: header mismatch\n");
    return 0;
  }
  return 1;
}

static int test_token_base64url_roundtrip(void) {
  uint8_t token[TOKEN_LENGTH];
  for (int i = 0; i < TOKEN_LENGTH; i++)
    token[i] = (uint8_t)(i * 7 + 3);
  char url[23];
  format_token_for_url(token, url);
  uint8_t out[TOKEN_LENGTH];
  if (decode_token_from_url(url, out) != 0) {
    printf("token_base64url_roundtrip FAILED: decode error\n");
    return 0;
  }
  if (memcmp(token, out, TOKEN_LENGTH) != 0) {
    printf("token_base64url_roundtrip FAILED: mismatch\n");
    return 0;
  }
  return 1;
}

static int test_header_endianness(void) {
  struct WambleMsg in = {0};
  in.ctrl = WAMBLE_CTRL_BOARD_UPDATE;
  in.board_id = 0x0123456789ABCDEFULL;
  in.seq_num = 0x00FEDCBA;
  strncpy(in.fen, "x", FEN_MAX_LENGTH);

  uint8_t buf[WAMBLE_MAX_PACKET_SIZE];
  size_t out_len = 0;
  if (serialize_wamble_msg(&in, buf, sizeof buf, &out_len, 0) != 0) {
    printf("header_endianness FAILED: serialize error\n");
    return 0;
  }
  struct WambleMsg out = {0};
  if (deserialize_wamble_msg(buf, out_len, &out, NULL) != 0) {
    printf("header_endianness FAILED: deserialize error\n");
    return 0;
  }
  if (out.board_id != 0x0123456789ABCDEFULL || out.seq_num != 0x00FEDCBA) {
    printf("header_endianness FAILED: mismatch\n");
    return 0;
  }
  return 1;
}

typedef struct {
  const char *name;
  int (*fn)(void);
} Case;

static int run_case(const Case *c) {
  if (c->fn()) {
    return 1;
  }
  printf("%s FAILED\n", c->name);
  return 0;
}

int main(int argc, char **argv) {
  const char *filter = (argc > 1 ? argv[1] : "");
  int pass = 0, total = 0;

  const Case cases[] = {
      {"spectate_update_roundtrip", test_spectate_update_roundtrip},
      {"spectate_game_empty_payload", test_spectate_game_empty_payload},
      {"player_move_uci_len_guard", test_player_move_uci_len_guard},
      {"server_and_board_update_roundtrip",
       test_server_and_board_update_roundtrip},
      {"profiles_payloads", test_profiles_payloads},
      {"login_payloads", test_login_payloads},
      {"player_stats_data_serialize", test_player_stats_data_serialize},
      {"error_payload_roundtrip_short", test_error_payload_roundtrip_short},
      {"error_payload_truncation", test_error_payload_truncation},
      {"server_notification_unreliable_flag",
       test_server_notification_unreliable_flag},
      {"get_legal_moves_roundtrip", test_get_legal_moves_roundtrip},
      {"legal_moves_payload_roundtrip", test_legal_moves_payload_roundtrip},
      {"ack_roundtrip", test_ack_roundtrip},
      {"token_base64url_roundtrip", test_token_base64url_roundtrip},
      {"header_endianness", test_header_endianness},
      {"capability_flags_roundtrip", test_capability_flags_roundtrip},
  };

  for (size_t i = 0; i < (sizeof(cases) / sizeof((cases)[0])); ++i) {
    if (*filter && !strstr(cases[i].name, filter))
      continue;

    ++total;
    if (run_case(&cases[i])) {
      printf("%s PASSED\n", cases[i].name);
      ++pass;
    }
  }
  printf("%d/%d passed\n", pass, total);
  return (pass == total) ? 0 : 1;
}
#endif
