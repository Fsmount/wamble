#include "common/wamble_test.h"
#include "common/wamble_test_helpers.h"
#include "wamble/wamble.h"
#include "wamble/wamble_client.h"

#if defined(WAMBLE_PLATFORM_POSIX)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

static WsGatewayStatus g_last_ws_status = WS_GATEWAY_OK;
static int g_last_ws_port = 0;
static WambleWsGateway *g_test_gateway = NULL;
static wamble_socket_t g_test_client = WAMBLE_INVALID_SOCKET;

static void ws_close_tracked_socket(wamble_socket_t *sock) {
  if (!sock || *sock == WAMBLE_INVALID_SOCKET)
    return;
  wamble_close_socket(*sock);
  *sock = WAMBLE_INVALID_SOCKET;
}

static void ws_test_setup(void) {
  g_test_gateway = NULL;
  g_test_client = WAMBLE_INVALID_SOCKET;
  (void)wamble_net_init();
}

static void ws_test_teardown(void) {
  ws_close_tracked_socket(&g_test_client);
  if (g_test_gateway) {
    ws_gateway_stop(g_test_gateway);
    g_test_gateway = NULL;
  }
  wamble_net_cleanup();
}

static int ws_alloc_port(void) {
  wamble_socket_t sock = create_and_bind_socket(0);
  if (sock == WAMBLE_INVALID_SOCKET)
    return -1;
  {
    int port = wamble_socket_bound_port(sock);
    wamble_close_socket(sock);
    return port;
  }
}

static int ws_start_gateway(int *out_port) {
  if (!out_port)
    return -1;
  for (int i = 0; i < 64; i++) {
    int port = ws_alloc_port();
    if (port <= 0) {
      g_last_ws_status = WS_GATEWAY_ERR_BIND;
      g_last_ws_port = -1;
      return -1;
    }
    g_last_ws_port = port;
    g_test_gateway =
        ws_gateway_start("test", port, 1, "/ws", 8, &g_last_ws_status);
    if (g_test_gateway) {
      *out_port = port;
      return 0;
    }
    if (g_last_ws_status != WS_GATEWAY_ERR_BIND)
      return -1;
  }
  return -1;
}

static wamble_socket_t ws_connect_loopback(int port) {
  wamble_socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == WAMBLE_INVALID_SOCKET)
    return WAMBLE_INVALID_SOCKET;
  {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)port);
    if (connect(sock, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
      wamble_close_socket(sock);
      return WAMBLE_INVALID_SOCKET;
    }
  }
  return sock;
}

static int ws_connect_and_upgrade(int port) {
  wamble_socket_t c = ws_connect_loopback(port);
  wamble_client_t client = {0};
  if (c == WAMBLE_INVALID_SOCKET)
    return -1;
  if (wamble_client_upgrade_ws(&client, c, "/ws", "localhost").code !=
      WAMBLE_CLIENT_STATUS_OK) {
    wamble_close_socket(c);
    return -1;
  }
  g_test_client = client.sock;
  return 0;
}

static void ws_fill_token(uint8_t token[TOKEN_LENGTH], uint8_t base) {
  for (int i = 0; i < TOKEN_LENGTH; i++)
    token[i] = (uint8_t)(base + i);
}

static int ws_serialize_msg(const struct WambleMsg *msg, uint8_t flags,
                            uint8_t *out, size_t out_cap, size_t *out_len) {
  return (wamble_packet_serialize(msg, out, out_cap, out_len, flags) == NET_OK)
             ? 0
             : -1;
}

static int ws_pop_packet_wait(uint8_t *packet, size_t packet_cap,
                              size_t *out_packet_len,
                              struct sockaddr_in *out_cliaddr, int timeout_ms) {
  if (!g_test_gateway)
    return -1;
  int waited = 0;
  while (waited < timeout_ms) {
    int rc = ws_gateway_pop_packet(g_test_gateway, packet, packet_cap,
                                   out_packet_len, out_cliaddr);
    if (rc != 0)
      return rc;
    wamble_sleep_ms(5);
    waited += 5;
  }
  return 0;
}

static int ws_send_msg(const struct WambleMsg *msg, uint8_t flags) {
  uint8_t packet[WAMBLE_MAX_PACKET_SIZE];
  size_t packet_len = 0;
  if (ws_serialize_msg(msg, flags, packet, sizeof(packet), &packet_len) != 0)
    return -1;
  return (wamble_client_ws_send_frame(g_test_client, 0x2u, packet, packet_len,
                                      0)
              .code == WAMBLE_CLIENT_STATUS_OK)
             ? 0
             : -1;
}

static const WambleMessageExtField *
ws_find_ext_field(const struct WambleMsg *msg, const char *key) {
  if (!msg || !key)
    return NULL;
  for (uint8_t i = 0; i < msg->extensions.count; i++) {
    if (strcmp(msg->extensions.fields[i].key, key) == 0)
      return &msg->extensions.fields[i];
  }
  return NULL;
}

WAMBLE_TEST(ws_handshake_rejects_invalid_key) {
  config_load(NULL, NULL, NULL, 0);
  int port = 0;
  T_ASSERT_EQ_INT(ws_start_gateway(&port), 0);

  wamble_socket_t c = ws_connect_loopback(port);
  g_test_client = c;
  T_ASSERT(c != WAMBLE_INVALID_SOCKET);
  T_ASSERT_CLIENT_STATUS_OK(
      wamble_client_ws_send_handshake(c, "/ws", "localhost", "abc", "13"));

  char resp[1024];
  T_ASSERT_CLIENT_STATUS_OK(wamble_client_ws_recv_http(c, resp, sizeof(resp)));
  T_ASSERT(strstr(resp, "HTTP/1.1 400") != NULL);

  return 0;
}

WAMBLE_TEST(ws_handshake_wrong_version_426) {
  config_load(NULL, NULL, NULL, 0);
  int port = 0;
  T_ASSERT_EQ_INT(ws_start_gateway(&port), 0);

  wamble_socket_t c = ws_connect_loopback(port);
  g_test_client = c;
  T_ASSERT(c != WAMBLE_INVALID_SOCKET);
  T_ASSERT_CLIENT_STATUS_OK(wamble_client_ws_send_handshake(
      c, "/ws", "localhost", "dGhlIHNhbXBsZSBub25jZQ==", "12"));

  char resp[1024];
  T_ASSERT_CLIENT_STATUS_OK(wamble_client_ws_recv_http(c, resp, sizeof(resp)));
  T_ASSERT(strstr(resp, "HTTP/1.1 426") != NULL);
  T_ASSERT(strstr(resp, "Sec-WebSocket-Version: 13") != NULL);

  return 0;
}

WAMBLE_TEST(ws_oversized_control_frame_closes_protocol_error) {
  config_load(NULL, NULL, NULL, 0);
  int port = 0;
  T_ASSERT_EQ_INT(ws_start_gateway(&port), 0);
  T_ASSERT_EQ_INT(ws_connect_and_upgrade(port), 0);

  uint8_t payload[126];
  memset(payload, 0xAB, sizeof(payload));
  T_ASSERT_CLIENT_STATUS_OK(wamble_client_ws_send_frame(
      g_test_client, 0x9u, payload, sizeof(payload), 1));

  uint8_t opcode = 0;
  uint8_t in[128];
  size_t in_len = 0;
  T_ASSERT_CLIENT_STATUS_OK(wamble_client_ws_recv_frame(
      g_test_client, &opcode, in, sizeof(in), &in_len));
  T_ASSERT_EQ_INT(opcode, 0x8);
  T_ASSERT(in_len >= 2u);
  uint16_t code = (uint16_t)(((uint16_t)in[0] << 8) | in[1]);
  T_ASSERT_EQ_INT((int)code, 1002);

  return 0;
}

WAMBLE_TEST(ws_unsupported_opcode_closes_protocol_error) {
  config_load(NULL, NULL, NULL, 0);
  int port = 0;
  T_ASSERT_EQ_INT(ws_start_gateway(&port), 0);
  T_ASSERT_EQ_INT(ws_connect_and_upgrade(port), 0);

  uint8_t payload[2] = {'h', 'i'};
  T_ASSERT_CLIENT_STATUS_OK(wamble_client_ws_send_frame(
      g_test_client, 0x1u, payload, sizeof(payload), 0));

  uint8_t opcode = 0;
  uint8_t in[128];
  size_t in_len = 0;
  T_ASSERT_CLIENT_STATUS_OK(wamble_client_ws_recv_frame(
      g_test_client, &opcode, in, sizeof(in), &in_len));
  T_ASSERT_EQ_INT(opcode, 0x8);
  T_ASSERT(in_len >= 2u);
  uint16_t code = (uint16_t)(((uint16_t)in[0] << 8) | in[1]);
  T_ASSERT_EQ_INT((int)code, 1002);

  return 0;
}

WAMBLE_TEST(ws_binary_roundtrip_and_coalesced_first_frame) {
  config_load(NULL, NULL, NULL, 0);
  int port = 0;
  T_ASSERT_EQ_INT(ws_start_gateway(&port), 0);

  wamble_socket_t c = ws_connect_loopback(port);
  g_test_client = c;
  T_ASSERT(c != WAMBLE_INVALID_SOCKET);

  struct WambleMsg in = {0};
  in.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  ws_fill_token(in.token, 0x11);
  in.board_id = 7;
  in.seq_num = 42;

  uint8_t first_packet[WAMBLE_MAX_PACKET_SIZE];
  size_t first_packet_len = 0;
  T_ASSERT_EQ_INT(ws_serialize_msg(&in, 0, first_packet, sizeof(first_packet),
                                   &first_packet_len),
                  0);

  T_ASSERT_CLIENT_STATUS_OK(wamble_client_ws_send_handshake_with_first_frame(
      c, "/ws", "localhost", "dGhlIHNhbXBsZSBub25jZQ==", "13", first_packet,
      first_packet_len));
  {
    char resp[1024];
    T_ASSERT_CLIENT_STATUS_OK(
        wamble_client_ws_recv_http(c, resp, sizeof(resp)));
    T_ASSERT(strstr(resp, "HTTP/1.1 101") != NULL);
  }

  uint8_t queued[WAMBLE_MAX_PACKET_SIZE];
  size_t queued_len = 0;
  struct sockaddr_in src;
  memset(&src, 0, sizeof(src));
  T_ASSERT_EQ_INT(
      ws_pop_packet_wait(queued, sizeof(queued), &queued_len, &src, 2000), 1);
  T_ASSERT_EQ_INT((int)queued_len, (int)first_packet_len);
  T_ASSERT(memcmp(queued, first_packet, first_packet_len) == 0);

  struct WambleMsg out = {0};
  out.ctrl = WAMBLE_CTRL_SERVER_NOTIFICATION;
  memcpy(out.token, in.token, TOKEN_LENGTH);
  snprintf(out.view.fen, sizeof(out.view.fen), "server-msg");
  out.seq_num = 99;

  uint8_t out_packet[WAMBLE_MAX_PACKET_SIZE];
  size_t out_packet_len = 0;
  T_ASSERT_EQ_INT(ws_serialize_msg(&out, 0, out_packet, sizeof(out_packet),
                                   &out_packet_len),
                  0);
  T_ASSERT_EQ_INT(ws_gateway_queue_packet(&src, out_packet, out_packet_len), 1);
  ws_gateway_flush_outbound(g_test_gateway);

  uint8_t opcode = 0;
  uint8_t in_frame[WAMBLE_MAX_PACKET_SIZE];
  size_t in_frame_len = 0;
  T_ASSERT_CLIENT_STATUS_OK(wamble_client_ws_recv_frame(
      c, &opcode, in_frame, sizeof(in_frame), &in_frame_len));
  T_ASSERT_EQ_INT(opcode, 0x2);
  T_ASSERT_EQ_INT((int)in_frame_len, (int)out_packet_len);
  T_ASSERT(memcmp(in_frame, out_packet, out_packet_len) == 0);

  return 0;
}

WAMBLE_TEST(ws_fragmented_binary_frame_reassembled) {
  config_load(NULL, NULL, NULL, 0);
  int port = 0;
  T_ASSERT_EQ_INT(ws_start_gateway(&port), 0);
  T_ASSERT_EQ_INT(ws_connect_and_upgrade(port), 0);

  struct WambleMsg msg = {0};
  msg.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  ws_fill_token(msg.token, 0x21);
  msg.board_id = 88;
  msg.seq_num = 19;

  uint8_t packet[WAMBLE_MAX_PACKET_SIZE];
  size_t packet_len = 0;
  T_ASSERT_EQ_INT(
      ws_serialize_msg(&msg, 0, packet, sizeof(packet), &packet_len), 0);
  T_ASSERT(packet_len > 2);

  size_t part1_len = packet_len / 2;
  if (part1_len == 0)
    part1_len = 1;
  size_t part2_len = packet_len - part1_len;
  T_ASSERT_CLIENT_STATUS_OK(wamble_client_ws_send_frame_ex(
      g_test_client, 0u, 0x2u, packet, part1_len, 0));
  T_ASSERT_CLIENT_STATUS_OK(wamble_client_ws_send_frame_ex(
      g_test_client, 1u, 0x0u, packet + part1_len, part2_len, 0));

  uint8_t queued[WAMBLE_MAX_PACKET_SIZE];
  size_t queued_len = 0;
  struct sockaddr_in src;
  memset(&src, 0, sizeof(src));
  T_ASSERT_EQ_INT(
      ws_pop_packet_wait(queued, sizeof(queued), &queued_len, &src, 2000), 1);
  T_ASSERT_EQ_INT((int)queued_len, (int)packet_len);
  T_ASSERT(memcmp(queued, packet, packet_len) == 0);

  return 0;
}

WAMBLE_TEST(ws_reliable_send_skips_ack_retry_for_ws) {
  config_load(NULL, NULL, NULL, 0);
  int port = 0;
  T_ASSERT_EQ_INT(ws_start_gateway(&port), 0);
  T_ASSERT_EQ_INT(ws_connect_and_upgrade(port), 0);

  struct WambleMsg bootstrap = {0};
  bootstrap.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  ws_fill_token(bootstrap.token, 0x31);
  bootstrap.board_id = 3;
  bootstrap.seq_num = 5;

  uint8_t bootstrap_packet[WAMBLE_MAX_PACKET_SIZE];
  size_t bootstrap_len = 0;
  T_ASSERT_EQ_INT(ws_serialize_msg(&bootstrap, 0, bootstrap_packet,
                                   sizeof(bootstrap_packet), &bootstrap_len),
                  0);
  T_ASSERT_CLIENT_STATUS_OK(wamble_client_ws_send_frame(
      g_test_client, 0x2u, bootstrap_packet, bootstrap_len, 0));

  uint8_t queued[WAMBLE_MAX_PACKET_SIZE];
  size_t queued_len = 0;
  struct sockaddr_in src;
  memset(&src, 0, sizeof(src));
  T_ASSERT_EQ_INT(
      ws_pop_packet_wait(queued, sizeof(queued), &queued_len, &src, 2000), 1);

  struct WambleMsg out = {0};
  out.ctrl = WAMBLE_CTRL_SERVER_NOTIFICATION;
  memcpy(out.token, bootstrap.token, TOKEN_LENGTH);
  snprintf(out.view.fen, sizeof(out.view.fen), "ws-reliable");

  uint64_t start_ms = wamble_now_mono_millis();
  T_ASSERT_EQ_INT(
      send_reliable_message(WAMBLE_INVALID_SOCKET, &out, &src, 250, 2), 0);
  uint64_t elapsed_ms = wamble_now_mono_millis() - start_ms;
  T_ASSERT(elapsed_ms < 100u);

  ws_gateway_flush_outbound(g_test_gateway);

  uint8_t opcode = 0;
  uint8_t frame[WAMBLE_MAX_PACKET_SIZE];
  size_t frame_len = 0;
  T_ASSERT_CLIENT_STATUS_OK(wamble_client_ws_recv_frame(
      g_test_client, &opcode, frame, sizeof(frame), &frame_len));
  T_ASSERT_EQ_INT(opcode, 0x2);

  struct WambleMsg decoded = {0};
  uint8_t decoded_flags = 0;
  T_ASSERT_EQ_INT((int)wamble_packet_deserialize(frame, frame_len, &decoded,
                                                 &decoded_flags),
                  (int)NET_OK);
  T_ASSERT_EQ_INT((int)decoded.ctrl, (int)WAMBLE_CTRL_SERVER_NOTIFICATION);

  return 0;
}

WAMBLE_TEST(ws_outbound_batches_multiple_packets_per_frame) {
  config_load(NULL, NULL, NULL, 0);
  int port = 0;
  T_ASSERT_EQ_INT(ws_start_gateway(&port), 0);
  T_ASSERT_EQ_INT(ws_connect_and_upgrade(port), 0);

  struct WambleMsg bootstrap = {0};
  bootstrap.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  ws_fill_token(bootstrap.token, 0x41);
  bootstrap.seq_num = 1;

  uint8_t bootstrap_packet[WAMBLE_MAX_PACKET_SIZE];
  size_t bootstrap_len = 0;
  T_ASSERT_EQ_INT(ws_serialize_msg(&bootstrap, 0, bootstrap_packet,
                                   sizeof(bootstrap_packet), &bootstrap_len),
                  0);
  T_ASSERT_CLIENT_STATUS_OK(wamble_client_ws_send_frame(
      g_test_client, 0x2u, bootstrap_packet, bootstrap_len, 0));

  uint8_t queued[WAMBLE_MAX_PACKET_SIZE];
  size_t queued_len = 0;
  struct sockaddr_in src;
  memset(&src, 0, sizeof(src));
  T_ASSERT_EQ_INT(
      ws_pop_packet_wait(queued, sizeof(queued), &queued_len, &src, 2000), 1);

  struct WambleMsg out_a = {0};
  out_a.ctrl = WAMBLE_CTRL_SERVER_NOTIFICATION;
  memcpy(out_a.token, bootstrap.token, TOKEN_LENGTH);
  snprintf(out_a.view.fen, sizeof(out_a.view.fen), "batch-a");

  struct WambleMsg out_b = {0};
  out_b.ctrl = WAMBLE_CTRL_SERVER_NOTIFICATION;
  memcpy(out_b.token, bootstrap.token, TOKEN_LENGTH);
  snprintf(out_b.view.fen, sizeof(out_b.view.fen), "batch-b");

  T_ASSERT_EQ_INT(send_unreliable_packet(WAMBLE_INVALID_SOCKET, &out_a, &src),
                  0);
  T_ASSERT_EQ_INT(send_unreliable_packet(WAMBLE_INVALID_SOCKET, &out_b, &src),
                  0);

  ws_gateway_flush_outbound(g_test_gateway);

  uint8_t opcode = 0;
  uint8_t frame[4096];
  size_t frame_len = 0;
  T_ASSERT_CLIENT_STATUS_OK(wamble_client_ws_recv_frame(
      g_test_client, &opcode, frame, sizeof(frame), &frame_len));
  T_ASSERT_EQ_INT(opcode, 0x2);

  size_t p1_len = 0;
  size_t p2_len = 0;
  T_ASSERT_EQ_INT((int)wamble_wire_packet_size(frame, frame_len, &p1_len),
                  (int)NET_OK);
  T_ASSERT_EQ_INT(
      (int)wamble_wire_packet_size(frame + p1_len, frame_len - p1_len, &p2_len),
      (int)NET_OK);
  T_ASSERT_EQ_INT((int)frame_len, (int)(p1_len + p2_len));

  struct WambleMsg dec_a = {0};
  struct WambleMsg dec_b = {0};
  uint8_t flags_a = 0;
  uint8_t flags_b = 0;
  T_ASSERT_EQ_INT(
      (int)wamble_packet_deserialize(frame, p1_len, &dec_a, &flags_a),
      (int)NET_OK);
  T_ASSERT_EQ_INT(
      (int)wamble_packet_deserialize(frame + p1_len, p2_len, &dec_b, &flags_b),
      (int)NET_OK);
  T_ASSERT(strcmp(dec_a.view.fen, "batch-a") == 0);
  T_ASSERT(strcmp(dec_b.view.fen, "batch-b") == 0);

  return 0;
}

WAMBLE_TEST(ws_server_protocol_discovery_and_fragmented_tos_roundtrip) {
  char tos_text[WAMBLE_FRAGMENT_DATA_MAX + 256 + 1];
  size_t tos_len = (size_t)WAMBLE_FRAGMENT_DATA_MAX + 256;
  for (size_t i = 0; i < tos_len; i++)
    tos_text[i] = (char)('a' + (i % 26));
  tos_text[tos_len] = '\0';

  char cfg[WAMBLE_FRAGMENT_DATA_MAX + 2048];
  int wrote_cfg = snprintf(cfg, sizeof(cfg),
                           "(def rate-limit-requests-per-sec 100)\n"
                           "(defprofile open "
                           "((def port 19431) (def advertise 1) "
                           "(def websocket-enabled 1) "
                           "(def websocket-path \"/ws\") "
                           "(def tos-text \"%s\")))\n",
                           tos_text);
  T_ASSERT(wrote_cfg > 0);
  T_ASSERT(wrote_cfg < (int)sizeof(cfg));

  const char *cfg_path = "build/test_ws_gateway_discovery_tos.conf";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'protocol.ctrl', 'client_hello', '*', 'allow', 0, "
          "'hello_access', 'test'), "
          "(0, 'protocol.ctrl', 'list_profiles', '*', 'allow', 0, "
          "'list_access', 'test'), "
          "(0, 'protocol.ctrl', 'get_profile_info', '*', 'allow', 0, "
          "'profile_info_access', 'test'), "
          "(0, 'protocol.ctrl', 'get_profile_tos', '*', 'allow', 0, "
          "'profile_tos_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  player_manager_init();
  board_manager_init();

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);

  int port = 0;
  T_ASSERT_EQ_INT(ws_start_gateway(&port), 0);
  T_ASSERT_EQ_INT(ws_connect_and_upgrade(port), 0);

  uint8_t packet[WAMBLE_MAX_PACKET_SIZE];
  size_t packet_len = 0;
  struct sockaddr_in cliaddr;
  struct WambleMsg in = {0};

  struct WambleMsg hello = {0};
  hello.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  hello.header_version = WAMBLE_PROTO_VERSION;
  hello.seq_num = 0;
  T_ASSERT_EQ_INT(ws_send_msg(&hello, 0), 0);
  T_ASSERT_EQ_INT(
      ws_pop_packet_wait(packet, sizeof(packet), &packet_len, &cliaddr, 2000),
      1);
  T_ASSERT(receive_message_packet(packet, packet_len, &in, &cliaddr) > 0);
  T_ASSERT_EQ_INT(handle_message(srv, &in, &cliaddr, 0, "open"), SERVER_OK);
  ws_gateway_flush_outbound(g_test_gateway);

  uint8_t opcode = 0;
  uint8_t frame[WAMBLE_MAX_PACKET_SIZE * 2];
  size_t frame_len = 0;
  T_ASSERT_CLIENT_STATUS_OK(wamble_client_ws_recv_frame(
      g_test_client, &opcode, frame, sizeof(frame), &frame_len));
  T_ASSERT_EQ_INT(opcode, 0x2);
  {
    struct WambleMsg out = {0};
    uint8_t out_flags = 0;
    T_ASSERT_EQ_INT(
        (int)wamble_packet_deserialize(frame, frame_len, &out, &out_flags),
        (int)NET_OK);
    T_ASSERT_EQ_INT(out.ctrl, WAMBLE_CTRL_SERVER_HELLO);

    struct WambleMsg list_req = {0};
    list_req.ctrl = WAMBLE_CTRL_LIST_PROFILES;
    list_req.header_version = WAMBLE_PROTO_VERSION;
    list_req.seq_num = 1;
    memcpy(list_req.token, out.token, TOKEN_LENGTH);
    T_ASSERT_EQ_INT(ws_send_msg(&list_req, 0), 0);

    T_ASSERT_EQ_INT(
        ws_pop_packet_wait(packet, sizeof(packet), &packet_len, &cliaddr, 2000),
        1);
    memset(&in, 0, sizeof(in));
    T_ASSERT(receive_message_packet(packet, packet_len, &in, &cliaddr) > 0);
    T_ASSERT_EQ_INT(handle_message(srv, &in, &cliaddr, 0, "open"), SERVER_OK);
    ws_gateway_flush_outbound(g_test_gateway);

    T_ASSERT_CLIENT_STATUS_OK(wamble_client_ws_recv_frame(
        g_test_client, &opcode, frame, sizeof(frame), &frame_len));
    T_ASSERT_EQ_INT(opcode, 0x2);
    memset(&out, 0, sizeof(out));
    T_ASSERT_EQ_INT(
        (int)wamble_packet_deserialize(frame, frame_len, &out, &out_flags),
        (int)NET_OK);
    T_ASSERT_EQ_INT(out.ctrl, WAMBLE_CTRL_PROFILES_LIST);
    T_ASSERT_STREQ(out.view.profiles_list, "open");

    struct WambleMsg info_req = {0};
    info_req.ctrl = WAMBLE_CTRL_GET_PROFILE_INFO;
    info_req.header_version = WAMBLE_PROTO_VERSION;
    info_req.seq_num = 2;
    memcpy(info_req.token, out.token, TOKEN_LENGTH);
    memcpy(info_req.text.profile_name, "open", 4);
    info_req.text.profile_name_len = 4;
    T_ASSERT_EQ_INT(ws_send_msg(&info_req, 0), 0);

    T_ASSERT_EQ_INT(
        ws_pop_packet_wait(packet, sizeof(packet), &packet_len, &cliaddr, 2000),
        1);
    memset(&in, 0, sizeof(in));
    T_ASSERT(receive_message_packet(packet, packet_len, &in, &cliaddr) > 0);
    T_ASSERT_EQ_INT(handle_message(srv, &in, &cliaddr, 0, "open"), SERVER_OK);
    ws_gateway_flush_outbound(g_test_gateway);

    T_ASSERT_CLIENT_STATUS_OK(wamble_client_ws_recv_frame(
        g_test_client, &opcode, frame, sizeof(frame), &frame_len));
    T_ASSERT_EQ_INT(opcode, 0x2);
    memset(&out, 0, sizeof(out));
    T_ASSERT_EQ_INT(
        (int)wamble_packet_deserialize(frame, frame_len, &out, &out_flags),
        (int)NET_OK);
    T_ASSERT_EQ_INT(out.ctrl, WAMBLE_CTRL_PROFILE_INFO);
    T_ASSERT_STREQ(out.text.profile_info, "open;19431;1;0");
    {
      const WambleMessageExtField *ws_path =
          ws_find_ext_field(&out, "profile.websocket_path");
      T_ASSERT(ws_path != NULL);
      T_ASSERT_EQ_INT(ws_path->value_type, WAMBLE_TREATMENT_VALUE_STRING);
      T_ASSERT_STREQ(ws_path->string_value, "/ws");
    }

    struct WambleMsg tos_req = {0};
    tos_req.ctrl = WAMBLE_CTRL_GET_PROFILE_TOS;
    tos_req.header_version = WAMBLE_PROTO_VERSION;
    tos_req.seq_num = 3;
    memcpy(tos_req.token, out.token, TOKEN_LENGTH);
    memcpy(tos_req.text.profile_name, "open", 4);
    tos_req.text.profile_name_len = 4;
    T_ASSERT_EQ_INT(ws_send_msg(&tos_req, 0), 0);
  }

  T_ASSERT_EQ_INT(
      ws_pop_packet_wait(packet, sizeof(packet), &packet_len, &cliaddr, 2000),
      1);
  memset(&in, 0, sizeof(in));
  T_ASSERT(receive_message_packet(packet, packet_len, &in, &cliaddr) > 0);
  T_ASSERT_EQ_INT(handle_message(srv, &in, &cliaddr, 0, "open"), SERVER_OK);
  ws_gateway_flush_outbound(g_test_gateway);

  {
    WambleFragmentReassembly frag;
    wamble_fragment_reassembly_init(&frag);
    int packet_count = 0;
    WambleFragmentReassemblyResult result = WAMBLE_FRAGMENT_REASSEMBLY_IGNORED;
    while (result != WAMBLE_FRAGMENT_REASSEMBLY_COMPLETE) {
      T_ASSERT_CLIENT_STATUS_OK(wamble_client_ws_recv_frame(
          g_test_client, &opcode, frame, sizeof(frame), &frame_len));
      T_ASSERT_EQ_INT(opcode, 0x2);
      size_t offset = 0;
      while (offset < frame_len) {
        size_t one_len = 0;
        struct WambleMsg fragment = {0};
        uint8_t fragment_flags = 0;
        T_ASSERT_EQ_INT((int)wamble_wire_packet_size(
                            frame + offset, frame_len - offset, &one_len),
                        (int)NET_OK);
        T_ASSERT(one_len > 0);
        T_ASSERT_EQ_INT((int)wamble_packet_deserialize(frame + offset, one_len,
                                                       &fragment,
                                                       &fragment_flags),
                        (int)NET_OK);
        T_ASSERT_EQ_INT(fragment.ctrl, WAMBLE_CTRL_PROFILE_TOS_DATA);
        T_ASSERT(msg_uses_fragment_payload(&fragment));
        result = wamble_fragment_reassembly_push(&frag, &fragment);
        packet_count++;
        offset += one_len;
      }
    }
    T_ASSERT(packet_count > 1);
    T_ASSERT_EQ_INT(result, WAMBLE_FRAGMENT_REASSEMBLY_COMPLETE);
    T_ASSERT_EQ_INT((int)frag.total_len, (int)tos_len);
    T_ASSERT(memcmp(frag.data, tos_text, tos_len) == 0);
    wamble_fragment_reassembly_free(&frag);
  }

  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(ws_server_protocol_profile_terms_acceptance_roundtrip) {
  const char *cfg_path = "build/test_ws_gateway_terms_accept.conf";
  const char *cfg = "(def rate-limit-requests-per-sec 100)\n"
                    "(defprofile p1 "
                    "((def port 19452) (def advertise 1) "
                    "(def websocket-enabled 1) "
                    "(def websocket-path \"/ws\") "
                    "(def tos-text \"profile terms v2\")))\n";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'protocol.ctrl', 'client_hello', '*', 'allow', 0, "
          "'hello_access', 'test'), "
          "(0, 'protocol.ctrl', 'get_profile_info', '*', 'allow', 0, "
          "'profile_info_access', 'test'), "
          "(0, 'protocol.ctrl', 'get_profile_tos', '*', 'allow', 0, "
          "'profile_tos_access', 'test'), "
          "(0, 'protocol.ctrl', 'accept_profile_tos', '*', 'allow', 0, "
          "'accept_profile_tos_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  player_manager_init();
  board_manager_init();

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);

  int port = 0;
  T_ASSERT_EQ_INT(ws_start_gateway(&port), 0);
  T_ASSERT_EQ_INT(ws_connect_and_upgrade(port), 0);

  uint8_t packet[WAMBLE_MAX_PACKET_SIZE];
  size_t packet_len = 0;
  struct sockaddr_in cliaddr;
  struct WambleMsg in = {0};
  uint8_t opcode = 0;
  uint8_t frame[WAMBLE_MAX_PACKET_SIZE * 2];
  size_t frame_len = 0;
  struct WambleMsg hello_out = {0};
  uint8_t hello_out_flags = 0;
  uint8_t client_token[TOKEN_LENGTH];

  struct WambleMsg hello = {0};
  hello.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  hello.header_version = WAMBLE_PROTO_VERSION;
  T_ASSERT_EQ_INT(ws_send_msg(&hello, 0), 0);
  T_ASSERT_EQ_INT(
      ws_pop_packet_wait(packet, sizeof(packet), &packet_len, &cliaddr, 2000),
      1);
  T_ASSERT(receive_message_packet(packet, packet_len, &in, &cliaddr) > 0);
  T_ASSERT_EQ_INT(handle_message(srv, &in, &cliaddr, 0, "p1"), SERVER_OK);
  ws_gateway_flush_outbound(g_test_gateway);

  T_ASSERT_CLIENT_STATUS_OK(wamble_client_ws_recv_frame(
      g_test_client, &opcode, frame, sizeof(frame), &frame_len));
  T_ASSERT_EQ_INT(opcode, 0x2);
  T_ASSERT_EQ_INT((int)wamble_packet_deserialize(frame, frame_len, &hello_out,
                                                 &hello_out_flags),
                  (int)NET_OK);
  T_ASSERT_EQ_INT(hello_out.ctrl, WAMBLE_CTRL_SERVER_HELLO);
  memcpy(client_token, hello_out.token, TOKEN_LENGTH);

  struct WambleMsg missing_info_req = {0};
  missing_info_req.ctrl = WAMBLE_CTRL_GET_PROFILE_INFO;
  missing_info_req.header_version = WAMBLE_PROTO_VERSION;
  missing_info_req.seq_num = 1;
  memcpy(missing_info_req.token, client_token, TOKEN_LENGTH);
  memcpy(missing_info_req.text.profile_name, "missing", 7);
  missing_info_req.text.profile_name_len = 7;
  T_ASSERT_EQ_INT(ws_send_msg(&missing_info_req, 0), 0);
  T_ASSERT_EQ_INT(
      ws_pop_packet_wait(packet, sizeof(packet), &packet_len, &cliaddr, 2000),
      1);
  memset(&in, 0, sizeof(in));
  T_ASSERT(receive_message_packet(packet, packet_len, &in, &cliaddr) > 0);
  T_ASSERT_EQ_INT(handle_message(srv, &in, &cliaddr, 0, "p1"), SERVER_OK);
  ws_gateway_flush_outbound(g_test_gateway);

  struct WambleMsg tos_req = {0};
  tos_req.ctrl = WAMBLE_CTRL_GET_PROFILE_TOS;
  tos_req.header_version = WAMBLE_PROTO_VERSION;
  tos_req.seq_num = 2;
  memcpy(tos_req.token, client_token, TOKEN_LENGTH);
  memcpy(tos_req.text.profile_name, "p1", 2);
  tos_req.text.profile_name_len = 2;
  T_ASSERT_EQ_INT(ws_send_msg(&tos_req, 0), 0);
  T_ASSERT_EQ_INT(
      ws_pop_packet_wait(packet, sizeof(packet), &packet_len, &cliaddr, 2000),
      1);
  memset(&in, 0, sizeof(in));
  T_ASSERT(receive_message_packet(packet, packet_len, &in, &cliaddr) > 0);
  T_ASSERT_EQ_INT(handle_message(srv, &in, &cliaddr, 0, "p1"), SERVER_OK);
  ws_gateway_flush_outbound(g_test_gateway);

  struct WambleMsg accept = {0};
  accept.ctrl = WAMBLE_CTRL_ACCEPT_PROFILE_TOS;
  accept.header_version = WAMBLE_PROTO_VERSION;
  accept.seq_num = 3;
  memcpy(accept.token, client_token, TOKEN_LENGTH);
  memcpy(accept.text.profile_name, "p1", 2);
  accept.text.profile_name_len = 2;
  T_ASSERT_EQ_INT(ws_send_msg(&accept, 0), 0);
  T_ASSERT_EQ_INT(
      ws_pop_packet_wait(packet, sizeof(packet), &packet_len, &cliaddr, 2000),
      1);
  memset(&in, 0, sizeof(in));
  T_ASSERT(receive_message_packet(packet, packet_len, &in, &cliaddr) > 0);
  T_ASSERT_EQ_INT(handle_message(srv, &in, &cliaddr, 0, "p1"), SERVER_OK);
  ws_gateway_flush_outbound(g_test_gateway);

  {
    WambleProfileTermsAcceptance acceptance = {0};
    T_ASSERT_EQ_INT(wamble_query_get_latest_profile_terms_acceptance(
                        accept.token, "p1", &acceptance),
                    DB_OK);
    T_ASSERT_STREQ(acceptance.profile_name, "p1");
    T_ASSERT(acceptance.tos_text != NULL);
    T_ASSERT_STREQ(acceptance.tos_text, "profile terms v2");
    wamble_profile_terms_acceptance_clear(&acceptance);
  }

  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(ws_server_protocol_fragmented_profiles_list_roundtrip) {
  char cfg[16384];
  char expected[4096];
  size_t cfg_off = 0;
  size_t expected_off = 0;

  cfg_off += (size_t)snprintf(cfg + cfg_off, sizeof(cfg) - cfg_off,
                              "(def rate-limit-requests-per-sec 100)\n");
  for (int i = 0; i < 20; i++) {
    char name[32];
    snprintf(name, sizeof(name), "profile-%02d", i);
    if (expected_off > 0) {
      expected_off += (size_t)snprintf(expected + expected_off,
                                       sizeof(expected) - expected_off, ",");
    }
    expected_off += (size_t)snprintf(
        expected + expected_off, sizeof(expected) - expected_off, "%s", name);
    cfg_off += (size_t)snprintf(
        cfg + cfg_off, sizeof(cfg) - cfg_off,
        "(defprofile %s ((def port %d) (def advertise 1) "
        "(def websocket-enabled 1) (def websocket-path \"/ws\")))\n",
        name, 19510 + i);
  }
  T_ASSERT(cfg_off < sizeof(cfg));
  T_ASSERT(expected_off < sizeof(expected));

  const char *cfg_path = "build/test_ws_gateway_profiles_list.conf";
  if (wamble_test_prepare_db(
          cfg_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'protocol.ctrl', 'client_hello', '*', 'allow', 0, "
          "'hello_access', 'test'), "
          "(0, 'protocol.ctrl', 'list_profiles', '*', 'allow', 0, "
          "'list_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  player_manager_init();
  board_manager_init();

  wamble_socket_t srv = create_and_bind_socket(0);
  T_ASSERT(srv != WAMBLE_INVALID_SOCKET);

  int port = 0;
  T_ASSERT_EQ_INT(ws_start_gateway(&port), 0);
  T_ASSERT_EQ_INT(ws_connect_and_upgrade(port), 0);

  uint8_t packet[WAMBLE_MAX_PACKET_SIZE];
  size_t packet_len = 0;
  struct sockaddr_in cliaddr;
  struct WambleMsg in = {0};

  struct WambleMsg hello = {0};
  hello.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  hello.header_version = WAMBLE_PROTO_VERSION;
  hello.seq_num = 0;
  T_ASSERT_EQ_INT(ws_send_msg(&hello, 0), 0);
  T_ASSERT_EQ_INT(
      ws_pop_packet_wait(packet, sizeof(packet), &packet_len, &cliaddr, 2000),
      1);
  T_ASSERT(receive_message_packet(packet, packet_len, &in, &cliaddr) > 0);
  T_ASSERT_EQ_INT(handle_message(srv, &in, &cliaddr, 0, "profile-00"),
                  SERVER_OK);
  ws_gateway_flush_outbound(g_test_gateway);

  uint8_t opcode = 0;
  uint8_t frame[WAMBLE_MAX_PACKET_SIZE * 2];
  size_t frame_len = 0;
  T_ASSERT_CLIENT_STATUS_OK(wamble_client_ws_recv_frame(
      g_test_client, &opcode, frame, sizeof(frame), &frame_len));
  T_ASSERT_EQ_INT(opcode, 0x2);

  struct WambleMsg out = {0};
  uint8_t out_flags = 0;
  T_ASSERT_EQ_INT(
      (int)wamble_packet_deserialize(frame, frame_len, &out, &out_flags),
      (int)NET_OK);
  T_ASSERT_EQ_INT(out.ctrl, WAMBLE_CTRL_SERVER_HELLO);

  struct WambleMsg list_req = {0};
  list_req.ctrl = WAMBLE_CTRL_LIST_PROFILES;
  list_req.header_version = WAMBLE_PROTO_VERSION;
  list_req.seq_num = 1;
  memcpy(list_req.token, out.token, TOKEN_LENGTH);
  T_ASSERT_EQ_INT(ws_send_msg(&list_req, 0), 0);

  T_ASSERT_EQ_INT(
      ws_pop_packet_wait(packet, sizeof(packet), &packet_len, &cliaddr, 2000),
      1);
  memset(&in, 0, sizeof(in));
  T_ASSERT(receive_message_packet(packet, packet_len, &in, &cliaddr) > 0);
  T_ASSERT_EQ_INT(handle_message(srv, &in, &cliaddr, 0, "profile-00"),
                  SERVER_OK);
  ws_gateway_flush_outbound(g_test_gateway);

  WambleFragmentReassembly frag = {0};
  wamble_fragment_reassembly_init(&frag);
  WambleFragmentReassemblyResult result =
      WAMBLE_FRAGMENT_REASSEMBLY_IN_PROGRESS;
  int packets_seen = 0;
  while (result == WAMBLE_FRAGMENT_REASSEMBLY_IN_PROGRESS) {
    T_ASSERT_CLIENT_STATUS_OK(wamble_client_ws_recv_frame(
        g_test_client, &opcode, frame, sizeof(frame), &frame_len));
    T_ASSERT_EQ_INT(opcode, 0x2);
    memset(&out, 0, sizeof(out));
    T_ASSERT_EQ_INT(
        (int)wamble_packet_deserialize(frame, frame_len, &out, &out_flags),
        (int)NET_OK);
    T_ASSERT_EQ_INT(out.ctrl, WAMBLE_CTRL_PROFILES_LIST);
    T_ASSERT(msg_uses_fragment_payload(&out));
    result = wamble_fragment_reassembly_push(&frag, &out);
    packets_seen++;
  }

  T_ASSERT_EQ_INT(result, WAMBLE_FRAGMENT_REASSEMBLY_COMPLETE);
  T_ASSERT(packets_seen >= 1);
  T_ASSERT_EQ_INT((int)frag.total_len, (int)strlen(expected));
  T_ASSERT(memcmp(frag.data, expected, strlen(expected)) == 0);
  wamble_fragment_reassembly_free(&frag);

  wamble_close_socket(srv);
  return 0;
}

WAMBLE_TEST(ws_send_ack_writes_ack_packet_to_ws_route) {
  config_load(NULL, NULL, NULL, 0);
  int port = 0;
  T_ASSERT_EQ_INT(ws_start_gateway(&port), 0);
  T_ASSERT_EQ_INT(ws_connect_and_upgrade(port), 0);

  struct WambleMsg bootstrap = {0};
  bootstrap.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  ws_fill_token(bootstrap.token, 0x71);
  bootstrap.seq_num = 0;
  T_ASSERT_EQ_INT(ws_send_msg(&bootstrap, 0), 0);

  uint8_t queued[WAMBLE_MAX_PACKET_SIZE];
  size_t queued_len = 0;
  struct sockaddr_in src;
  memset(&src, 0, sizeof(src));
  T_ASSERT_EQ_INT(
      ws_pop_packet_wait(queued, sizeof(queued), &queued_len, &src, 2000), 1);

  struct WambleMsg request = {0};
  request.ctrl = WAMBLE_CTRL_PLAYER_MOVE;
  memcpy(request.token, bootstrap.token, TOKEN_LENGTH);
  request.board_id = 17;
  request.seq_num = 4242;
  send_ack(WAMBLE_INVALID_SOCKET, &request, &src);

  uint8_t opcode = 0;
  uint8_t frame[WAMBLE_MAX_PACKET_SIZE];
  size_t frame_len = 0;
  T_ASSERT_CLIENT_STATUS_OK(wamble_client_ws_recv_frame(
      g_test_client, &opcode, frame, sizeof(frame), &frame_len));
  T_ASSERT_EQ_INT(opcode, 0x2);

  struct WambleMsg decoded = {0};
  uint8_t decoded_flags = 0;
  T_ASSERT_EQ_INT((int)wamble_packet_deserialize(frame, frame_len, &decoded,
                                                 &decoded_flags),
                  (int)NET_OK);
  T_ASSERT_EQ_INT((int)decoded.ctrl, (int)WAMBLE_CTRL_ACK);
  T_ASSERT_EQ_INT((int)decoded.seq_num, 4242);
  T_ASSERT_EQ_INT((int)decoded.board_id, 17);
  T_ASSERT(memcmp(decoded.token, bootstrap.token, TOKEN_LENGTH) == 0);
  return 0;
}

WAMBLE_TEST(ws_reliable_send_flushes_route_inline) {
  config_load(NULL, NULL, NULL, 0);
  int port = 0;
  T_ASSERT_EQ_INT(ws_start_gateway(&port), 0);
  T_ASSERT_EQ_INT(ws_connect_and_upgrade(port), 0);

  struct WambleMsg bootstrap = {0};
  bootstrap.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  ws_fill_token(bootstrap.token, 0x72);
  bootstrap.seq_num = 0;
  T_ASSERT_EQ_INT(ws_send_msg(&bootstrap, 0), 0);

  uint8_t queued[WAMBLE_MAX_PACKET_SIZE];
  size_t queued_len = 0;
  struct sockaddr_in src;
  memset(&src, 0, sizeof(src));
  T_ASSERT_EQ_INT(
      ws_pop_packet_wait(queued, sizeof(queued), &queued_len, &src, 2000), 1);

  struct WambleMsg out = {0};
  out.ctrl = WAMBLE_CTRL_SERVER_NOTIFICATION;
  memcpy(out.token, bootstrap.token, TOKEN_LENGTH);
  snprintf(out.view.fen, sizeof(out.view.fen), "ws-flush-inline");

  T_ASSERT_EQ_INT(
      send_reliable_message(WAMBLE_INVALID_SOCKET, &out, &src, 250, 2), 0);

  uint8_t opcode = 0;
  uint8_t frame[WAMBLE_MAX_PACKET_SIZE];
  size_t frame_len = 0;
  T_ASSERT_CLIENT_STATUS_OK(wamble_client_ws_recv_frame(
      g_test_client, &opcode, frame, sizeof(frame), &frame_len));
  T_ASSERT_EQ_INT(opcode, 0x2);

  struct WambleMsg decoded = {0};
  uint8_t decoded_flags = 0;
  T_ASSERT_EQ_INT((int)wamble_packet_deserialize(frame, frame_len, &decoded,
                                                 &decoded_flags),
                  (int)NET_OK);
  T_ASSERT_EQ_INT((int)decoded.ctrl, (int)WAMBLE_CTRL_SERVER_NOTIFICATION);
  T_ASSERT(strcmp(decoded.view.fen, "ws-flush-inline") == 0);
  return 0;
}

WAMBLE_TESTS_BEGIN_NAMED(wamble_register_tests_ws_gateway)
WAMBLE_TESTS_ADD_EX_SM(ws_handshake_rejects_invalid_key,
                       WAMBLE_SUITE_FUNCTIONAL, "ws_gateway", ws_test_setup,
                       ws_test_teardown, 0);
WAMBLE_TESTS_ADD_EX_SM(ws_handshake_wrong_version_426, WAMBLE_SUITE_FUNCTIONAL,
                       "ws_gateway", ws_test_setup, ws_test_teardown, 0);
WAMBLE_TESTS_ADD_EX_SM(ws_oversized_control_frame_closes_protocol_error,
                       WAMBLE_SUITE_FUNCTIONAL, "ws_gateway", ws_test_setup,
                       ws_test_teardown, 0);
WAMBLE_TESTS_ADD_EX_SM(ws_unsupported_opcode_closes_protocol_error,
                       WAMBLE_SUITE_FUNCTIONAL, "ws_gateway", ws_test_setup,
                       ws_test_teardown, 0);
WAMBLE_TESTS_ADD_EX_SM(ws_binary_roundtrip_and_coalesced_first_frame,
                       WAMBLE_SUITE_FUNCTIONAL, "ws_gateway", ws_test_setup,
                       ws_test_teardown, 0);
WAMBLE_TESTS_ADD_EX_SM(ws_fragmented_binary_frame_reassembled,
                       WAMBLE_SUITE_FUNCTIONAL, "ws_gateway", ws_test_setup,
                       ws_test_teardown, 0);
WAMBLE_TESTS_ADD_EX_SM(ws_reliable_send_skips_ack_retry_for_ws,
                       WAMBLE_SUITE_FUNCTIONAL, "ws_gateway", ws_test_setup,
                       ws_test_teardown, 0);
WAMBLE_TESTS_ADD_EX_SM(ws_outbound_batches_multiple_packets_per_frame,
                       WAMBLE_SUITE_FUNCTIONAL, "ws_gateway", ws_test_setup,
                       ws_test_teardown, 0);
WAMBLE_TESTS_ADD_EX_SM(ws_send_ack_writes_ack_packet_to_ws_route,
                       WAMBLE_SUITE_FUNCTIONAL, "ws_gateway", ws_test_setup,
                       ws_test_teardown, 0);
WAMBLE_TESTS_ADD_EX_SM(ws_reliable_send_flushes_route_inline,
                       WAMBLE_SUITE_FUNCTIONAL, "ws_gateway", ws_test_setup,
                       ws_test_teardown, 0);
WAMBLE_TESTS_ADD_DB_EX_SM(
    ws_server_protocol_discovery_and_fragmented_tos_roundtrip,
    WAMBLE_SUITE_FUNCTIONAL, "ws_gateway", ws_test_setup, ws_test_teardown, 0);
WAMBLE_TESTS_ADD_DB_EX_SM(ws_server_protocol_profile_terms_acceptance_roundtrip,
                          WAMBLE_SUITE_FUNCTIONAL, "ws_gateway", ws_test_setup,
                          ws_test_teardown, 0);
WAMBLE_TESTS_ADD_DB_EX_SM(ws_server_protocol_fragmented_profiles_list_roundtrip,
                          WAMBLE_SUITE_FUNCTIONAL, "ws_gateway", ws_test_setup,
                          ws_test_teardown, 0);
WAMBLE_TESTS_END()
