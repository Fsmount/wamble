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
  snprintf(out.fen, sizeof(out.fen), "server-msg");
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
  snprintf(out.fen, sizeof(out.fen), "ws-reliable");

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
  snprintf(out_a.fen, sizeof(out_a.fen), "batch-a");

  struct WambleMsg out_b = {0};
  out_b.ctrl = WAMBLE_CTRL_SERVER_NOTIFICATION;
  memcpy(out_b.token, bootstrap.token, TOKEN_LENGTH);
  snprintf(out_b.fen, sizeof(out_b.fen), "batch-b");

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
  T_ASSERT(strcmp(dec_a.fen, "batch-a") == 0);
  T_ASSERT(strcmp(dec_b.fen, "batch-b") == 0);

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
WAMBLE_TESTS_END()
