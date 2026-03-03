#include "common/wamble_net_helpers.h"
#include "common/wamble_test.h"
#include "wamble/wamble.h"

static WsGatewayStatus g_last_ws_status = WS_GATEWAY_OK;
static int g_last_ws_port = 0;
static WambleWsGateway *g_test_gateway = NULL;
static wamble_socket_t g_test_udp = WAMBLE_INVALID_SOCKET;
static wamble_socket_t g_test_client = WAMBLE_INVALID_SOCKET;

static void ws_close_tracked_socket(wamble_socket_t *sock) {
  if (!sock || *sock == WAMBLE_INVALID_SOCKET)
    return;
  wamble_close_socket(*sock);
  *sock = WAMBLE_INVALID_SOCKET;
}

static void ws_test_setup(void) {
  g_test_gateway = NULL;
  g_test_udp = WAMBLE_INVALID_SOCKET;
  g_test_client = WAMBLE_INVALID_SOCKET;
  (void)wamble_net_init();
}

static void ws_test_teardown(void) {
  ws_close_tracked_socket(&g_test_client);
  if (g_test_gateway) {
    ws_gateway_stop(g_test_gateway);
    g_test_gateway = NULL;
  }
  ws_close_tracked_socket(&g_test_udp);
  wamble_net_cleanup();
}

WAMBLE_TEST(ws_handshake_rejects_invalid_key) {
  config_load(NULL, NULL, NULL, 0);
  int port = 0;
  wamble_socket_t udp = WAMBLE_INVALID_SOCKET;
  g_test_gateway = wamble_test_start_gateway(&port, &udp, &g_last_ws_status,
                                             &g_last_ws_port);
  g_test_udp = udp;
  if (!g_test_gateway)
    T_FAIL("gateway start failed status=%d port=%d", (int)g_last_ws_status,
           g_last_ws_port);

  wamble_socket_t c = wamble_test_ws_connect(port);
  g_test_client = c;
  T_ASSERT(c != WAMBLE_INVALID_SOCKET);
  T_ASSERT_STATUS_OK(wamble_test_ws_handshake(c, "/ws", "abc", "13"));

  char resp[1024];
  T_ASSERT_STATUS_OK(wamble_test_ws_recv_http(c, resp, sizeof(resp)));
  T_ASSERT(strstr(resp, "HTTP/1.1 400") != NULL);

  return 0;
}

WAMBLE_TEST(ws_handshake_wrong_version_426) {
  config_load(NULL, NULL, NULL, 0);
  int port = 0;
  wamble_socket_t udp = WAMBLE_INVALID_SOCKET;
  g_test_gateway = wamble_test_start_gateway(&port, &udp, &g_last_ws_status,
                                             &g_last_ws_port);
  g_test_udp = udp;
  if (!g_test_gateway)
    T_FAIL("gateway start failed status=%d port=%d", (int)g_last_ws_status,
           g_last_ws_port);

  wamble_socket_t c = wamble_test_ws_connect(port);
  g_test_client = c;
  T_ASSERT(c != WAMBLE_INVALID_SOCKET);
  T_ASSERT_STATUS_OK(
      wamble_test_ws_handshake(c, "/ws", "dGhlIHNhbXBsZSBub25jZQ==", "12"));

  char resp[1024];
  T_ASSERT_STATUS_OK(wamble_test_ws_recv_http(c, resp, sizeof(resp)));
  T_ASSERT(strstr(resp, "HTTP/1.1 426") != NULL);
  T_ASSERT(strstr(resp, "Sec-WebSocket-Version: 13") != NULL);

  return 0;
}

WAMBLE_TEST(ws_oversized_control_frame_closes_protocol_error) {
  config_load(NULL, NULL, NULL, 0);
  int port = 0;
  wamble_socket_t udp = WAMBLE_INVALID_SOCKET;
  g_test_gateway = wamble_test_start_gateway(&port, &udp, &g_last_ws_status,
                                             &g_last_ws_port);
  g_test_udp = udp;
  if (!g_test_gateway)
    T_FAIL("gateway start failed status=%d port=%d", (int)g_last_ws_status,
           g_last_ws_port);

  wamble_socket_t c = wamble_test_ws_connect(port);
  g_test_client = c;
  T_ASSERT(c != WAMBLE_INVALID_SOCKET);
  T_ASSERT_STATUS_OK(
      wamble_test_ws_handshake(c, "/ws", "dGhlIHNhbXBsZSBub25jZQ==", "13"));
  {
    char hresp[1024];
    T_ASSERT_STATUS_OK(wamble_test_ws_recv_http(c, hresp, sizeof(hresp)));
    T_ASSERT(strstr(hresp, "HTTP/1.1 101") != NULL);
  }

  uint8_t payload[126];
  memset(payload, 0xAB, sizeof(payload));
  T_ASSERT_STATUS_OK(
      wamble_test_ws_send_frame(c, 0x9u, payload, sizeof(payload), 1));

  uint8_t opcode = 0;
  uint8_t in[128];
  size_t in_len = 0;
  T_ASSERT_STATUS_OK(
      wamble_test_ws_recv_frame(c, &opcode, in, sizeof(in), &in_len));
  T_ASSERT_EQ_INT(opcode, 0x8);
  T_ASSERT(in_len >= 2u);
  uint16_t code = (uint16_t)(((uint16_t)in[0] << 8) | in[1]);
  T_ASSERT_EQ_INT((int)code, 1002);

  return 0;
}

WAMBLE_TEST(ws_unsupported_opcode_closes_protocol_error) {
  config_load(NULL, NULL, NULL, 0);
  int port = 0;
  wamble_socket_t udp = WAMBLE_INVALID_SOCKET;
  g_test_gateway = wamble_test_start_gateway(&port, &udp, &g_last_ws_status,
                                             &g_last_ws_port);
  g_test_udp = udp;
  if (!g_test_gateway)
    T_FAIL("gateway start failed status=%d port=%d", (int)g_last_ws_status,
           g_last_ws_port);

  wamble_socket_t c = wamble_test_ws_connect(port);
  g_test_client = c;
  T_ASSERT(c != WAMBLE_INVALID_SOCKET);
  T_ASSERT_STATUS_OK(
      wamble_test_ws_handshake(c, "/ws", "dGhlIHNhbXBsZSBub25jZQ==", "13"));
  {
    char hresp[1024];
    T_ASSERT_STATUS_OK(wamble_test_ws_recv_http(c, hresp, sizeof(hresp)));
    T_ASSERT(strstr(hresp, "HTTP/1.1 101") != NULL);
  }

  uint8_t payload[2] = {'h', 'i'};
  T_ASSERT_STATUS_OK(
      wamble_test_ws_send_frame(c, 0x1u, payload, sizeof(payload), 0));

  uint8_t opcode = 0;
  uint8_t in[128];
  size_t in_len = 0;
  T_ASSERT_STATUS_OK(
      wamble_test_ws_recv_frame(c, &opcode, in, sizeof(in), &in_len));
  T_ASSERT_EQ_INT(opcode, 0x8);
  T_ASSERT(in_len >= 2u);
  uint16_t code = (uint16_t)(((uint16_t)in[0] << 8) | in[1]);
  T_ASSERT_EQ_INT((int)code, 1002);

  return 0;
}

WAMBLE_TEST(ws_binary_roundtrip_and_coalesced_first_frame) {
  config_load(NULL, NULL, NULL, 0);
  int port = 0;
  wamble_socket_t udp = WAMBLE_INVALID_SOCKET;
  g_test_gateway = wamble_test_start_gateway(&port, &udp, &g_last_ws_status,
                                             &g_last_ws_port);
  g_test_udp = udp;
  if (!g_test_gateway)
    T_FAIL("gateway start failed status=%d port=%d", (int)g_last_ws_status,
           g_last_ws_port);

  wamble_socket_t c = wamble_test_ws_connect(port);
  g_test_client = c;
  T_ASSERT(c != WAMBLE_INVALID_SOCKET);

  uint8_t first_payload[] = {0x11u, 0x22u, 0x33u, 0x44u};
  T_ASSERT_STATUS_OK(wamble_test_ws_send_handshake_with_first_frame(
      c, "/ws", first_payload, sizeof(first_payload)));
  {
    char resp[1024];
    T_ASSERT_STATUS_OK(wamble_test_ws_recv_http(c, resp, sizeof(resp)));
    T_ASSERT(strstr(resp, "HTTP/1.1 101") != NULL);
  }

  {
    uint8_t got[64];
    size_t got_len = 0;
    struct sockaddr_in src;
    memset(&src, 0, sizeof(src));
    T_ASSERT_STATUS_OK(wamble_test_wait_readable(udp, 2000));
    wamble_socklen_t srclen = (wamble_socklen_t)sizeof(src);
    ws_test_io_count_t nr = recvfrom(udp, (char *)got,
#ifdef WAMBLE_PLATFORM_WINDOWS
                                     (int)sizeof(got),
#else
                                     sizeof(got),
#endif
                                     0, (struct sockaddr *)&src, &srclen);
    T_ASSERT(nr > 0);
    got_len = (size_t)nr;
    T_ASSERT_EQ_INT((int)got_len, (int)sizeof(first_payload));
    T_ASSERT(memcmp(got, first_payload, sizeof(first_payload)) == 0);

    uint8_t back[] = {0x90u, 0x80u, 0x70u};
    ws_test_io_count_t sent =
        sendto(udp, (const char *)back,
#ifdef WAMBLE_PLATFORM_WINDOWS
               (int)sizeof(back),
#else
               sizeof(back),
#endif
               0, (const struct sockaddr *)&src, (wamble_socklen_t)sizeof(src));
    T_ASSERT(sent == (ws_test_io_count_t)sizeof(back));

    uint8_t opcode = 0;
    uint8_t in[128];
    size_t in_len = 0;
    T_ASSERT_STATUS_OK(
        wamble_test_ws_recv_frame(c, &opcode, in, sizeof(in), &in_len));
    T_ASSERT_EQ_INT(opcode, 0x2);
    T_ASSERT_EQ_INT((int)in_len, (int)sizeof(back));
    T_ASSERT(memcmp(in, back, sizeof(back)) == 0);
  }

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
WAMBLE_TESTS_END()
