#include "common/wamble_net_helpers.h"
#include "common/wamble_test.h"
#include "wamble/wamble.h"

#if defined(WAMBLE_PLATFORM_WINDOWS)
typedef int ws_test_io_count_t;
#else
typedef ssize_t ws_test_io_count_t;
#endif

static void sleep_ms_local(int ms) {
  struct timeval tv;
  tv.tv_sec = ms / 1000;
  tv.tv_usec = (ms % 1000) * 1000;
#ifdef WAMBLE_PLATFORM_WINDOWS
  select(0, NULL, NULL, NULL, &tv);
#else
  select(0, NULL, NULL, NULL, &tv);
#endif
}

static WsGatewayStatus g_last_ws_status = WS_GATEWAY_OK;
static int g_last_ws_port = 0;

static void ws_test_setup(void) { (void)wamble_net_init(); }

static void ws_test_teardown(void) { wamble_net_cleanup(); }

static int socket_port(wamble_socket_t sock) {
  struct sockaddr_in addr;
  wamble_socklen_t len = (wamble_socklen_t)sizeof(addr);
  if (getsockname(sock, (struct sockaddr *)&addr, &len) != 0)
    return -1;
  return (int)ntohs(addr.sin_port);
}

static wamble_socket_t connect_tcp_loopback(int port) {
  wamble_socket_t c = socket(AF_INET, SOCK_STREAM, 0);
  if (c == WAMBLE_INVALID_SOCKET)
    return WAMBLE_INVALID_SOCKET;
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons((uint16_t)port);
  if (connect(c, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
    wamble_close_socket(c);
    return WAMBLE_INVALID_SOCKET;
  }
  return c;
}

static int recv_http_headers(wamble_socket_t sock, char *out, size_t cap) {
  size_t used = 0;
  uint64_t deadline = wamble_now_mono_millis() + 2000;
  while (used + 1 < cap && wamble_now_mono_millis() < deadline) {
    ws_test_io_count_t n = recv(sock, out + used,
#ifdef WAMBLE_PLATFORM_WINDOWS
                                (int)(cap - used - 1),
#else
                                cap - used - 1,
#endif
                                0);
    if (n <= 0) {
      sleep_ms_local(5);
      continue;
    }
    used += (size_t)n;
    out[used] = '\0';
    if (strstr(out, "\r\n\r\n") != NULL)
      return 0;
  }
  return -1;
}

static int send_handshake(wamble_socket_t sock, const char *path,
                          const char *key, const char *version) {
  char req[1024];
  int n = snprintf(req, sizeof(req),
                   "GET %s HTTP/1.1\r\n"
                   "Host: localhost\r\n"
                   "Upgrade: websocket\r\n"
                   "Connection: Upgrade\r\n"
                   "Sec-WebSocket-Key: %s\r\n"
                   "Sec-WebSocket-Version: %s\r\n"
                   "\r\n",
                   path, key, version);
  if (n <= 0 || (size_t)n >= sizeof(req))
    return -1;
  ws_test_io_count_t rc = send(sock, req,
#ifdef WAMBLE_PLATFORM_WINDOWS
                               n,
#else
                               (size_t)n,
#endif
                               0);
  return (rc == n) ? 0 : -1;
}

static int send_masked_frame(wamble_socket_t sock, uint8_t opcode,
                             const uint8_t *payload, size_t len,
                             int force_ext126) {
  uint8_t frame[526];
  size_t frame_len = 0;
  uint8_t hdr[14];
  size_t hlen = 0;
  hdr[hlen++] = (uint8_t)(0x80u | (opcode & 0x0Fu));
  if (!force_ext126 && len <= 125u) {
    hdr[hlen++] = (uint8_t)(0x80u | (uint8_t)len);
  } else {
    hdr[hlen++] = (uint8_t)(0x80u | 126u);
    hdr[hlen++] = (uint8_t)((len >> 8) & 0xFFu);
    hdr[hlen++] = (uint8_t)(len & 0xFFu);
  }
  uint8_t mask[4] = {1, 2, 3, 4};
  memcpy(hdr + hlen, mask, 4);
  hlen += 4;
  if (hlen + len > sizeof(frame))
    return -1;
  memcpy(frame, hdr, hlen);
  for (size_t i = 0; i < len; i++)
    frame[hlen + i] = payload[i] ^ mask[i % 4u];
  frame_len = hlen + len;
  if (send(sock, (const char *)frame,
#ifdef WAMBLE_PLATFORM_WINDOWS
           (int)frame_len,
#else
           frame_len,
#endif
           0) != (int)frame_len) {
    return -1;
  }
  return 0;
}

static int recv_udp_packet(wamble_socket_t sock, uint8_t *out, size_t cap,
                           size_t *out_len, struct sockaddr_in *from) {
  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(sock, &rfds);
  struct timeval tv;
  tv.tv_sec = 2;
  tv.tv_usec = 0;
  int sel =
#ifdef WAMBLE_PLATFORM_WINDOWS
      select(0, &rfds, NULL, NULL, &tv);
#else
      select(sock + 1, &rfds, NULL, NULL, &tv);
#endif
  if (sel <= 0 || !FD_ISSET(sock, &rfds))
    return -1;

  struct sockaddr_in src;
  wamble_socklen_t slen = (wamble_socklen_t)sizeof(src);
  ws_test_io_count_t n = recvfrom(sock, (char *)out,
#ifdef WAMBLE_PLATFORM_WINDOWS
                                  (int)cap,
#else
                                  cap,
#endif
                                  0, (struct sockaddr *)&src, &slen);
  if (n <= 0)
    return -1;
  if (out_len)
    *out_len = (size_t)n;
  if (from)
    *from = src;
  return 0;
}

static int send_handshake_with_first_frame(wamble_socket_t sock,
                                           const char *path,
                                           const uint8_t *payload,
                                           size_t payload_len) {
  uint8_t hdr[14];
  size_t frame_len = 0;
  hdr[frame_len++] = (uint8_t)(0x80u | 0x2u);
  if (payload_len <= 125u) {
    hdr[frame_len++] = (uint8_t)(0x80u | (uint8_t)payload_len);
  } else {
    return -1;
  }
  {
    uint8_t mask[4] = {1, 2, 3, 4};
    memcpy(hdr + frame_len, mask, 4);
    frame_len += 4;
  }
  uint8_t frame[256];
  if (frame_len + payload_len > sizeof(frame))
    return -1;
  memcpy(frame, hdr, frame_len);
  for (size_t i = 0; i < payload_len; i++) {
    frame[frame_len + i] = payload[i] ^ hdr[2 + (i % 4u)];
  }
  frame_len += payload_len;

  char req[1024];
  int n = snprintf(req, sizeof(req),
                   "GET %s HTTP/1.1\r\n"
                   "Host: localhost\r\n"
                   "Upgrade: websocket\r\n"
                   "Connection: Upgrade\r\n"
                   "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                   "Sec-WebSocket-Version: 13\r\n"
                   "\r\n",
                   path);
  if (n <= 0 || (size_t)n >= sizeof(req))
    return -1;
  uint8_t out[1400];
  if ((size_t)n + frame_len > sizeof(out))
    return -1;
  memcpy(out, req, (size_t)n);
  memcpy(out + (size_t)n, frame, frame_len);

  ws_test_io_count_t rc = send(sock, (const char *)out,
#ifdef WAMBLE_PLATFORM_WINDOWS
                               (int)((size_t)n + frame_len),
#else
                               (size_t)n + frame_len,
#endif
                               0);
  return (rc == (ws_test_io_count_t)((size_t)n + frame_len)) ? 0 : -1;
}

static int recv_ws_frame(wamble_socket_t sock, uint8_t *out_opcode,
                         uint8_t *payload, size_t payload_cap,
                         size_t *out_len) {
  uint8_t h2[2];
  ws_test_io_count_t n = recv(sock, (char *)h2, 2, 0);
  if (n != 2)
    return -1;
  uint8_t opcode = (uint8_t)(h2[0] & 0x0Fu);
  uint8_t masked = (uint8_t)((h2[1] >> 7) & 1u);
  uint64_t len = (uint64_t)(h2[1] & 0x7Fu);
  if (masked)
    return -1;
  if (len == 126u) {
    uint8_t ext[2];
    if (recv(sock, (char *)ext, 2, 0) != 2)
      return -1;
    len = ((uint64_t)ext[0] << 8) | ext[1];
  } else if (len == 127u) {
    return -1;
  }
  if (len > payload_cap)
    return -1;
  size_t got = 0;
  while (got < len) {
    ws_test_io_count_t r = recv(sock, (char *)(payload + got),
#ifdef WAMBLE_PLATFORM_WINDOWS
                                (int)(len - got),
#else
                                len - got,
#endif
                                0);
    if (r <= 0)
      return -1;
    got += (size_t)r;
  }
  *out_opcode = opcode;
  *out_len = (size_t)len;
  return 0;
}

static WambleWsGateway *start_gateway_for_test(int *out_tcp_port,
                                               wamble_socket_t *out_udp_sock) {
  g_last_ws_status = WS_GATEWAY_OK;
  g_last_ws_port = 0;
  wamble_socket_t udp = create_and_bind_socket(0);
  if (udp == WAMBLE_INVALID_SOCKET) {
    g_last_ws_status = WS_GATEWAY_ERR_BIND;
    g_last_ws_port = -1;
    return NULL;
  }
  int udp_port = socket_port(udp);
  if (udp_port <= 0) {
    g_last_ws_status = WS_GATEWAY_ERR_BIND;
    g_last_ws_port = -2;
    wamble_close_socket(udp);
    return NULL;
  }

  WambleWsGateway *gw = NULL;
  int tcp_port = 0;
  for (int i = 0; i < 64; i++) {
    int cand = wamble_test_alloc_udp_port();
    if (cand <= 0) {
      g_last_ws_status = WS_GATEWAY_ERR_BIND;
      g_last_ws_port = -3;
      break;
    }
    WsGatewayStatus st = WS_GATEWAY_OK;
    gw = ws_gateway_start("test", cand, udp_port, "/ws", 8, &st);
    g_last_ws_status = st;
    g_last_ws_port = cand;
    if (gw) {
      tcp_port = cand;
      break;
    }
    if (st != WS_GATEWAY_ERR_BIND)
      break;
  }
  if (!gw || tcp_port <= 0) {
    wamble_close_socket(udp);
    return NULL;
  }

  *out_tcp_port = tcp_port;
  *out_udp_sock = udp;
  return gw;
}

WAMBLE_TEST(ws_handshake_rejects_invalid_key) {
  config_load(NULL, NULL, NULL, 0);
  int port = 0;
  wamble_socket_t udp = WAMBLE_INVALID_SOCKET;
  WambleWsGateway *gw = start_gateway_for_test(&port, &udp);
  if (!gw)
    T_FAIL("gateway start failed status=%d port=%d", (int)g_last_ws_status,
           g_last_ws_port);

  wamble_socket_t c = connect_tcp_loopback(port);
  T_ASSERT(c != WAMBLE_INVALID_SOCKET);
  T_ASSERT_STATUS_OK(send_handshake(c, "/ws", "abc", "13"));

  char resp[1024];
  T_ASSERT_STATUS_OK(recv_http_headers(c, resp, sizeof(resp)));
  T_ASSERT(strstr(resp, "HTTP/1.1 400") != NULL);

  wamble_close_socket(c);
  ws_gateway_stop(gw);
  wamble_close_socket(udp);
  return 0;
}

WAMBLE_TEST(ws_handshake_wrong_version_426) {
  config_load(NULL, NULL, NULL, 0);
  int port = 0;
  wamble_socket_t udp = WAMBLE_INVALID_SOCKET;
  WambleWsGateway *gw = start_gateway_for_test(&port, &udp);
  if (!gw)
    T_FAIL("gateway start failed status=%d port=%d", (int)g_last_ws_status,
           g_last_ws_port);

  wamble_socket_t c = connect_tcp_loopback(port);
  T_ASSERT(c != WAMBLE_INVALID_SOCKET);
  T_ASSERT_STATUS_OK(
      send_handshake(c, "/ws", "dGhlIHNhbXBsZSBub25jZQ==", "12"));

  char resp[1024];
  T_ASSERT_STATUS_OK(recv_http_headers(c, resp, sizeof(resp)));
  T_ASSERT(strstr(resp, "HTTP/1.1 426") != NULL);
  T_ASSERT(strstr(resp, "Sec-WebSocket-Version: 13") != NULL);

  wamble_close_socket(c);
  ws_gateway_stop(gw);
  wamble_close_socket(udp);
  return 0;
}

static int ws_expect_open(wamble_socket_t c) {
  T_ASSERT_STATUS_OK(
      send_handshake(c, "/ws", "dGhlIHNhbXBsZSBub25jZQ==", "13"));
  char resp[1024];
  T_ASSERT_STATUS_OK(recv_http_headers(c, resp, sizeof(resp)));
  T_ASSERT(strstr(resp, "HTTP/1.1 101") != NULL);
  return 0;
}

WAMBLE_TEST(ws_oversized_control_frame_closes_protocol_error) {
  config_load(NULL, NULL, NULL, 0);
  int port = 0;
  wamble_socket_t udp = WAMBLE_INVALID_SOCKET;
  WambleWsGateway *gw = start_gateway_for_test(&port, &udp);
  if (!gw)
    T_FAIL("gateway start failed status=%d port=%d", (int)g_last_ws_status,
           g_last_ws_port);

  wamble_socket_t c = connect_tcp_loopback(port);
  T_ASSERT(c != WAMBLE_INVALID_SOCKET);
  T_ASSERT_STATUS_OK(ws_expect_open(c));

  uint8_t payload[126];
  memset(payload, 0xAB, sizeof(payload));
  T_ASSERT_STATUS_OK(send_masked_frame(c, 0x9u, payload, sizeof(payload), 1));

  uint8_t opcode = 0;
  uint8_t in[128];
  size_t in_len = 0;
  T_ASSERT_STATUS_OK(recv_ws_frame(c, &opcode, in, sizeof(in), &in_len));
  T_ASSERT_EQ_INT(opcode, 0x8);
  T_ASSERT(in_len >= 2u);
  uint16_t code = (uint16_t)(((uint16_t)in[0] << 8) | in[1]);
  T_ASSERT_EQ_INT((int)code, 1002);

  wamble_close_socket(c);
  ws_gateway_stop(gw);
  wamble_close_socket(udp);
  return 0;
}

WAMBLE_TEST(ws_unsupported_opcode_closes_protocol_error) {
  config_load(NULL, NULL, NULL, 0);
  int port = 0;
  wamble_socket_t udp = WAMBLE_INVALID_SOCKET;
  WambleWsGateway *gw = start_gateway_for_test(&port, &udp);
  if (!gw)
    T_FAIL("gateway start failed status=%d port=%d", (int)g_last_ws_status,
           g_last_ws_port);

  wamble_socket_t c = connect_tcp_loopback(port);
  T_ASSERT(c != WAMBLE_INVALID_SOCKET);
  T_ASSERT_STATUS_OK(ws_expect_open(c));

  uint8_t payload[2] = {'h', 'i'};
  T_ASSERT_STATUS_OK(send_masked_frame(c, 0x1u, payload, sizeof(payload), 0));

  uint8_t opcode = 0;
  uint8_t in[128];
  size_t in_len = 0;
  T_ASSERT_STATUS_OK(recv_ws_frame(c, &opcode, in, sizeof(in), &in_len));
  T_ASSERT_EQ_INT(opcode, 0x8);
  T_ASSERT(in_len >= 2u);
  uint16_t code = (uint16_t)(((uint16_t)in[0] << 8) | in[1]);
  T_ASSERT_EQ_INT((int)code, 1002);

  wamble_close_socket(c);
  ws_gateway_stop(gw);
  wamble_close_socket(udp);
  return 0;
}

WAMBLE_TEST(ws_binary_roundtrip_and_coalesced_first_frame) {
  config_load(NULL, NULL, NULL, 0);
  int port = 0;
  wamble_socket_t udp = WAMBLE_INVALID_SOCKET;
  WambleWsGateway *gw = start_gateway_for_test(&port, &udp);
  if (!gw)
    T_FAIL("gateway start failed status=%d port=%d", (int)g_last_ws_status,
           g_last_ws_port);

  wamble_socket_t c = connect_tcp_loopback(port);
  T_ASSERT(c != WAMBLE_INVALID_SOCKET);

  uint8_t first_payload[] = {0x11u, 0x22u, 0x33u, 0x44u};
  T_ASSERT_STATUS_OK(send_handshake_with_first_frame(c, "/ws", first_payload,
                                                     sizeof(first_payload)));
  {
    char resp[1024];
    T_ASSERT_STATUS_OK(recv_http_headers(c, resp, sizeof(resp)));
    T_ASSERT(strstr(resp, "HTTP/1.1 101") != NULL);
  }

  {
    uint8_t got[64];
    size_t got_len = 0;
    struct sockaddr_in src;
    memset(&src, 0, sizeof(src));
    T_ASSERT_STATUS_OK(recv_udp_packet(udp, got, sizeof(got), &got_len, &src));
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
    T_ASSERT_STATUS_OK(recv_ws_frame(c, &opcode, in, sizeof(in), &in_len));
    T_ASSERT_EQ_INT(opcode, 0x2);
    T_ASSERT_EQ_INT((int)in_len, (int)sizeof(back));
    T_ASSERT(memcmp(in, back, sizeof(back)) == 0);
  }

  wamble_close_socket(c);
  ws_gateway_stop(gw);
  wamble_close_socket(udp);
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
