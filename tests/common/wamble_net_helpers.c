#include "wamble_net_helpers.h"
#include "wamble/wamble.h"

#if defined(WAMBLE_PLATFORM_POSIX)
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

int wamble_test_alloc_udp_port(void) {
#if defined(WAMBLE_PLATFORM_POSIX)
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
    return -1;
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(0);
  if (bind(sock, (struct sockaddr *)&addr, sizeof addr) != 0) {
    close(sock);
    return -1;
  }
  socklen_t len = sizeof addr;
  if (getsockname(sock, (struct sockaddr *)&addr, &len) != 0) {
    close(sock);
    return -1;
  }
  int port = (int)ntohs(addr.sin_port);
  close(sock);
  return port;
#elif defined(WAMBLE_PLATFORM_WINDOWS)
  if (wamble_net_init() != 0)
    return -1;
  wamble_socket_t sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock == WAMBLE_INVALID_SOCKET)
    return -1;
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(0);
  if (bind(sock, (struct sockaddr *)&addr, sizeof addr) != 0) {
    wamble_close_socket(sock);
    return -1;
  }
  wamble_socklen_t len = (wamble_socklen_t)sizeof addr;
  if (getsockname(sock, (struct sockaddr *)&addr, &len) != 0) {
    wamble_close_socket(sock);
    return -1;
  }
  int port = (int)ntohs(addr.sin_port);
  wamble_close_socket(sock);
  return port;
#else
  return -1;
#endif
}

int wamble_test_wait_readable(wamble_socket_t sock, int timeout_ms) {
#if defined(WAMBLE_PLATFORM_POSIX)
  int fd = (int)sock;
  fd_set rset;
  FD_ZERO(&rset);
  FD_SET(fd, &rset);
  struct timeval tv;
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  int rc = select(fd + 1, &rset, NULL, NULL, &tv);
  if (rc < 0)
    return -1;
  return rc == 0 ? 1 : 0;
#elif defined(WAMBLE_PLATFORM_WINDOWS)
  fd_set rset;
  FD_ZERO(&rset);
  FD_SET(sock, &rset);
  struct timeval tv;
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  int rc = select(0, &rset, NULL, NULL, &tv);
  if (rc == SOCKET_ERROR)
    return -1;
  return rc == 0 ? 1 : 0;
#else
  (void)sock;
  (void)timeout_ms;
  return -1;
#endif
}

#if defined(__unix__) && !defined(__APPLE__)
#define WAMBLE_HAVE_PTHREAD_TIMEDJOIN 1
#endif

#ifdef __unix__
#include <pthread.h>
#include <time.h>

#ifdef WAMBLE_HAVE_PTHREAD_TIMEDJOIN

int pthread_timedjoin_np(pthread_t thread, void **retval,
                         const struct timespec *abstime);
#endif

int wamble_test_join_thread_with_timeout(pthread_t thr, int timeout_ms) {
#ifdef WAMBLE_HAVE_PTHREAD_TIMEDJOIN
  struct timespec ts;
  if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
    return -1;
  ts.tv_sec += timeout_ms / 1000;
  long add_ns = (long)(timeout_ms % 1000) * 1000000L;
  ts.tv_nsec += add_ns;
  if (ts.tv_nsec >= 1000000000L) {
    ts.tv_sec += 1;
    ts.tv_nsec -= 1000000000L;
  }
  int rc = pthread_timedjoin_np(thr, NULL, &ts);
  if (rc == 0)
    return 0;
  if (rc == ETIMEDOUT)
    return 1;
  return -1;
#else
  (void)thr;
  (void)timeout_ms;
  return -2;
#endif
}
#endif

wamble_socket_t wamble_test_ws_connect(int port) {
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

int wamble_test_ws_handshake(wamble_socket_t sock, const char *path,
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

int wamble_test_ws_send_frame_ex(wamble_socket_t sock, uint8_t fin,
                                 uint8_t opcode, const uint8_t *payload,
                                 size_t len, int force_ext126) {
  uint8_t frame[526];
  size_t frame_len = 0;
  uint8_t hdr[14];
  size_t hlen = 0;
  hdr[hlen++] = (uint8_t)(((fin ? 1u : 0u) << 7) | (opcode & 0x0Fu));
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

int wamble_test_ws_send_frame(wamble_socket_t sock, uint8_t opcode,
                              const uint8_t *payload, size_t len,
                              int force_ext126) {
  return wamble_test_ws_send_frame_ex(sock, 1u, opcode, payload, len,
                                      force_ext126);
}

int wamble_test_ws_recv_frame(wamble_socket_t sock, uint8_t *out_opcode,
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

int wamble_test_ws_recv_http(wamble_socket_t sock, char *out, size_t cap) {
  size_t used = 0;
  uint64_t deadline = wamble_now_mono_millis() + 2000;
  while (used + 1 < cap && wamble_now_mono_millis() < deadline) {
    int wait_rc = wamble_test_wait_readable(sock, 5);
    if (wait_rc != 0)
      continue;
    ws_test_io_count_t n = recv(sock, out + used,
#ifdef WAMBLE_PLATFORM_WINDOWS
                                (int)(cap - used - 1),
#else
                                cap - used - 1,
#endif
                                0);
    if (n <= 0)
      continue;
    used += (size_t)n;
    out[used] = '\0';
    if (strstr(out, "\r\n\r\n") != NULL)
      return 0;
  }
  return -1;
}

int wamble_test_ws_send_handshake_with_first_frame(wamble_socket_t sock,
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

WambleWsGateway *wamble_test_start_gateway(int *out_tcp_port,
                                           wamble_socket_t *out_udp_sock,
                                           WsGatewayStatus *out_status,
                                           int *out_last_port) {
  if (!out_tcp_port)
    return NULL;
  if (out_udp_sock)
    *out_udp_sock = WAMBLE_INVALID_SOCKET;

  WambleWsGateway *gw = NULL;
  int tcp_port = 0;
  for (int i = 0; i < 64; i++) {
    int cand = wamble_test_alloc_udp_port();
    if (cand <= 0) {
      if (out_status)
        *out_status = WS_GATEWAY_ERR_BIND;
      if (out_last_port)
        *out_last_port = -3;
      break;
    }
    WsGatewayStatus st = WS_GATEWAY_OK;
    gw = ws_gateway_start("test", cand, 1, "/ws", 8, &st);
    if (out_status)
      *out_status = st;
    if (out_last_port)
      *out_last_port = cand;
    if (gw) {
      tcp_port = cand;
      break;
    }
    if (st != WS_GATEWAY_ERR_BIND)
      break;
  }
  if (!gw || tcp_port <= 0) {
    return NULL;
  }

  *out_tcp_port = tcp_port;
  return gw;
}
