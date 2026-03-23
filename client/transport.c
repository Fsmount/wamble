#include "wamble/wamble_client.h"

#if defined(WAMBLE_PLATFORM_WASM)
/* ---- WASM transport: Emscripten WebSocket API + ring buffer ---- */
#include <emscripten/emscripten.h>
#include <emscripten/websocket.h>

static struct WambleMsg *wasm_ring_buf;
static int wasm_ring_cap;
static int wasm_ring_head;
static int wasm_ring_tail;
static int wasm_ring_count;

static EMSCRIPTEN_WEBSOCKET_T wasm_ws_handle;
static int wasm_ws_connected;
static int wasm_ws_closed;

static int wasm_ring_ensure_capacity(int need) {
  if (need <= wasm_ring_cap)
    return 0;
  int next_cap = (wasm_ring_cap > 0) ? wasm_ring_cap : 256;
  while (next_cap < need) {
    if (next_cap > (INT32_MAX / 2))
      return -1;
    next_cap *= 2;
  }
  struct WambleMsg *next =
      (struct WambleMsg *)calloc((size_t)next_cap, sizeof(*next));
  if (!next)
    return -1;
  for (int i = 0; i < wasm_ring_count; i++) {
    int src = (wasm_ring_tail + i) % (wasm_ring_cap > 0 ? wasm_ring_cap : 1);
    if (wasm_ring_cap > 0)
      next[i] = wasm_ring_buf[src];
  }
  free(wasm_ring_buf);
  wasm_ring_buf = next;
  wasm_ring_cap = next_cap;
  wasm_ring_tail = 0;
  wasm_ring_head = wasm_ring_count;
  return 0;
}

static int wasm_ring_push(const struct WambleMsg *msg) {
  if (!msg)
    return -1;
  if (wasm_ring_ensure_capacity(wasm_ring_count + 1) != 0)
    return -1;
  if (wasm_ring_cap <= 0)
    return -1;
  wasm_ring_buf[wasm_ring_head] = *msg;
  wasm_ring_head = (wasm_ring_head + 1) % wasm_ring_cap;
  wasm_ring_count++;
  return 0;
}

static int wasm_ring_pop(struct WambleMsg *out) {
  if (wasm_ring_count <= 0)
    return -1;
  *out = wasm_ring_buf[wasm_ring_tail];
  wasm_ring_tail = (wasm_ring_tail + 1) % wasm_ring_cap;
  wasm_ring_count--;
  return 0;
}

static EM_BOOL wasm_on_ws_open(int event_type,
                               const EmscriptenWebSocketOpenEvent *event,
                               void *user_data) {
  (void)event_type;
  (void)event;
  (void)user_data;
  wasm_ws_connected = 1;
  wasm_ws_closed = 0;
  return EM_TRUE;
}

static EM_BOOL wasm_on_ws_message(int event_type,
                                  const EmscriptenWebSocketMessageEvent *event,
                                  void *user_data) {
  (void)event_type;
  (void)user_data;
  if (!event->isText && event->numBytes > 0) {
    const uint8_t *buf = (const uint8_t *)event->data;
    size_t total = (size_t)event->numBytes;
    size_t offset = 0;
    while (offset < total) {
      size_t packet_len = 0;
      struct WambleMsg msg;
      uint8_t flags = 0;
      if (wamble_wire_packet_size(buf + offset, total - offset, &packet_len) !=
              NET_OK ||
          packet_len == 0 || packet_len > (total - offset)) {
        break;
      }
      memset(&msg, 0, sizeof(msg));
      if (wamble_packet_deserialize(buf + offset, packet_len, &msg, &flags) ==
          NET_OK) {
        wasm_ring_push(&msg);
      }
      offset += packet_len;
    }
  }
  return EM_TRUE;
}

static EM_BOOL wasm_on_ws_close(int event_type,
                                const EmscriptenWebSocketCloseEvent *event,
                                void *user_data) {
  (void)event_type;
  (void)event;
  (void)user_data;
  wasm_ws_connected = 0;
  wasm_ws_closed = 1;
  return EM_TRUE;
}

static EM_BOOL wasm_on_ws_error(int event_type,
                                const EmscriptenWebSocketErrorEvent *event,
                                void *user_data) {
  (void)event_type;
  (void)event;
  (void)user_data;
  wasm_ws_connected = 0;
  wasm_ws_closed = 1;
  return EM_TRUE;
}

static int wasm_client_connect(const char *url) {
  if (wasm_ws_handle) {
    emscripten_websocket_close(wasm_ws_handle, 1000, "reconnect");
    emscripten_websocket_delete(wasm_ws_handle);
    wasm_ws_handle = 0;
  }
  wasm_ws_connected = 0;
  wasm_ws_closed = 0;
  free(wasm_ring_buf);
  wasm_ring_buf = NULL;
  wasm_ring_cap = 0;
  wasm_ring_head = 0;
  wasm_ring_tail = 0;
  wasm_ring_count = 0;

  EmscriptenWebSocketCreateAttributes attrs = {url, NULL, EM_TRUE};
  wasm_ws_handle = emscripten_websocket_new(&attrs);
  if (wasm_ws_handle <= 0)
    return -1;

  emscripten_websocket_set_onopen_callback(wasm_ws_handle, NULL,
                                           wasm_on_ws_open);
  emscripten_websocket_set_onmessage_callback(wasm_ws_handle, NULL,
                                              wasm_on_ws_message);
  emscripten_websocket_set_onclose_callback(wasm_ws_handle, NULL,
                                            wasm_on_ws_close);
  emscripten_websocket_set_onerror_callback(wasm_ws_handle, NULL,
                                            wasm_on_ws_error);
  return 0;
}

static int wasm_client_send_msg(struct WambleMsg *msg) {
  if (!wasm_ws_connected || !wasm_ws_handle)
    return -1;
  uint8_t buf[WAMBLE_MAX_PACKET_SIZE];
  size_t len = 0;
  if (wamble_packet_serialize(msg, buf, sizeof(buf), &len, msg->flags) !=
      NET_OK)
    return -1;
  EMSCRIPTEN_RESULT r =
      emscripten_websocket_send_binary(wasm_ws_handle, buf, (uint32_t)len);
  return (r == EMSCRIPTEN_RESULT_SUCCESS) ? 0 : -1;
}

static int wasm_client_recv_msg(struct WambleMsg *out) {
  return wasm_ring_pop(out);
}

static void wasm_client_close(void) {
  if (wasm_ws_handle) {
    emscripten_websocket_close(wasm_ws_handle, 1000, "goodbye");
    emscripten_websocket_delete(wasm_ws_handle);
    wasm_ws_handle = 0;
  }
  wasm_ws_connected = 0;
  wasm_ws_closed = 1;
  free(wasm_ring_buf);
  wasm_ring_buf = NULL;
  wasm_ring_cap = 0;
  wasm_ring_head = 0;
  wasm_ring_tail = 0;
  wasm_ring_count = 0;
}

static WambleClientStatus wasm_client_init_ws(wamble_client_t *c,
                                              wamble_socket_t sock) {
  if (!c || sock == WAMBLE_INVALID_SOCKET)
    return (WambleClientStatus){WAMBLE_CLIENT_STATUS_INVALID_ARGUMENT, 0};
  c->kind = WAMBLE_TRANSPORT_WS;
  c->sock = sock;
  memset(&c->peer, 0, sizeof(c->peer));
  c->seq = 0;
  return (WambleClientStatus){WAMBLE_CLIENT_STATUS_OK, 0};
}
static WambleClientStatus wasm_client_connect_web(wamble_client_t *c,
                                                  const char *url) {
  if (!c || !url || !*url)
    return (WambleClientStatus){WAMBLE_CLIENT_STATUS_INVALID_ARGUMENT, 0};
  memset(c, 0, sizeof(*c));
  c->kind = WAMBLE_TRANSPORT_WS;
  c->sock = WAMBLE_INVALID_SOCKET;
  if (wasm_client_connect(url) != 0)
    return (WambleClientStatus){WAMBLE_CLIENT_STATUS_NETWORK, 0};
  return (WambleClientStatus){WAMBLE_CLIENT_STATUS_OK, 0};
}
static WambleClientStatus wasm_client_send(wamble_client_t *c,
                                           struct WambleMsg *msg) {
  if (!c || !msg || c->kind != WAMBLE_TRANSPORT_WS)
    return (WambleClientStatus){WAMBLE_CLIENT_STATUS_INVALID_ARGUMENT, 0};
  msg->seq_num = c->seq++;
  if (wasm_client_send_msg(msg) != 0)
    return (WambleClientStatus){WAMBLE_CLIENT_STATUS_NETWORK, 0};
  return (WambleClientStatus){WAMBLE_CLIENT_STATUS_OK, 0};
}
static WambleClientStatus
wasm_client_recv(wamble_client_t *c, struct WambleMsg *out, int timeout_ms) {
  (void)timeout_ms;
  if (!c || !out || c->kind != WAMBLE_TRANSPORT_WS)
    return (WambleClientStatus){WAMBLE_CLIENT_STATUS_INVALID_ARGUMENT, 0};
  if (wasm_client_recv_msg(out) == 0)
    return (WambleClientStatus){WAMBLE_CLIENT_STATUS_OK, 0};
  return (WambleClientStatus){WAMBLE_CLIENT_STATUS_TIMEOUT, 0};
}
static void wasm_client_shutdown(wamble_client_t *c) {
  if (!c)
    return;
  if (c->kind == WAMBLE_TRANSPORT_WS)
    wasm_client_close();
  c->sock = WAMBLE_INVALID_SOCKET;
  c->kind = 0;
  memset(&c->peer, 0, sizeof(c->peer));
  c->seq = 0;
}

#else
/* ---- Native transport: raw sockets (POSIX / Windows) ---- */

#if defined(WAMBLE_PLATFORM_POSIX)
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

#if defined(WAMBLE_PLATFORM_WINDOWS)
typedef int wamble_client_io_count_t;
#else
typedef ssize_t wamble_client_io_count_t;
#endif

static const char ws_client_key[] = "dGhlIHNhbXBsZSBub25jZQ==";
static const char ws_client_accept[] = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
static const char ws_client_version[] = "13";

static int sock_wait_readable(wamble_socket_t sock, int timeout_ms) {
#if defined(WAMBLE_PLATFORM_POSIX)
  fd_set rset;
  FD_ZERO(&rset);
  FD_SET(sock, &rset);
  struct timeval tv;
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  int rc = select(sock + 1, &rset, NULL, NULL, &tv);
  if (rc < 0)
    return -1;
  return (rc == 0) ? 1 : 0;
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
  return (rc == 0) ? 1 : 0;
#else
  (void)sock;
  (void)timeout_ms;
  return -1;
#endif
}

static int sock_error_is_retryable(int err) {
#ifdef WAMBLE_PLATFORM_WINDOWS
  return err == WSAEINTR || err == WSAEINPROGRESS || err == WSAEWOULDBLOCK;
#else
  return err == EINTR || err == EAGAIN || err == EWOULDBLOCK;
#endif
}

static int native_ws_send_handshake(wamble_socket_t sock, const char *path,
                                    const char *host_header, const char *key,
                                    const char *version) {
  const char *req_host =
      (host_header && *host_header) ? host_header : "localhost";
  if (!path || !key || !version)
    return -1;
  char req[1024];
  int n = snprintf(req, sizeof(req),
                   "GET %s HTTP/1.1\r\n"
                   "Host: %s\r\n"
                   "Upgrade: websocket\r\n"
                   "Connection: Upgrade\r\n"
                   "Sec-WebSocket-Key: %s\r\n"
                   "Sec-WebSocket-Version: %s\r\n"
                   "\r\n",
                   path, req_host, key, version);
  if (n <= 0 || (size_t)n >= sizeof(req))
    return -1;
  wamble_client_io_count_t rc = send(sock, req,
#ifdef WAMBLE_PLATFORM_WINDOWS
                                     n,
#else
                                     (size_t)n,
#endif
                                     0);
  return (rc == n) ? 0 : -1;
}

static int native_ws_recv_http(wamble_socket_t sock, char *out, size_t cap) {
  size_t used = 0;
  uint64_t deadline = wamble_now_mono_millis() + 2000;
  while (used + 1 < cap && wamble_now_mono_millis() < deadline) {
    int wait_rc = sock_wait_readable(sock, 5);
    if (wait_rc != 0)
      continue;
    wamble_client_io_count_t n = recv(sock, out + used,
#ifdef WAMBLE_PLATFORM_WINDOWS
                                      (int)(cap - used - 1),
#else
                                      cap - used - 1,
#endif
                                      0);
    if (n == 0)
      return -1;
    if (n < 0) {
      int err = wamble_last_error();
      if (sock_error_is_retryable(err))
        continue;
      return -1;
    }
    used += (size_t)n;
    out[used] = '\0';
    if (strstr(out, "\r\n\r\n") != NULL)
      return 0;
  }
  return -1;
}

static int ws_validate_http_upgrade(const char *response) {
  char accept_header[128];
  if (!response)
    return -1;
  if (strstr(response, "HTTP/1.1 101") == NULL)
    return -1;
  if (strstr(response, "\r\nUpgrade: websocket\r\n") == NULL)
    return -1;
  if (strstr(response, "\r\nConnection: Upgrade\r\n") == NULL)
    return -1;
  if (snprintf(accept_header, sizeof(accept_header),
               "\r\nSec-WebSocket-Accept: %s\r\n", ws_client_accept) <= 0) {
    return -1;
  }
  if (strstr(response, accept_header) == NULL) {
    return -1;
  }
  return 0;
}

static int native_ws_send_frame_ex(wamble_socket_t sock, uint8_t fin,
                                   uint8_t opcode, const uint8_t *payload,
                                   size_t len, int force_ext126) {
  uint8_t frame[WAMBLE_MAX_PACKET_SIZE + 8];
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
  {
    uint8_t mask[4] = {1, 2, 3, 4};
    memcpy(hdr + hlen, mask, 4);
    hlen += 4;
    if (hlen + len > sizeof(frame))
      return -1;
    memcpy(frame, hdr, hlen);
    for (size_t i = 0; i < len; i++)
      frame[hlen + i] = payload[i] ^ mask[i % 4u];
  }
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

static int native_ws_send_frame(wamble_socket_t sock, uint8_t opcode,
                                const uint8_t *payload, size_t len,
                                int force_ext126) {
  return native_ws_send_frame_ex(sock, 1u, opcode, payload, len, force_ext126);
}

static int recv_exact(wamble_socket_t sock, uint8_t *buf, size_t len) {
  size_t got = 0;
  while (got < len) {
    wamble_client_io_count_t r = recv(sock, (char *)(buf + got),
#ifdef WAMBLE_PLATFORM_WINDOWS
                                      (int)(len - got),
#else
                                      len - got,
#endif
                                      0);
    if (r == 0)
      return -1;
    if (r < 0) {
      int err = wamble_last_error();
      if (sock_error_is_retryable(err))
        continue;
      return -1;
    }
    got += (size_t)r;
  }
  return 0;
}

static int native_ws_recv_frame(wamble_socket_t sock, uint8_t *out_opcode,
                                uint8_t *payload, size_t payload_cap,
                                size_t *out_len) {
  for (;;) {
    uint8_t h2[2];
    if (recv_exact(sock, h2, 2) != 0)
      return -1;

    uint8_t opcode = (uint8_t)(h2[0] & 0x0Fu);
    uint8_t masked = (uint8_t)((h2[1] >> 7) & 1u);
    uint64_t len = (uint64_t)(h2[1] & 0x7Fu);
    if (masked)
      return -1;

    if (opcode & 0x8u) {
      if (len > 125u)
        return -1;
      {
        uint8_t ctrl[125];
        if (recv_exact(sock, ctrl, (size_t)len) != 0)
          return -1;
        if (opcode == 0x9u) {
          native_ws_send_frame(sock, 0xAu, ctrl, (size_t)len, 0);
          continue;
        }
        if (opcode == 0xAu)
          continue;
        if (opcode == 0x8u) {
          size_t copy =
              ((size_t)len <= payload_cap) ? (size_t)len : payload_cap;
          native_ws_send_frame(sock, 0x8u, ctrl, (size_t)len, 0);
          if (copy)
            memcpy(payload, ctrl, copy);
          *out_opcode = 0x8u;
          *out_len = copy;
          return 0;
        }
      }
      return -1;
    }

    if (len == 126u) {
      uint8_t ext[2];
      if (recv_exact(sock, ext, 2) != 0)
        return -1;
      len = ((uint64_t)ext[0] << 8) | ext[1];
    } else if (len == 127u) {
      return -1;
    }
    if (len > payload_cap)
      return -1;
    if (recv_exact(sock, payload, (size_t)len) != 0)
      return -1;
    *out_opcode = opcode;
    *out_len = (size_t)len;
    return 0;
  }
}

static int native_ws_send_handshake_with_first_frame(
    wamble_socket_t sock, const char *path, const char *host_header,
    const char *key, const char *version, const uint8_t *payload,
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
  {
    uint8_t frame[256];
    char req[1024];
    uint8_t out[1400];
    int n;
    const char *req_host =
        (host_header && *host_header) ? host_header : "localhost";
    if (!path || !key || !version)
      return -1;
    if (frame_len + payload_len > sizeof(frame))
      return -1;
    memcpy(frame, hdr, frame_len);
    for (size_t i = 0; i < payload_len; i++)
      frame[frame_len + i] = payload[i] ^ hdr[2 + (i % 4u)];
    frame_len += payload_len;
    n = snprintf(req, sizeof(req),
                 "GET %s HTTP/1.1\r\n"
                 "Host: %s\r\n"
                 "Upgrade: websocket\r\n"
                 "Connection: Upgrade\r\n"
                 "Sec-WebSocket-Key: %s\r\n"
                 "Sec-WebSocket-Version: %s\r\n"
                 "\r\n",
                 path, req_host, key, version);
    if (n <= 0 || (size_t)n >= sizeof(req))
      return -1;
    if ((size_t)n + frame_len > sizeof(out))
      return -1;
    memcpy(out, req, (size_t)n);
    memcpy(out + (size_t)n, frame, frame_len);
    {
      wamble_client_io_count_t rc = send(sock, (const char *)out,
#ifdef WAMBLE_PLATFORM_WINDOWS
                                         (int)((size_t)n + frame_len),
#else
                                         (size_t)n + frame_len,
#endif
                                         0);
      return (rc == (wamble_client_io_count_t)((size_t)n + frame_len)) ? 0 : -1;
    }
  }
}

static int ws_send_close(wamble_socket_t sock, uint16_t code) {
  uint8_t p[2];
  p[0] = (uint8_t)((code >> 8) & 0xFFu);
  p[1] = (uint8_t)(code & 0xFFu);
  return native_ws_send_frame(sock, 0x8u, p, sizeof(p), 0);
}

static wamble_socket_t udp_open(void) {
  wamble_socket_t sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock == WAMBLE_INVALID_SOCKET)
    return WAMBLE_INVALID_SOCKET;
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = 0;
  if (bind(sock, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
    wamble_close_socket(sock);
    return WAMBLE_INVALID_SOCKET;
  }
  return sock;
}

static int udp_send(wamble_socket_t sock, struct WambleMsg *msg,
                    const struct sockaddr_in *server) {
  uint8_t buf[WAMBLE_MAX_PACKET_SIZE];
  size_t len = 0;
  if (wamble_packet_serialize(msg, buf, sizeof(buf), &len, msg->flags) !=
      NET_OK)
    return -1;
#ifdef WAMBLE_PLATFORM_WINDOWS
  int rc = sendto(sock, (const char *)buf, (int)len, 0,
                  (const struct sockaddr *)server, (int)sizeof(*server));
  return (rc >= 0) ? 0 : -1;
#else
  ssize_t rc = sendto(sock, (const char *)buf, (size_t)len, 0,
                      (const struct sockaddr *)server,
                      (wamble_socklen_t)sizeof(*server));
  return (rc >= 0) ? 0 : -1;
#endif
}

static int udp_recv_msg(wamble_socket_t sock, struct WambleMsg *out_msg,
                        struct sockaddr_in *out_addr, int timeout_ms) {
  int wait_rc = sock_wait_readable(sock, timeout_ms);
  if (wait_rc != 0)
    return wait_rc;
  uint8_t buf[WAMBLE_MAX_PACKET_SIZE];
  struct sockaddr_in from;
  memset(&from, 0, sizeof(from));
  wamble_socklen_t from_len = (wamble_socklen_t)sizeof(from);
#ifdef WAMBLE_PLATFORM_WINDOWS
  int n = recvfrom(sock, (char *)buf, (int)sizeof(buf), 0,
                   (struct sockaddr *)&from, &from_len);
  if (n <= 0)
    return -1;
#else
  ssize_t n = recvfrom(sock, (char *)buf, sizeof(buf), 0,
                       (struct sockaddr *)&from, &from_len);
  if (n <= 0)
    return -1;
#endif
  uint8_t flags = 0;
  if (wamble_packet_deserialize(buf, (size_t)n, out_msg, &flags) != NET_OK)
    return -1;
  if (out_addr)
    *out_addr = from;
  return 0;
}

static int udp_send_reliable(wamble_socket_t sock, struct WambleMsg *msg,
                             const struct sockaddr_in *server, int timeout_ms,
                             int max_retries) {
  uint8_t buf[WAMBLE_MAX_PACKET_SIZE];
  size_t len = 0;
  if (wamble_packet_serialize(msg, buf, sizeof(buf), &len, msg->flags) !=
      NET_OK)
    return -1;
  int current_timeout = timeout_ms;
  for (int attempt = 0; attempt < max_retries; attempt++) {
#ifdef WAMBLE_PLATFORM_WINDOWS
    if (sendto(sock, (const char *)buf, (int)len, 0,
               (const struct sockaddr *)server, (int)sizeof(*server)) < 0)
      return -1;
#else
    if (sendto(sock, (const char *)buf, (size_t)len, 0,
               (const struct sockaddr *)server,
               (wamble_socklen_t)sizeof(*server)) < 0)
      return -1;
#endif
    int wait_rc = sock_wait_readable(sock, current_timeout);
    if (wait_rc < 0)
      return -1;
    if (wait_rc == 0) {
      uint8_t ack_buf[WAMBLE_MAX_PACKET_SIZE];
      struct WambleMsg ack_msg;
      struct sockaddr_in ack_from;
      wamble_socklen_t ack_len = (wamble_socklen_t)sizeof(ack_from);
#ifdef WAMBLE_PLATFORM_WINDOWS
      int rcv = recvfrom(sock, (char *)ack_buf, (int)sizeof(ack_buf), 0,
                         (struct sockaddr *)&ack_from, &ack_len);
#else
      ssize_t rcv = recvfrom(sock, (char *)ack_buf, sizeof(ack_buf), 0,
                             (struct sockaddr *)&ack_from, &ack_len);
#endif
      if (rcv > 0) {
        uint8_t ack_flags = 0;
        if (wamble_packet_deserialize(ack_buf, (size_t)rcv, &ack_msg,
                                      &ack_flags) == NET_OK &&
            ack_msg.ctrl == WAMBLE_CTRL_ACK &&
            ack_msg.seq_num == msg->seq_num &&
            memcmp(ack_msg.token, msg->token, TOKEN_LENGTH) == 0) {
          return 0;
        }
      }
    }
    if (current_timeout < 8000) {
      int next = current_timeout * 2;
      current_timeout = (next > 8000) ? 8000 : next;
    }
  }
  return -1;
}

static int native_client_init_ws(wamble_client_t *c, wamble_socket_t sock) {
  if (!c || sock == WAMBLE_INVALID_SOCKET)
    return -1;
  c->kind = WAMBLE_TRANSPORT_WS;
  c->sock = sock;
  memset(&c->peer, 0, sizeof(c->peer));
  c->seq = 0;
  c->ws_rx_len = 0;
  c->ws_rx_offset = 0;
  return 0;
}

static int native_client_upgrade_ws(wamble_client_t *c, wamble_socket_t sock,
                                    const char *path, const char *host_header) {
  char response[1024];
  if (!c || sock == WAMBLE_INVALID_SOCKET)
    return -1;
  if (native_ws_send_handshake(sock, path, host_header, ws_client_key,
                               ws_client_version) != 0)
    return -1;
  if (native_ws_recv_http(sock, response, sizeof(response)) != 0)
    return -1;
  if (ws_validate_http_upgrade(response) != 0)
    return -1;
  return native_client_init_ws(c, sock);
}

static int native_client_init_udp(wamble_client_t *c,
                                  const struct sockaddr_in *server) {
  if (!c || !server)
    return -1;
  wamble_socket_t sock = udp_open();
  if (sock == WAMBLE_INVALID_SOCKET)
    return -1;
  c->kind = WAMBLE_TRANSPORT_UDP;
  c->sock = sock;
  c->peer = *server;
  c->seq = 1;
  c->ws_rx_len = 0;
  c->ws_rx_offset = 0;
  return 0;
}

static int native_resolve_udp_server(const char *host, uint16_t port,
                                     struct sockaddr_in *out_server) {
  char port_text[6];
  struct addrinfo hints;
  struct addrinfo *result = NULL;
  int rc;

  if (!host || !*host || !out_server)
    return -1;
  if (snprintf(port_text, sizeof(port_text), "%u", (unsigned)port) <= 0)
    return -1;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;

  rc = getaddrinfo(host, port_text, &hints, &result);
  if (rc != 0 || !result)
    return -1;

  memcpy(out_server, result->ai_addr, sizeof(*out_server));
  freeaddrinfo(result);
  return 0;
}

static int native_client_connect_udp(wamble_client_t *c, const char *host,
                                     uint16_t port) {
  struct sockaddr_in server;
  if (native_resolve_udp_server(host, port, &server) != 0)
    return -1;
  return native_client_init_udp(c, &server);
}

static int native_client_send(wamble_client_t *c, struct WambleMsg *msg) {
  if (!c || !msg)
    return -1;
  if (c->kind == WAMBLE_TRANSPORT_WS) {
    msg->seq_num = c->seq++;
    uint8_t buf[WAMBLE_MAX_PACKET_SIZE];
    size_t len = 0;
    if (wamble_packet_serialize(msg, buf, sizeof(buf), &len, msg->flags) !=
        NET_OK)
      return -1;
    return native_ws_send_frame(c->sock, 0x2u, buf, len, 0);
  }
  if (c->kind == WAMBLE_TRANSPORT_UDP) {
    msg->seq_num = c->seq++;
    if (msg->flags & WAMBLE_FLAG_UNRELIABLE)
      return udp_send(c->sock, msg, &c->peer);
    return udp_send_reliable(c->sock, msg, &c->peer,
                             WAMBLE_CLIENT_DEFAULT_TIMEOUT_MS,
                             WAMBLE_CLIENT_DEFAULT_MAX_RETRIES);
  }
  return -1;
}

static int native_client_recv_ws_packet(wamble_client_t *c,
                                        struct WambleMsg *out) {
  if (!c || !out || c->kind != WAMBLE_TRANSPORT_WS)
    return -1;

  while (c->ws_rx_offset < c->ws_rx_len) {
    size_t packet_len = 0;
    uint8_t flags = 0;
    if (wamble_wire_packet_size(c->ws_rx_buf + c->ws_rx_offset,
                                c->ws_rx_len - c->ws_rx_offset,
                                &packet_len) != NET_OK ||
        packet_len == 0 || packet_len > (c->ws_rx_len - c->ws_rx_offset)) {
      c->ws_rx_len = 0;
      c->ws_rx_offset = 0;
      return -1;
    }
    if (wamble_packet_deserialize(c->ws_rx_buf + c->ws_rx_offset, packet_len,
                                  out, &flags) == NET_OK) {
      c->ws_rx_offset += packet_len;
      if (c->ws_rx_offset >= c->ws_rx_len) {
        c->ws_rx_len = 0;
        c->ws_rx_offset = 0;
      }
      return 0;
    }
    c->ws_rx_len = 0;
    c->ws_rx_offset = 0;
    return -1;
  }

  c->ws_rx_len = 0;
  c->ws_rx_offset = 0;
  return 1;
}

static int native_client_recv(wamble_client_t *c, struct WambleMsg *out,
                              int timeout_ms) {
  if (!c || !out)
    return -1;
  if (c->kind == WAMBLE_TRANSPORT_WS) {
    int buffered_rc = native_client_recv_ws_packet(c, out);
    if (buffered_rc <= 0)
      return buffered_rc;

    uint8_t buf[WAMBLE_CLIENT_WS_FRAME_MAX];
    uint8_t opcode = 0;
    size_t len = 0;
    if (sock_wait_readable(c->sock, timeout_ms) != 0)
      return 1;
    if (native_ws_recv_frame(c->sock, &opcode, buf, sizeof(buf), &len) != 0)
      return -1;
    if (opcode == 0x8u)
      return -1;
    if (len == 0 || len > sizeof(c->ws_rx_buf))
      return -1;
    memcpy(c->ws_rx_buf, buf, len);
    c->ws_rx_len = len;
    c->ws_rx_offset = 0;
    return native_client_recv_ws_packet(c, out);
  }
  if (c->kind == WAMBLE_TRANSPORT_UDP)
    return udp_recv_msg(c->sock, out, NULL, timeout_ms);
  return -1;
}

static void native_client_close(wamble_client_t *c) {
  if (!c || c->sock == WAMBLE_INVALID_SOCKET)
    return;
  if (c->kind == WAMBLE_TRANSPORT_WS)
    ws_send_close(c->sock, 1000);
  wamble_close_socket(c->sock);
  c->sock = WAMBLE_INVALID_SOCKET;
  c->ws_rx_len = 0;
  c->ws_rx_offset = 0;
}

#endif /* !WAMBLE_PLATFORM_WASM */

WambleClientStatus wamble_client_ws_send_handshake(wamble_socket_t sock,
                                                   const char *path,
                                                   const char *host_header,
                                                   const char *key,
                                                   const char *version) {
#if defined(WAMBLE_PLATFORM_WASM)
  (void)sock;
  (void)path;
  (void)host_header;
  (void)key;
  (void)version;
  return (WambleClientStatus){WAMBLE_CLIENT_STATUS_UNSUPPORTED, 0};
#else
  if (native_ws_send_handshake(sock, path, host_header, key, version) != 0)
    return (WambleClientStatus){WAMBLE_CLIENT_STATUS_NETWORK,
                                wamble_last_error()};
  return (WambleClientStatus){WAMBLE_CLIENT_STATUS_OK, 0};
#endif
}

WambleClientStatus wamble_client_ws_recv_http(wamble_socket_t sock, char *out,
                                              size_t cap) {
#if defined(WAMBLE_PLATFORM_WASM)
  (void)sock;
  (void)out;
  (void)cap;
  return (WambleClientStatus){WAMBLE_CLIENT_STATUS_UNSUPPORTED, 0};
#else
  if (native_ws_recv_http(sock, out, cap) != 0)
    return (WambleClientStatus){WAMBLE_CLIENT_STATUS_NETWORK,
                                wamble_last_error()};
  return (WambleClientStatus){WAMBLE_CLIENT_STATUS_OK, 0};
#endif
}

WambleClientStatus wamble_client_ws_send_frame_ex(wamble_socket_t sock,
                                                  uint8_t fin, uint8_t opcode,
                                                  const uint8_t *payload,
                                                  size_t len,
                                                  int force_ext126) {
#if defined(WAMBLE_PLATFORM_WASM)
  (void)sock;
  (void)fin;
  (void)opcode;
  (void)payload;
  (void)len;
  (void)force_ext126;
  return (WambleClientStatus){WAMBLE_CLIENT_STATUS_UNSUPPORTED, 0};
#else
  if (native_ws_send_frame_ex(sock, fin, opcode, payload, len, force_ext126) !=
      0) {
    return (WambleClientStatus){WAMBLE_CLIENT_STATUS_NETWORK,
                                wamble_last_error()};
  }
  return (WambleClientStatus){WAMBLE_CLIENT_STATUS_OK, 0};
#endif
}

WambleClientStatus wamble_client_ws_send_frame(wamble_socket_t sock,
                                               uint8_t opcode,
                                               const uint8_t *payload,
                                               size_t len, int force_ext126) {
#if defined(WAMBLE_PLATFORM_WASM)
  (void)sock;
  (void)opcode;
  (void)payload;
  (void)len;
  (void)force_ext126;
  return (WambleClientStatus){WAMBLE_CLIENT_STATUS_UNSUPPORTED, 0};
#else
  if (native_ws_send_frame(sock, opcode, payload, len, force_ext126) != 0)
    return (WambleClientStatus){WAMBLE_CLIENT_STATUS_NETWORK,
                                wamble_last_error()};
  return (WambleClientStatus){WAMBLE_CLIENT_STATUS_OK, 0};
#endif
}

WambleClientStatus wamble_client_ws_recv_frame(wamble_socket_t sock,
                                               uint8_t *out_opcode,
                                               uint8_t *payload,
                                               size_t payload_cap,
                                               size_t *out_len) {
#if defined(WAMBLE_PLATFORM_WASM)
  (void)sock;
  (void)out_opcode;
  (void)payload;
  (void)payload_cap;
  (void)out_len;
  return (WambleClientStatus){WAMBLE_CLIENT_STATUS_UNSUPPORTED, 0};
#else
  if (native_ws_recv_frame(sock, out_opcode, payload, payload_cap, out_len) !=
      0) {
    return (WambleClientStatus){WAMBLE_CLIENT_STATUS_NETWORK,
                                wamble_last_error()};
  }
  return (WambleClientStatus){WAMBLE_CLIENT_STATUS_OK, 0};
#endif
}

WambleClientStatus wamble_client_ws_send_handshake_with_first_frame(
    wamble_socket_t sock, const char *path, const char *host_header,
    const char *key, const char *version, const uint8_t *payload,
    size_t payload_len) {
#if defined(WAMBLE_PLATFORM_WASM)
  (void)sock;
  (void)path;
  (void)host_header;
  (void)key;
  (void)version;
  (void)payload;
  (void)payload_len;
  return (WambleClientStatus){WAMBLE_CLIENT_STATUS_UNSUPPORTED, 0};
#else
  if (native_ws_send_handshake_with_first_frame(
          sock, path, host_header, key, version, payload, payload_len) != 0) {
    return (WambleClientStatus){WAMBLE_CLIENT_STATUS_NETWORK,
                                wamble_last_error()};
  }
  return (WambleClientStatus){WAMBLE_CLIENT_STATUS_OK, 0};
#endif
}

WambleClientStatus wamble_client_upgrade_ws(wamble_client_t *c,
                                            wamble_socket_t sock,
                                            const char *path,
                                            const char *host_header) {
#if defined(WAMBLE_PLATFORM_WASM)
  (void)c;
  (void)sock;
  (void)path;
  (void)host_header;
  return (WambleClientStatus){WAMBLE_CLIENT_STATUS_UNSUPPORTED, 0};
#else
  if (native_client_upgrade_ws(c, sock, path, host_header) != 0)
    return (WambleClientStatus){WAMBLE_CLIENT_STATUS_NETWORK,
                                wamble_last_error()};
  return (WambleClientStatus){WAMBLE_CLIENT_STATUS_OK, 0};
#endif
}

WambleClientStatus wamble_client_init_ws(wamble_client_t *c,
                                         wamble_socket_t sock) {
#if defined(WAMBLE_PLATFORM_WASM)
  return wasm_client_init_ws(c, sock);
#else
  if (native_client_init_ws(c, sock) != 0)
    return (WambleClientStatus){WAMBLE_CLIENT_STATUS_INVALID_ARGUMENT, 0};
  return (WambleClientStatus){WAMBLE_CLIENT_STATUS_OK, 0};
#endif
}

WambleClientStatus wamble_client_init_udp(wamble_client_t *c,
                                          const struct sockaddr_in *server) {
#if defined(WAMBLE_PLATFORM_WASM)
  (void)c;
  (void)server;
  return (WambleClientStatus){WAMBLE_CLIENT_STATUS_UNSUPPORTED, 0};
#else
  if (native_client_init_udp(c, server) != 0)
    return (WambleClientStatus){WAMBLE_CLIENT_STATUS_INVALID_ARGUMENT, 0};
  return (WambleClientStatus){WAMBLE_CLIENT_STATUS_OK, 0};
#endif
}

WambleClientStatus wamble_client_connect_udp(wamble_client_t *c,
                                             const char *host, uint16_t port) {
#if defined(WAMBLE_PLATFORM_WASM)
  (void)c;
  (void)host;
  (void)port;
  return (WambleClientStatus){WAMBLE_CLIENT_STATUS_UNSUPPORTED, 0};
#else
  if (native_client_connect_udp(c, host, port) != 0)
    return (WambleClientStatus){WAMBLE_CLIENT_STATUS_RESOLVE, 0};
  return (WambleClientStatus){WAMBLE_CLIENT_STATUS_OK, 0};
#endif
}

WambleClientStatus wamble_client_connect_web(wamble_client_t *c,
                                             const char *url) {
#if defined(WAMBLE_PLATFORM_WASM)
  return wasm_client_connect_web(c, url);
#else
  (void)c;
  (void)url;
  return (WambleClientStatus){WAMBLE_CLIENT_STATUS_UNSUPPORTED, 0};
#endif
}

int wamble_client_connected(const wamble_client_t *c) {
#if defined(WAMBLE_PLATFORM_WASM)
  return (c && c->kind == WAMBLE_TRANSPORT_WS) ? wasm_ws_connected : 0;
#else
  if (!c)
    return 0;
  if (c->kind != WAMBLE_TRANSPORT_WS && c->kind != WAMBLE_TRANSPORT_UDP)
    return 0;
  return c->sock != WAMBLE_INVALID_SOCKET;
#endif
}

int wamble_client_closed(const wamble_client_t *c) {
#if defined(WAMBLE_PLATFORM_WASM)
  return (c && c->kind == WAMBLE_TRANSPORT_WS) ? wasm_ws_closed : 0;
#else
  if (!c)
    return 1;
  if (c->kind != WAMBLE_TRANSPORT_WS && c->kind != WAMBLE_TRANSPORT_UDP)
    return 1;
  return c->sock == WAMBLE_INVALID_SOCKET;
#endif
}

WambleClientStatus wamble_client_send(wamble_client_t *c,
                                      struct WambleMsg *msg) {
#if defined(WAMBLE_PLATFORM_WASM)
  return wasm_client_send(c, msg);
#else
  int rc = native_client_send(c, msg);
  if (rc != 0)
    return (WambleClientStatus){WAMBLE_CLIENT_STATUS_NETWORK,
                                wamble_last_error()};
  return (WambleClientStatus){WAMBLE_CLIENT_STATUS_OK, 0};
#endif
}

WambleClientStatus wamble_client_recv(wamble_client_t *c, struct WambleMsg *out,
                                      int timeout_ms) {
#if defined(WAMBLE_PLATFORM_WASM)
  return wasm_client_recv(c, out, timeout_ms);
#else
  int rc = native_client_recv(c, out, timeout_ms);
  if (rc < 0)
    return (WambleClientStatus){WAMBLE_CLIENT_STATUS_NETWORK,
                                wamble_last_error()};
  if (rc > 0)
    return (WambleClientStatus){WAMBLE_CLIENT_STATUS_TIMEOUT, 0};
  return (WambleClientStatus){WAMBLE_CLIENT_STATUS_OK, 0};
#endif
}

void wamble_client_close(wamble_client_t *c) {
#if defined(WAMBLE_PLATFORM_WASM)
  wasm_client_shutdown(c);
#else
  native_client_close(c);
#endif
}
