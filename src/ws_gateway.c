#include "../include/wamble/wamble.h"

#if defined(WAMBLE_PLATFORM_WINDOWS)
#include <winsock2.h>
#include <ws2tcpip.h>
#define WAMBLE_STRCASECMP _stricmp
#define WAMBLE_STRNCASECMP _strnicmp
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <strings.h>
#define WAMBLE_STRCASECMP strcasecmp
#define WAMBLE_STRNCASECMP strncasecmp
#endif

#define WS_HANDSHAKE_MAX 8192
#define WS_FRAME_MAX 4096
#define WS_PREFETCH_MAX (WS_FRAME_MAX + 14u)
#define WS_INBOUND_QUEUE_CAP_DEFAULT 1024
#define WS_ROUTE_ID_MASK 0x0FFFFFFFu
#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_CLOSE_PROTOCOL_ERROR 1002
#define WS_CLOSE_MESSAGE_TOO_BIG 1009
#define WS_CONTROL_PAYLOAD_MAX 125u

typedef enum WsOpcode {
  WS_OPCODE_CONTINUATION = 0x0u,
  WS_OPCODE_BINARY = 0x2u,
  WS_OPCODE_CLOSE = 0x8u,
  WS_OPCODE_PING = 0x9u,
  WS_OPCODE_PONG = 0xAu,
} WsOpcode;

typedef struct WsClientSlot WsClientSlot;
typedef struct WsInboundPacket WsInboundPacket;

struct WambleWsGateway {
  char *profile_name;
  char *ws_path;
  int ws_port;
  int udp_port;
  int clients_capacity;

  wamble_socket_t listen_sock;
  wamble_thread_t thread;
  int running;
  volatile int should_stop;

  wamble_mutex_t mutex;
  wamble_cond_t clients_done;
  int active_client_threads;
  WsClientSlot **clients;
  WsInboundPacket *inbound_packets;
  int inbound_cap;
  int inbound_head;
  int inbound_count;
};

#if defined(WAMBLE_PLATFORM_WINDOWS)
typedef int wamble_io_count_t;
#else
typedef ssize_t wamble_io_count_t;
#endif

typedef struct WsClientCtx {
  WambleWsGateway *gateway;
  int slot_index;
} WsClientCtx;

struct WsClientSlot {
  wamble_socket_t tcp_sock;
  int in_use;
  volatile int should_stop;
  int upgraded;
  uint32_t route_id;
  struct sockaddr_in virtual_addr;
  uint8_t tx_batch[WS_FRAME_MAX];
  size_t tx_batch_len;
};

struct WsInboundPacket {
  struct sockaddr_in addr;
  size_t len;
  uint8_t data[WAMBLE_MAX_PACKET_SIZE];
};

typedef struct WsRouteEntry {
  struct sockaddr_in addr;
  WambleWsGateway *gateway;
  int slot_index;
  uint32_t route_id;
  int in_use;
} WsRouteEntry;

static WsRouteEntry *g_ws_routes = NULL;
static size_t g_ws_routes_cap = 0;
static uint32_t g_ws_route_seq = 1;
static wamble_mutex_t g_ws_routes_mutex;
static int g_ws_routes_mutex_ready = 0;

static void publish_ws_gateway_status_detail(WsGatewayStatus status,
                                             const WambleWsGateway *gw,
                                             const char *detail) {
  WambleRuntimeStatus runtime_status = {WAMBLE_RUNTIME_STATUS_WS_GATEWAY,
                                        (int)status};
  wamble_runtime_event_publish(runtime_status,
                               (gw && gw->profile_name && gw->profile_name[0])
                                   ? gw->profile_name
                                   : "default",
                               detail);
}

static void ws_routes_ensure_mutex_ready(void) {
  if (!g_ws_routes_mutex_ready) {
    wamble_mutex_init(&g_ws_routes_mutex);
    g_ws_routes_mutex_ready = 1;
  }
}

static int ws_sockaddr_equal(const struct sockaddr_in *a,
                             const struct sockaddr_in *b) {
  if (!a || !b)
    return 0;
  return a->sin_family == b->sin_family && a->sin_port == b->sin_port &&
         a->sin_addr.s_addr == b->sin_addr.s_addr;
}

static struct sockaddr_in ws_virtual_addr_for_id(uint32_t route_id) {
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  uint32_t ip_low = (route_id >> 16) & 0x0FFFu;
  uint32_t host_ip = 0xF0000000u | ip_low;
  uint16_t port = (uint16_t)(route_id & 0xFFFFu);
  if (port == 0)
    port = 1;
  addr.sin_addr.s_addr = htonl(host_ip);
  addr.sin_port = htons(port);
  return addr;
}

static int ws_routes_ensure_capacity(size_t need) {
  if (need <= g_ws_routes_cap)
    return 0;
  size_t next_cap = (g_ws_routes_cap > 0) ? g_ws_routes_cap : 64u;
  while (next_cap < need) {
    if (next_cap > (SIZE_MAX / 2u)) {
      next_cap = need;
      break;
    }
    next_cap *= 2u;
  }
  WsRouteEntry *next =
      (WsRouteEntry *)realloc(g_ws_routes, next_cap * sizeof(*next));
  if (!next)
    return -1;
  memset(next + g_ws_routes_cap, 0,
         (next_cap - g_ws_routes_cap) * sizeof(*next));
  g_ws_routes = next;
  g_ws_routes_cap = next_cap;
  return 0;
}

static int ws_route_register(WambleWsGateway *gw, int slot_index,
                             struct sockaddr_in *out_addr,
                             uint32_t *out_route_id) {
  if (!gw || slot_index < 0 || !out_addr || !out_route_id)
    return -1;
  ws_routes_ensure_mutex_ready();
  wamble_mutex_lock(&g_ws_routes_mutex);
  if (ws_routes_ensure_capacity(g_ws_routes_cap + 1u) != 0) {
    wamble_mutex_unlock(&g_ws_routes_mutex);
    return -1;
  }
  size_t idx = 0;
  while (idx < g_ws_routes_cap && g_ws_routes[idx].in_use)
    idx++;
  if (idx >= g_ws_routes_cap) {
    wamble_mutex_unlock(&g_ws_routes_mutex);
    return -1;
  }
  uint32_t route_id = (g_ws_route_seq++ & WS_ROUTE_ID_MASK);
  if (route_id == 0)
    route_id = (g_ws_route_seq++ & WS_ROUTE_ID_MASK);
  struct sockaddr_in vaddr = ws_virtual_addr_for_id(route_id);
  g_ws_routes[idx].in_use = 1;
  g_ws_routes[idx].gateway = gw;
  g_ws_routes[idx].slot_index = slot_index;
  g_ws_routes[idx].route_id = route_id;
  g_ws_routes[idx].addr = vaddr;
  *out_addr = vaddr;
  *out_route_id = route_id;
  wamble_mutex_unlock(&g_ws_routes_mutex);
  return 0;
}

static void ws_route_unregister(uint32_t route_id) {
  if (route_id == 0)
    return;
  ws_routes_ensure_mutex_ready();
  wamble_mutex_lock(&g_ws_routes_mutex);
  for (size_t i = 0; i < g_ws_routes_cap; i++) {
    if (g_ws_routes[i].in_use && g_ws_routes[i].route_id == route_id) {
      memset(&g_ws_routes[i], 0, sizeof(g_ws_routes[i]));
      break;
    }
  }
  wamble_mutex_unlock(&g_ws_routes_mutex);
}

static void ws_route_unregister_gateway(WambleWsGateway *gw) {
  if (!gw)
    return;
  ws_routes_ensure_mutex_ready();
  wamble_mutex_lock(&g_ws_routes_mutex);
  for (size_t i = 0; i < g_ws_routes_cap; i++) {
    if (g_ws_routes[i].in_use && g_ws_routes[i].gateway == gw)
      memset(&g_ws_routes[i], 0, sizeof(g_ws_routes[i]));
  }
  wamble_mutex_unlock(&g_ws_routes_mutex);
}

static int ws_route_lookup(const struct sockaddr_in *addr, WambleWsGateway **gw,
                           int *slot_index, uint32_t *route_id) {
  if (!addr || !gw || !slot_index || !route_id)
    return 0;
  *gw = NULL;
  *slot_index = -1;
  *route_id = 0;
  ws_routes_ensure_mutex_ready();
  wamble_mutex_lock(&g_ws_routes_mutex);
  for (size_t i = 0; i < g_ws_routes_cap; i++) {
    if (!g_ws_routes[i].in_use)
      continue;
    if (ws_sockaddr_equal(&g_ws_routes[i].addr, addr)) {
      *gw = g_ws_routes[i].gateway;
      *slot_index = g_ws_routes[i].slot_index;
      *route_id = g_ws_routes[i].route_id;
      wamble_mutex_unlock(&g_ws_routes_mutex);
      return 1;
    }
  }
  wamble_mutex_unlock(&g_ws_routes_mutex);
  return 0;
}

static int ws_send_all(wamble_socket_t sock, const uint8_t *data, size_t len) {
  size_t sent = 0;
  while (sent < len) {
    wamble_io_count_t n = send(sock, (const char *)(data + sent),
#ifdef WAMBLE_PLATFORM_WINDOWS
                               (int)(len - sent),
#else
                               len - sent,
#endif
                               0);
    if (n <= 0)
      return -1;
    sent += (size_t)n;
  }
  return 0;
}

static int ws_recv_some(wamble_socket_t sock, uint8_t *buf, size_t cap,
                        size_t *out_n) {
  if (!buf || cap == 0 || !out_n)
    return -1;
  wamble_io_count_t n = recv(sock, (char *)buf,
#ifdef WAMBLE_PLATFORM_WINDOWS
                             (int)cap,
#else
                             cap,
#endif
                             0);
  if (n <= 0)
    return -1;
  *out_n = (size_t)n;
  return 0;
}

static int ws_recv_exact(wamble_socket_t sock, uint8_t *buf, size_t len) {
  size_t got = 0;
  while (got < len) {
    wamble_io_count_t n = recv(sock, (char *)(buf + got),
#ifdef WAMBLE_PLATFORM_WINDOWS
                               (int)(len - got),
#else
                               len - got,
#endif
                               0);
    if (n <= 0)
      return -1;
    got += (size_t)n;
  }
  return 0;
}

static char *ws_strdup_local(const char *s) {
  if (!s)
    return NULL;
  size_t n = strlen(s);
  char *out = (char *)malloc(n + 1);
  if (!out)
    return NULL;
  memcpy(out, s, n + 1);
  return out;
}

static int ws_send_http_response(wamble_socket_t sock, int code,
                                 const char *reason, const char *body) {
  char resp[1024];
  size_t body_len = body ? strlen(body) : 0;
  int n = snprintf(resp, sizeof(resp),
                   "HTTP/1.1 %d %s\r\n"
                   "Connection: close\r\n"
                   "Content-Type: text/plain\r\n"
                   "Content-Length: %zu\r\n"
                   "\r\n"
                   "%s",
                   code, reason ? reason : "Error", body_len, body ? body : "");
  if (n <= 0 || (size_t)n >= sizeof(resp))
    return -1;
  return ws_send_all(sock, (const uint8_t *)resp, (size_t)n);
}

static int ws_send_http_upgrade_required(wamble_socket_t sock) {
  static const char response[] = "HTTP/1.1 426 Upgrade Required\r\n"
                                 "Connection: close\r\n"
                                 "Sec-WebSocket-Version: 13\r\n"
                                 "Content-Length: 0\r\n"
                                 "\r\n";
  return ws_send_all(sock, (const uint8_t *)response, sizeof(response) - 1u);
}

static int ws_extract_header(const char *headers, const char *name, char *out,
                             size_t out_cap) {
  if (!headers || !name || !out || out_cap == 0)
    return -1;

  size_t name_len = strlen(name);
  const char *cur = headers;
  while (*cur) {
    const char *line_end = strstr(cur, "\r\n");
    size_t line_len = line_end ? (size_t)(line_end - cur) : strlen(cur);

    if (line_len > name_len + 1 &&
        WAMBLE_STRNCASECMP(cur, name, name_len) == 0 && cur[name_len] == ':') {
      const char *value = cur + name_len + 1;
      while (*value == ' ' || *value == '\t')
        value++;
      size_t value_len = line_len - (size_t)(value - cur);
      while (value_len > 0 &&
             (value[value_len - 1] == ' ' || value[value_len - 1] == '\t')) {
        value_len--;
      }
      if (value_len + 1 > out_cap)
        return -1;
      memcpy(out, value, value_len);
      out[value_len] = '\0';
      return 0;
    }

    if (!line_end)
      break;
    cur = line_end + 2;
  }

  return -1;
}

static int ws_contains_token_ci(const char *haystack, const char *token) {
  if (!haystack || !token)
    return 0;
  size_t needle_len = strlen(token);
  if (needle_len == 0)
    return 0;
  const char *p = haystack;
  while (*p) {
    while (*p == ' ' || *p == '\t' || *p == ',')
      p++;
    if (!*p)
      break;

    const char *start = p;
    while (*p && *p != ',')
      p++;
    const char *end = p;
    while (end > start && (end[-1] == ' ' || end[-1] == '\t'))
      end--;

    if ((size_t)(end - start) == needle_len &&
        WAMBLE_STRNCASECMP(start, token, needle_len) == 0) {
      return 1;
    }
    if (*p == ',')
      p++;
  }
  return 0;
}

static int ws_base64_decode_char(unsigned char c) {
  if (c >= 'A' && c <= 'Z')
    return c - 'A';
  if (c >= 'a' && c <= 'z')
    return 26 + (c - 'a');
  if (c >= '0' && c <= '9')
    return 52 + (c - '0');
  if (c == '+')
    return 62;
  if (c == '/')
    return 63;
  return -1;
}

static int ws_base64_decode(const char *in, uint8_t *out, size_t out_cap,
                            size_t *out_len) {
  if (!in || !out || !out_len)
    return -1;
  size_t in_len = strlen(in);
  if (in_len == 0 || (in_len % 4u) != 0)
    return -1;

  size_t produced = 0;
  for (size_t i = 0; i < in_len; i += 4u) {
    char c0 = in[i];
    char c1 = in[i + 1u];
    char c2 = in[i + 2u];
    char c3 = in[i + 3u];
    int v0 = ws_base64_decode_char((unsigned char)c0);
    int v1 = ws_base64_decode_char((unsigned char)c1);
    int v2 = (c2 == '=') ? -2 : ws_base64_decode_char((unsigned char)c2);
    int v3 = (c3 == '=') ? -2 : ws_base64_decode_char((unsigned char)c3);

    if (v0 < 0 || v1 < 0)
      return -1;
    if (v2 == -1 || v3 == -1)
      return -1;
    if (c2 == '=' && c3 != '=')
      return -1;
    if ((c2 == '=' || c3 == '=') && (i + 4u) != in_len)
      return -1;

    uint32_t triple = ((uint32_t)v0 << 18) | ((uint32_t)v1 << 12) |
                      ((uint32_t)((v2 >= 0) ? v2 : 0) << 6) |
                      (uint32_t)((v3 >= 0) ? v3 : 0);

    if (produced >= out_cap)
      return -1;
    out[produced++] = (uint8_t)((triple >> 16) & 0xFFu);
    if (c2 != '=') {
      if (produced >= out_cap)
        return -1;
      out[produced++] = (uint8_t)((triple >> 8) & 0xFFu);
    }
    if (c3 != '=') {
      if (produced >= out_cap)
        return -1;
      out[produced++] = (uint8_t)(triple & 0xFFu);
    }
  }

  *out_len = produced;
  return 0;
}

static int ws_validate_client_key(const char *key) {
  uint8_t decoded[32];
  size_t n = 0;
  if (ws_base64_decode(key, decoded, sizeof(decoded), &n) != 0)
    return -1;
  return (n == 16u) ? 0 : -1;
}

typedef struct {
  uint32_t h[5];
  uint64_t len_bits;
  uint8_t block[64];
  size_t block_len;
} Sha1Ctx;

static uint32_t sha1_rol(uint32_t x, uint32_t n) {
  return (x << n) | (x >> (32u - n));
}

static void sha1_init(Sha1Ctx *ctx) {
  ctx->h[0] = 0x67452301u;
  ctx->h[1] = 0xEFCDAB89u;
  ctx->h[2] = 0x98BADCFEu;
  ctx->h[3] = 0x10325476u;
  ctx->h[4] = 0xC3D2E1F0u;
  ctx->len_bits = 0;
  ctx->block_len = 0;
}

static void sha1_process_block(Sha1Ctx *ctx, const uint8_t block[64]) {
  uint32_t w[80];
  for (int i = 0; i < 16; i++) {
    size_t j = (size_t)i * 4u;
    w[i] = ((uint32_t)block[j] << 24) | ((uint32_t)block[j + 1] << 16) |
           ((uint32_t)block[j + 2] << 8) | (uint32_t)block[j + 3];
  }
  for (int i = 16; i < 80; i++) {
    w[i] = sha1_rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1u);
  }

  uint32_t a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3],
           e = ctx->h[4];

  for (int i = 0; i < 80; i++) {
    uint32_t f, k;
    if (i < 20) {
      f = (b & c) | ((~b) & d);
      k = 0x5A827999u;
    } else if (i < 40) {
      f = b ^ c ^ d;
      k = 0x6ED9EBA1u;
    } else if (i < 60) {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8F1BBCDCu;
    } else {
      f = b ^ c ^ d;
      k = 0xCA62C1D6u;
    }

    uint32_t temp = sha1_rol(a, 5u) + f + e + k + w[i];
    e = d;
    d = c;
    c = sha1_rol(b, 30u);
    b = a;
    a = temp;
  }

  ctx->h[0] += a;
  ctx->h[1] += b;
  ctx->h[2] += c;
  ctx->h[3] += d;
  ctx->h[4] += e;
}

static void sha1_update(Sha1Ctx *ctx, const uint8_t *data, size_t len) {
  if (!ctx || !data)
    return;
  ctx->len_bits += (uint64_t)len * 8u;
  while (len > 0) {
    size_t take = 64u - ctx->block_len;
    if (take > len)
      take = len;
    memcpy(ctx->block + ctx->block_len, data, take);
    ctx->block_len += take;
    data += take;
    len -= take;
    if (ctx->block_len == 64u) {
      sha1_process_block(ctx, ctx->block);
      ctx->block_len = 0;
    }
  }
}

static void sha1_final(Sha1Ctx *ctx, uint8_t out[20]) {
  if (!ctx || !out)
    return;
  ctx->block[ctx->block_len++] = 0x80;

  if (ctx->block_len > 56u) {
    while (ctx->block_len < 64u)
      ctx->block[ctx->block_len++] = 0;
    sha1_process_block(ctx, ctx->block);
    ctx->block_len = 0;
  }

  while (ctx->block_len < 56u)
    ctx->block[ctx->block_len++] = 0;

  for (int i = 7; i >= 0; i--) {
    ctx->block[ctx->block_len++] = (uint8_t)((ctx->len_bits >> (i * 8)) & 0xFF);
  }

  sha1_process_block(ctx, ctx->block);
  for (int i = 0; i < 5; i++) {
    out[i * 4] = (uint8_t)((ctx->h[i] >> 24) & 0xFF);
    out[i * 4 + 1] = (uint8_t)((ctx->h[i] >> 16) & 0xFF);
    out[i * 4 + 2] = (uint8_t)((ctx->h[i] >> 8) & 0xFF);
    out[i * 4 + 3] = (uint8_t)(ctx->h[i] & 0xFF);
  }
}

static int ws_base64_encode(const uint8_t *in, size_t in_len, char *out,
                            size_t out_cap) {
  static const char table[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  size_t out_needed = ((in_len + 2u) / 3u) * 4u;
  if (!out || out_cap < out_needed + 1u)
    return -1;

  size_t i = 0;
  size_t j = 0;
  while (i < in_len) {
    size_t rem = in_len - i;
    uint32_t octet_a = in[i++];
    uint32_t octet_b = (rem > 1) ? in[i++] : 0;
    uint32_t octet_c = (rem > 2) ? in[i++] : 0;
    uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

    out[j++] = table[(triple >> 18) & 0x3F];
    out[j++] = table[(triple >> 12) & 0x3F];
    out[j++] = (rem > 1) ? table[(triple >> 6) & 0x3F] : '=';
    out[j++] = (rem > 2) ? table[triple & 0x3F] : '=';
  }

  out[j] = '\0';
  return 0;
}

static int ws_compute_accept_key(const char *client_key, char *out,
                                 size_t out_cap) {
  if (!client_key || !out)
    return -1;

  char input[256];
  int n = snprintf(input, sizeof(input), "%s%s", client_key, WS_GUID);
  if (n <= 0 || (size_t)n >= sizeof(input))
    return -1;

  uint8_t digest[20];
  Sha1Ctx ctx;
  sha1_init(&ctx);
  sha1_update(&ctx, (const uint8_t *)input, (size_t)n);
  sha1_final(&ctx, digest);

  return ws_base64_encode(digest, sizeof(digest), out, out_cap);
}

static int ws_send_frame(wamble_socket_t sock, uint8_t opcode,
                         const uint8_t *payload, size_t payload_len) {
  if (payload_len > WS_FRAME_MAX)
    return -1;
  if ((opcode & WS_OPCODE_CLOSE) != 0u && payload_len > WS_CONTROL_PAYLOAD_MAX)
    return -1;

  uint8_t hdr[10];
  size_t hdr_len = 0;

  hdr[hdr_len++] = (uint8_t)(0x80u | (opcode & 0x0Fu));
  if (payload_len <= 125u) {
    hdr[hdr_len++] = (uint8_t)payload_len;
  } else {
    hdr[hdr_len++] = 126u;
    hdr[hdr_len++] = (uint8_t)((payload_len >> 8) & 0xFF);
    hdr[hdr_len++] = (uint8_t)(payload_len & 0xFF);
  }

  if (ws_send_all(sock, hdr, hdr_len) != 0)
    return -1;
  if (payload_len > 0 && ws_send_all(sock, payload, payload_len) != 0)
    return -1;
  return 0;
}

static int ws_send_close_code(wamble_socket_t sock, uint16_t code) {
  uint8_t payload[2];
  payload[0] = (uint8_t)((code >> 8) & 0xFFu);
  payload[1] = (uint8_t)(code & 0xFFu);
  return ws_send_frame(sock, WS_OPCODE_CLOSE, payload, sizeof(payload));
}

typedef enum WsReadStatus {
  WS_READ_OK = 0,
  WS_READ_ERR_IO = -1,
  WS_READ_ERR_PROTOCOL = -2,
  WS_READ_ERR_TOO_BIG = -3,
} WsReadStatus;

static WsReadStatus ws_read_frame_prefetch_copy(wamble_socket_t sock,
                                                uint8_t *prefetch,
                                                size_t *prefetch_len,
                                                uint8_t *dst, size_t need_len);

static WsReadStatus
ws_read_frame_prefetch(wamble_socket_t sock, uint8_t *prefetch,
                       size_t *prefetch_len, uint8_t *out_opcode,
                       uint8_t *payload, size_t payload_cap, size_t *out_len) {
  if (!prefetch || !prefetch_len || !out_opcode || !payload || !out_len)
    return WS_READ_ERR_PROTOCOL;
  size_t total_len = 0;
  int fragmented_binary = 0;
  uint8_t message_opcode = 0;

  for (;;) {
    uint8_t h2[2];
    if (ws_read_frame_prefetch_copy(sock, prefetch, prefetch_len, h2,
                                    sizeof(h2)) != WS_READ_OK) {
      return WS_READ_ERR_IO;
    }

    uint8_t rsv = (uint8_t)((h2[0] >> 4) & 0x07u);
    uint8_t fin = (uint8_t)((h2[0] >> 7) & 1u);
    uint8_t opcode = (uint8_t)(h2[0] & 0x0Fu);
    uint8_t is_control = (uint8_t)((opcode & 0x08u) != 0u);
    uint8_t masked = (uint8_t)((h2[1] >> 7) & 1u);
    uint64_t len = (uint64_t)(h2[1] & 0x7Fu);

    if (rsv != 0u)
      return WS_READ_ERR_PROTOCOL;
    if (is_control && fin == 0u)
      return WS_READ_ERR_PROTOCOL;

    if (len == 126u) {
      if (is_control)
        return WS_READ_ERR_PROTOCOL;
      uint8_t ext[2];
      if (ws_read_frame_prefetch_copy(sock, prefetch, prefetch_len, ext,
                                      sizeof(ext)) != WS_READ_OK) {
        return WS_READ_ERR_IO;
      }
      len = ((uint64_t)ext[0] << 8) | (uint64_t)ext[1];
    } else if (len == 127u) {
      if (is_control)
        return WS_READ_ERR_PROTOCOL;
      uint8_t ext[8];
      if (ws_read_frame_prefetch_copy(sock, prefetch, prefetch_len, ext,
                                      sizeof(ext)) != WS_READ_OK) {
        return WS_READ_ERR_IO;
      }
      len = 0;
      for (int i = 0; i < 8; i++) {
        len = (len << 8) | (uint64_t)ext[i];
      }
    }

    if (!masked || (is_control && len > WS_CONTROL_PAYLOAD_MAX))
      return WS_READ_ERR_PROTOCOL;
    if (len > (uint64_t)(payload_cap - total_len))
      return WS_READ_ERR_TOO_BIG;

    uint8_t mask[4];
    if (ws_read_frame_prefetch_copy(sock, prefetch, prefetch_len, mask,
                                    sizeof(mask)) != WS_READ_OK) {
      return WS_READ_ERR_IO;
    }
    if (len > 0 && ws_read_frame_prefetch_copy(sock, prefetch, prefetch_len,
                                               payload + total_len,
                                               (size_t)len) != WS_READ_OK) {
      return WS_READ_ERR_IO;
    }

    for (uint64_t i = 0; i < len; i++) {
      payload[total_len + (size_t)i] ^= mask[i % 4u];
    }

    if (!fragmented_binary) {
      if (opcode == WS_OPCODE_CONTINUATION)
        return WS_READ_ERR_PROTOCOL;
      if (fin == 1u) {
        *out_opcode = opcode;
        *out_len = (size_t)len;
        return WS_READ_OK;
      }
      if (opcode != WS_OPCODE_BINARY)
        return WS_READ_ERR_PROTOCOL;
      fragmented_binary = 1;
      message_opcode = opcode;
      total_len += (size_t)len;
      continue;
    }

    if (is_control || opcode != WS_OPCODE_CONTINUATION)
      return WS_READ_ERR_PROTOCOL;
    total_len += (size_t)len;
    if (fin == 1u) {
      *out_opcode = message_opcode;
      *out_len = total_len;
      return WS_READ_OK;
    }
  }
}

static WsReadStatus ws_read_frame_prefetch_copy(wamble_socket_t sock,
                                                uint8_t *prefetch,
                                                size_t *prefetch_len,
                                                uint8_t *dst, size_t need_len) {
  size_t copied = 0;
  if (!prefetch || !prefetch_len || !dst)
    return WS_READ_ERR_PROTOCOL;

  if (*prefetch_len > 0) {
    size_t take = (*prefetch_len < need_len) ? *prefetch_len : need_len;
    memcpy(dst, prefetch, take);
    if (take < *prefetch_len) {
      memmove(prefetch, prefetch + take, *prefetch_len - take);
    }
    *prefetch_len -= take;
    copied = take;
  }

  if (copied < need_len &&
      ws_recv_exact(sock, dst + copied, need_len - copied) != 0) {
    return WS_READ_ERR_IO;
  }

  return WS_READ_OK;
}

static int ws_wait_tcp_ready(wamble_socket_t tcp_sock, size_t prefetch_len) {
  if (prefetch_len > 0)
    return 1;
  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(tcp_sock, &rfds);
  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 20000;
  int sel =
#ifdef WAMBLE_PLATFORM_WINDOWS
      select(0, &rfds, NULL, NULL, &tv);
#else
      select(tcp_sock + 1, &rfds, NULL, NULL, &tv);
#endif
  if (sel <= 0)
    return sel;
  return FD_ISSET(tcp_sock, &rfds) ? 1 : 0;
}

static void ws_drain_peer_after_close(wamble_socket_t tcp_sock) {
#ifdef WAMBLE_PLATFORM_WINDOWS
  (void)shutdown(tcp_sock, SD_SEND);
#else
  (void)shutdown(tcp_sock, SHUT_WR);
#endif
  for (int i = 0; i < 4; i++) {
    fd_set dr;
    FD_ZERO(&dr);
    FD_SET(tcp_sock, &dr);
    struct timeval dtv;
    dtv.tv_sec = 0;
    dtv.tv_usec = 15000;
    int dsel =
#ifdef WAMBLE_PLATFORM_WINDOWS
        select(0, &dr, NULL, NULL, &dtv);
#else
        select(tcp_sock + 1, &dr, NULL, NULL, &dtv);
#endif
    if (dsel <= 0 || !FD_ISSET(tcp_sock, &dr))
      break;

    uint8_t drain[256];
    wamble_io_count_t dn = recv(tcp_sock, (char *)drain,
#ifdef WAMBLE_PLATFORM_WINDOWS
                                (int)sizeof(drain),
#else
                                sizeof(drain),
#endif
                                0);
    if (dn <= 0)
      break;
  }
}

static void ws_handle_bad_incoming_frame(wamble_socket_t tcp_sock,
                                         WsReadStatus read_status) {
  int sent_close = 0;
  if (read_status == WS_READ_ERR_PROTOCOL) {
    sent_close = (ws_send_close_code(tcp_sock, WS_CLOSE_PROTOCOL_ERROR) == 0);
  } else if (read_status == WS_READ_ERR_TOO_BIG) {
    sent_close = (ws_send_close_code(tcp_sock, WS_CLOSE_MESSAGE_TOO_BIG) == 0);
  }
  if (sent_close)
    ws_drain_peer_after_close(tcp_sock);
}

static int ws_enqueue_inbound_packet(WambleWsGateway *gw,
                                     const struct sockaddr_in *addr,
                                     const uint8_t *packet, size_t packet_len) {
  if (!gw || !addr || !packet || packet_len == 0 ||
      packet_len > WAMBLE_MAX_PACKET_SIZE) {
    return -1;
  }
  wamble_mutex_lock(&gw->mutex);
  if (gw->inbound_count >= gw->inbound_cap) {
    wamble_mutex_unlock(&gw->mutex);
    return -1;
  }
  int slot = (gw->inbound_head + gw->inbound_count) % gw->inbound_cap;
  WsInboundPacket *dst = &gw->inbound_packets[slot];
  dst->addr = *addr;
  dst->len = packet_len;
  memcpy(dst->data, packet, packet_len);
  gw->inbound_count++;
  wamble_mutex_unlock(&gw->mutex);
  return 0;
}

static int ws_slot_flush_locked(WambleWsGateway *gw, WsClientSlot *slot) {
  if (!slot || slot->tcp_sock == WAMBLE_INVALID_SOCKET)
    return -1;
  if (slot->tx_batch_len == 0)
    return 0;
  uint8_t frame[WS_FRAME_MAX];
  size_t frame_len = slot->tx_batch_len;
  uint32_t route_id = slot->route_id;
  memcpy(frame, slot->tx_batch, frame_len);
  slot->tx_batch_len = 0;
  if (ws_send_frame(slot->tcp_sock, WS_OPCODE_BINARY, frame, frame_len) != 0)
    return -1;
  {
    char detail[96];
    snprintf(detail, sizeof(detail), "route=%u bytes=%zu", (unsigned)route_id,
             frame_len);
    publish_ws_gateway_status_detail(WS_GATEWAY_STATUS_OUTBOUND_FLUSHED, gw,
                                     detail);
  }
  return 0;
}

static int ws_handle_binary_payload(WambleWsGateway *gw, WsClientSlot *slot,
                                    const uint8_t *payload, size_t len) {
  if (!gw || !slot || !payload)
    return -1;
  size_t offset = 0;
  while (offset < len) {
    size_t packet_len = 0;
    if (wamble_wire_packet_size(payload + offset, len - offset, &packet_len) !=
        NET_OK) {
      return -1;
    }
    if (packet_len == 0 || packet_len > WAMBLE_MAX_PACKET_SIZE)
      return -1;
    if (ws_enqueue_inbound_packet(gw, &slot->virtual_addr, payload + offset,
                                  packet_len) != 0) {
      return -1;
    }
    offset += packet_len;
  }
  return 0;
}

static int ws_process_client_stream(WambleWsGateway *gw, WsClientSlot *slot,
                                    wamble_socket_t tcp_sock, uint8_t *prefetch,
                                    size_t prefetch_len) {
  if (!gw || !slot || !prefetch)
    return -1;
  uint8_t ws_payload[WS_FRAME_MAX];
  {
    char detail[64];
    snprintf(detail, sizeof(detail), "route=%u", (unsigned)slot->route_id);
    publish_ws_gateway_status_detail(WS_GATEWAY_STATUS_STREAM_STARTED, gw,
                                     detail);
  }
  while (!slot->should_stop && !gw->should_stop) {
    int ready = ws_wait_tcp_ready(tcp_sock, prefetch_len);
    if (ready < 0) {
      char detail[64];
      snprintf(detail, sizeof(detail), "route=%u", (unsigned)slot->route_id);
      publish_ws_gateway_status_detail(WS_GATEWAY_STATUS_WAIT_FAILED, gw,
                                       detail);
      return -1;
    }
    if (ready == 0) {
      int flush_rc = 0;
      wamble_mutex_lock(&gw->mutex);
      if (slot->tx_batch_len > 0)
        flush_rc = ws_slot_flush_locked(gw, slot);
      wamble_mutex_unlock(&gw->mutex);
      if (flush_rc != 0) {
        char detail[64];
        snprintf(detail, sizeof(detail), "route=%u", (unsigned)slot->route_id);
        publish_ws_gateway_status_detail(
            WS_GATEWAY_STATUS_OUTBOUND_FLUSH_FAILED, gw, detail);
        return -1;
      }
      continue;
    }

    uint8_t opcode = 0;
    size_t len = 0;
    WsReadStatus rst =
        ws_read_frame_prefetch(tcp_sock, prefetch, &prefetch_len, &opcode,
                               ws_payload, sizeof(ws_payload), &len);
    if (rst != WS_READ_OK) {
      char detail[96];
      snprintf(detail, sizeof(detail), "route=%u read_status=%d",
               (unsigned)slot->route_id, (int)rst);
      publish_ws_gateway_status_detail(WS_GATEWAY_STATUS_READ_FAILED, gw,
                                       detail);
      ws_handle_bad_incoming_frame(tcp_sock, rst);
      return -1;
    }
    if (opcode == WS_OPCODE_CLOSE) {
      if (len > WS_CONTROL_PAYLOAD_MAX) {
        char detail[96];
        snprintf(detail, sizeof(detail), "route=%u len=%zu",
                 (unsigned)slot->route_id, len);
        publish_ws_gateway_status_detail(WS_GATEWAY_STATUS_CLOSE_TOO_LARGE, gw,
                                         detail);
        (void)ws_send_close_code(tcp_sock, WS_CLOSE_PROTOCOL_ERROR);
        return -1;
      }
      {
        char detail[96];
        snprintf(detail, sizeof(detail), "route=%u len=%zu",
                 (unsigned)slot->route_id, len);
        publish_ws_gateway_status_detail(WS_GATEWAY_STATUS_CLOSE_RECEIVED, gw,
                                         detail);
      }
      (void)ws_send_frame(tcp_sock, WS_OPCODE_CLOSE, ws_payload, len);
      return 0;
    }
    if (opcode == WS_OPCODE_PING) {
      if (ws_send_frame(tcp_sock, WS_OPCODE_PONG, ws_payload, len) != 0)
        return -1;
      continue;
    }
    if (opcode == WS_OPCODE_PONG)
      continue;
    if (opcode != WS_OPCODE_BINARY) {
      char detail[96];
      snprintf(detail, sizeof(detail), "route=%u opcode=0x%02x",
               (unsigned)slot->route_id, (unsigned)opcode);
      publish_ws_gateway_status_detail(WS_GATEWAY_STATUS_NON_BINARY_OPCODE, gw,
                                       detail);
      (void)ws_send_close_code(tcp_sock, WS_CLOSE_PROTOCOL_ERROR);
      return -1;
    }
    if (ws_handle_binary_payload(gw, slot, ws_payload, len) != 0) {
      char detail[96];
      snprintf(detail, sizeof(detail), "route=%u len=%zu",
               (unsigned)slot->route_id, len);
      publish_ws_gateway_status_detail(WS_GATEWAY_STATUS_BINARY_REJECTED, gw,
                                       detail);
      (void)ws_send_close_code(tcp_sock, WS_CLOSE_PROTOCOL_ERROR);
      return -1;
    }
    int flush_rc = 0;
    wamble_mutex_lock(&gw->mutex);
    if (slot->tx_batch_len > 0)
      flush_rc = ws_slot_flush_locked(gw, slot);
    wamble_mutex_unlock(&gw->mutex);
    if (flush_rc != 0) {
      char detail[64];
      snprintf(detail, sizeof(detail), "route=%u", (unsigned)slot->route_id);
      publish_ws_gateway_status_detail(WS_GATEWAY_STATUS_OUTBOUND_FLUSH_FAILED,
                                       gw, detail);
      return -1;
    }
  }
  {
    char detail[96];
    snprintf(detail, sizeof(detail), "route=%u should_stop=%d gateway_stop=%d",
             (unsigned)slot->route_id, slot->should_stop, gw->should_stop);
    publish_ws_gateway_status_detail(WS_GATEWAY_STATUS_STREAM_EXITED, gw,
                                     detail);
  }
  return -1;
}

static int ws_read_http_handshake(wamble_socket_t tcp_sock, uint8_t *req,
                                  size_t req_cap, uint8_t *prefetch,
                                  size_t prefetch_cap,
                                  size_t *out_prefetch_len) {
  size_t used = 0;
  if (!req || req_cap == 0 || !prefetch || !out_prefetch_len)
    return -1;

  for (;;) {
    if (used >= req_cap - 1u)
      return -1;
    size_t got = 0;
    if (ws_recv_some(tcp_sock, req + used, req_cap - 1u - used, &got) != 0)
      return -1;
    used += got;
    req[used] = '\0';
    if (strstr((const char *)req, "\r\n\r\n") != NULL)
      break;
  }

  char *headers_end = strstr((char *)req, "\r\n\r\n");
  if (!headers_end)
    return -1;

  size_t header_len = (size_t)((headers_end + 4) - (char *)req);
  *out_prefetch_len = used - header_len;
  if (*out_prefetch_len > prefetch_cap)
    return -1;
  if (*out_prefetch_len > 0) {
    memcpy(prefetch, req + header_len, *out_prefetch_len);
  }

  *headers_end = '\0';
  return 0;
}

static int ws_parse_http_request_line(uint8_t *req, char **out_headers,
                                      char *method, char *path, char *version) {
  if (!req || !out_headers || !method || !path || !version)
    return -1;

  char *line_end = strstr((char *)req, "\r\n");
  if (!line_end)
    return -1;
  *line_end = '\0';
  *out_headers = line_end + 2;

  if (sscanf((char *)req, "%15s %255s %15s", method, path, version) != 3)
    return -1;
  return 0;
}

static int ws_path_matches(const char *request_path,
                           const char *expected_path) {
  if (!request_path || !expected_path)
    return 0;

  char req_path[256];
  snprintf(req_path, sizeof(req_path), "%s", request_path);
  char *q = strchr(req_path, '?');
  if (q)
    *q = '\0';
  return strcmp(req_path, expected_path) == 0;
}

static int ws_validate_upgrade_headers(wamble_socket_t tcp_sock,
                                       const char *headers, char *accept_key,
                                       size_t accept_key_cap) {
  char upgrade[64];
  char connection[128];
  char ws_key[128];
  char ws_ver[32];

  if (ws_extract_header(headers, "Upgrade", upgrade, sizeof(upgrade)) != 0 ||
      ws_extract_header(headers, "Connection", connection,
                        sizeof(connection)) != 0 ||
      ws_extract_header(headers, "Sec-WebSocket-Key", ws_key, sizeof(ws_key)) !=
          0 ||
      ws_extract_header(headers, "Sec-WebSocket-Version", ws_ver,
                        sizeof(ws_ver)) != 0) {
    (void)ws_send_http_response(tcp_sock, 400, "Bad Request",
                                "missing websocket headers");
    return -1;
  }

  if (strcmp(ws_ver, "13") != 0) {
    (void)ws_send_http_upgrade_required(tcp_sock);
    return -1;
  }

  if (WAMBLE_STRCASECMP(upgrade, "websocket") != 0 ||
      !ws_contains_token_ci(connection, "Upgrade")) {
    (void)ws_send_http_response(tcp_sock, 400, "Bad Request",
                                "invalid websocket headers");
    return -1;
  }

  if (ws_validate_client_key(ws_key) != 0) {
    (void)ws_send_http_response(tcp_sock, 400, "Bad Request",
                                "invalid websocket key");
    return -1;
  }

  if (ws_compute_accept_key(ws_key, accept_key, accept_key_cap) != 0) {
    (void)ws_send_http_response(tcp_sock, 500, "Internal Server Error",
                                "handshake failed");
    return -1;
  }

  return 0;
}

static int ws_send_upgrade_switching_protocols(wamble_socket_t tcp_sock,
                                               const char *accept_key) {
  char response[512];
  int n = snprintf(response, sizeof(response),
                   "HTTP/1.1 101 Switching Protocols\r\n"
                   "Upgrade: websocket\r\n"
                   "Connection: Upgrade\r\n"
                   "Sec-WebSocket-Accept: %s\r\n"
                   "\r\n",
                   accept_key);
  if (n <= 0 || (size_t)n >= sizeof(response))
    return -1;
  return ws_send_all(tcp_sock, (const uint8_t *)response, (size_t)n);
}

static int ws_upgrade_and_serve(WambleWsGateway *gw, WsClientSlot *slot,
                                int slot_index, wamble_socket_t tcp_sock) {
  uint8_t req[WS_HANDSHAKE_MAX + 1];
  uint8_t prefetch[WS_PREFETCH_MAX];
  size_t prefetch_len = 0;
  if (ws_read_http_handshake(tcp_sock, req, sizeof(req), prefetch,
                             sizeof(prefetch), &prefetch_len) != 0) {
    publish_ws_gateway_status_detail(WS_GATEWAY_STATUS_HANDSHAKE_READ_FAILED,
                                     gw, NULL);
    return -1;
  }

  char *headers = NULL;
  char method[16] = {0};
  char path[256] = {0};
  char version[16] = {0};
  if (ws_parse_http_request_line(req, &headers, method, path, version) != 0) {
    publish_ws_gateway_status_detail(WS_GATEWAY_STATUS_BAD_REQUEST_LINE, gw,
                                     NULL);
    (void)ws_send_http_response(tcp_sock, 400, "Bad Request", "bad request");
    return -1;
  }

  if (strcmp(method, "GET") != 0) {
    (void)ws_send_http_response(tcp_sock, 405, "Method Not Allowed",
                                "GET required");
    return -1;
  }

  if (!ws_path_matches(path, gw->ws_path)) {
    char detail[128];
    snprintf(detail, sizeof(detail), "request=%s expected=%s", path,
             gw->ws_path ? gw->ws_path : "");
    publish_ws_gateway_status_detail(WS_GATEWAY_STATUS_PATH_MISMATCH, gw,
                                     detail);
    (void)ws_send_http_response(tcp_sock, 404, "Not Found", "not found");
    return -1;
  }

  char accept_key[128];
  if (ws_validate_upgrade_headers(tcp_sock, headers, accept_key,
                                  sizeof(accept_key)) != 0) {
    publish_ws_gateway_status_detail(WS_GATEWAY_STATUS_UPGRADE_HEADER_INVALID,
                                     gw, NULL);
    return -1;
  }

  if (ws_send_upgrade_switching_protocols(tcp_sock, accept_key) != 0) {
    publish_ws_gateway_status_detail(WS_GATEWAY_STATUS_SEND_101_FAILED, gw,
                                     NULL);
    return -1;
  }
  {
    char detail[128];
    snprintf(detail, sizeof(detail), "method=%s path=%s version=%s", method,
             path, version);
    publish_ws_gateway_status_detail(WS_GATEWAY_STATUS_UPGRADE_ACCEPTED, gw,
                                     detail);
  }

  if (ws_route_register(gw, slot_index, &slot->virtual_addr, &slot->route_id) !=
      0) {
    publish_ws_gateway_status_detail(WS_GATEWAY_STATUS_ROUTE_REGISTER_FAILED,
                                     gw, NULL);
    return -1;
  }
  slot->upgraded = 1;
  {
    char detail[64];
    snprintf(detail, sizeof(detail), "route=%u", (unsigned)slot->route_id);
    publish_ws_gateway_status_detail(WS_GATEWAY_STATUS_ROUTE_REGISTERED, gw,
                                     detail);
  }

  int rc = ws_process_client_stream(gw, slot, tcp_sock, prefetch, prefetch_len);
  {
    char detail[96];
    snprintf(detail, sizeof(detail), "route=%u rc=%d", (unsigned)slot->route_id,
             rc);
    publish_ws_gateway_status_detail(WS_GATEWAY_STATUS_STREAM_EXITED, gw,
                                     detail);
  }
  return rc;
}

static void ws_mark_client_slot_closed(WambleWsGateway *gw, int slot_index) {
  if (!gw || slot_index < 0)
    return;
  uint32_t route_id = 0;
  wamble_mutex_lock(&gw->mutex);
  if (slot_index < gw->clients_capacity) {
    WsClientSlot *slot = gw->clients[slot_index];
    if (slot) {
      route_id = slot->route_id;
      slot->in_use = 0;
      slot->should_stop = 0;
      slot->upgraded = 0;
      slot->route_id = 0;
      slot->tx_batch_len = 0;
      memset(&slot->virtual_addr, 0, sizeof(slot->virtual_addr));
      slot->tcp_sock = WAMBLE_INVALID_SOCKET;
    }
  }
  if (gw->active_client_threads > 0)
    gw->active_client_threads--;
  wamble_cond_broadcast(&gw->clients_done);
  wamble_mutex_unlock(&gw->mutex);
  ws_route_unregister(route_id);
}

static void *ws_client_main(void *arg) {
  WsClientCtx *ctx = (WsClientCtx *)arg;
  if (!ctx || !ctx->gateway)
    return NULL;

  WambleWsGateway *gw = ctx->gateway;
  int slot_index = ctx->slot_index;
  free(ctx);

  wamble_socket_t tcp_sock = WAMBLE_INVALID_SOCKET;
  WsClientSlot *slot = NULL;

  wamble_mutex_lock(&gw->mutex);
  if (slot_index >= 0 && slot_index < gw->clients_capacity) {
    slot = gw->clients[slot_index];
    if (slot)
      tcp_sock = slot->tcp_sock;
  }
  wamble_mutex_unlock(&gw->mutex);

  if (!slot || tcp_sock == WAMBLE_INVALID_SOCKET) {
    ws_mark_client_slot_closed(gw, slot_index);
    return NULL;
  }

  (void)ws_upgrade_and_serve(gw, slot, slot_index, tcp_sock);
  wamble_close_socket(tcp_sock);
  ws_mark_client_slot_closed(gw, slot_index);
  return NULL;
}

static int ws_allocate_client_slot(WambleWsGateway *gw, wamble_socket_t sock,
                                   int *out_slot) {
  if (!gw || !out_slot)
    return -1;
  *out_slot = -1;
  wamble_mutex_lock(&gw->mutex);
  for (int i = 0; i < gw->clients_capacity; i++) {
    WsClientSlot *slot = gw->clients[i];
    if (slot && !slot->in_use) {
      slot->in_use = 1;
      slot->should_stop = 0;
      slot->upgraded = 0;
      slot->route_id = 0;
      slot->tx_batch_len = 0;
      memset(&slot->virtual_addr, 0, sizeof(slot->virtual_addr));
      slot->tcp_sock = sock;
      *out_slot = i;
      break;
    }
  }
  if (*out_slot < 0) {
    int old_capacity = gw->clients_capacity;
    int new_capacity = old_capacity > 0 ? old_capacity * 2 : 1;
    if (new_capacity > old_capacity) {
      WsClientSlot **grown = (WsClientSlot **)realloc(
          gw->clients, (size_t)new_capacity * sizeof(*gw->clients));
      if (grown) {
        memset(grown + old_capacity, 0,
               (size_t)(new_capacity - old_capacity) * sizeof(*grown));
        WsClientSlot *slot = (WsClientSlot *)calloc(1, sizeof(*slot));
        if (!slot) {
          gw->clients = grown;
          gw->clients_capacity = new_capacity;
          wamble_mutex_unlock(&gw->mutex);
          return -1;
        }
        slot->tcp_sock = sock;
        slot->in_use = 1;
        gw->clients = grown;
        gw->clients_capacity = new_capacity;
        gw->clients[old_capacity] = slot;
        *out_slot = old_capacity;
      }
    }
  }
  wamble_mutex_unlock(&gw->mutex);
  return (*out_slot >= 0) ? 0 : -1;
}

static void *ws_accept_loop(void *arg) {
  WambleWsGateway *gw = (WambleWsGateway *)arg;
  if (!gw)
    return NULL;

  while (!gw->should_stop) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(gw->listen_sock, &rfds);
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    int sel =
#ifdef WAMBLE_PLATFORM_WINDOWS
        select(0, &rfds, NULL, NULL, &tv);
#else
        select(gw->listen_sock + 1, &rfds, NULL, NULL, &tv);
#endif
    if (sel <= 0)
      continue;

    struct sockaddr_in cliaddr;
    wamble_socklen_t clilen = sizeof(cliaddr);
    wamble_socket_t csock =
        accept(gw->listen_sock, (struct sockaddr *)&cliaddr, &clilen);
    if (csock == WAMBLE_INVALID_SOCKET)
      continue;

    int slot_index = -1;
    if (ws_allocate_client_slot(gw, csock, &slot_index) != 0) {
      (void)ws_send_http_response(csock, 503, "Service Unavailable",
                                  "too many websocket clients");
      wamble_close_socket(csock);
      continue;
    }

    WsClientCtx *ctx = (WsClientCtx *)calloc(1, sizeof(WsClientCtx));
    if (!ctx) {
      wamble_close_socket(csock);
      ws_mark_client_slot_closed(gw, slot_index);
      continue;
    }
    ctx->gateway = gw;
    ctx->slot_index = slot_index;

    wamble_mutex_lock(&gw->mutex);
    gw->active_client_threads++;
    wamble_mutex_unlock(&gw->mutex);

    wamble_thread_t t = 0;
    if (wamble_thread_create(&t, ws_client_main, ctx) != 0) {
      free(ctx);
      wamble_close_socket(csock);
      ws_mark_client_slot_closed(gw, slot_index);
      continue;
    }
    (void)wamble_thread_detach(t);
  }

  return NULL;
}

static wamble_socket_t ws_create_listener(int port) {
  wamble_socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == WAMBLE_INVALID_SOCKET)
    return WAMBLE_INVALID_SOCKET;

  int opt = 1;
  (void)setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt,
                   sizeof(opt));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons((uint16_t)port);
  if (bind(sock, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
    wamble_close_socket(sock);
    return WAMBLE_INVALID_SOCKET;
  }

  if (listen(sock, 128) != 0) {
    wamble_close_socket(sock);
    return WAMBLE_INVALID_SOCKET;
  }

#if defined(WAMBLE_PLATFORM_POSIX)
  {
    int flags = fcntl(sock, F_GETFD);
    if (flags >= 0)
      (void)fcntl(sock, F_SETFD, flags | FD_CLOEXEC);
  }
#elif defined(WAMBLE_PLATFORM_WINDOWS)
  {
    HANDLE h = (HANDLE)sock;
    SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0);
  }
#endif

  return sock;
}

static void ws_request_client_shutdowns(WambleWsGateway *gateway) {
  if (!gateway || !gateway->clients)
    return;
  for (int i = 0; i < gateway->clients_capacity; i++) {
    WsClientSlot *slot = gateway->clients[i];
    if (slot && slot->in_use && slot->tcp_sock != WAMBLE_INVALID_SOCKET) {
      slot->should_stop = 1;
#ifdef WAMBLE_PLATFORM_WINDOWS
      (void)shutdown(slot->tcp_sock, SD_BOTH);
#else
      (void)shutdown(slot->tcp_sock, SHUT_RDWR);
#endif
    }
  }
}

WambleWsGateway *ws_gateway_start(const char *profile_name, int ws_port,
                                  int udp_port, const char *ws_path,
                                  WsGatewayStatus *out_status) {
  WsGatewayStatus status = WS_GATEWAY_OK;
  int sync_ready = 0;
  WambleWsGateway *gw = NULL;

  if (out_status)
    *out_status = status;
  if (!ws_path || ws_path[0] != '/') {
    status = WS_GATEWAY_ERR_CONFIG;
    goto fail;
  }
  if (ws_port <= 0 || ws_port > 65535 || udp_port <= 0 || udp_port > 65535) {
    status = WS_GATEWAY_ERR_CONFIG;
    goto fail;
  }
  gw = (WambleWsGateway *)calloc(1, sizeof(WambleWsGateway));
  if (!gw)
    goto fail_alloc;

  gw->profile_name = ws_strdup_local(profile_name ? profile_name : "default");
  gw->ws_path = ws_strdup_local(ws_path);
  gw->ws_port = ws_port;
  gw->udp_port = udp_port;
  gw->clients_capacity = 0;
  gw->listen_sock = WAMBLE_INVALID_SOCKET;
  gw->running = 0;
  gw->should_stop = 0;
  gw->active_client_threads = 0;
  gw->inbound_packets = NULL;
  gw->inbound_cap = 0;
  gw->inbound_head = 0;
  gw->inbound_count = 0;

  if (!gw->profile_name || !gw->ws_path)
    goto fail_alloc;

  gw->inbound_cap = WS_INBOUND_QUEUE_CAP_DEFAULT;
  gw->inbound_packets = (WsInboundPacket *)calloc((size_t)gw->inbound_cap,
                                                  sizeof(WsInboundPacket));
  if (!gw->inbound_packets)
    goto fail_alloc;

  wamble_mutex_init(&gw->mutex);
  wamble_cond_init(&gw->clients_done);
  sync_ready = 1;

  gw->listen_sock = ws_create_listener(ws_port);
  if (gw->listen_sock == WAMBLE_INVALID_SOCKET) {
    status = WS_GATEWAY_ERR_BIND;
    goto fail;
  }

  if (wamble_thread_create(&gw->thread, ws_accept_loop, gw) != 0) {
    status = WS_GATEWAY_ERR_THREAD;
    goto fail;
  }

  gw->running = 1;
  return gw;

fail_alloc:
  status = WS_GATEWAY_ERR_ALLOC;
fail:
  if (out_status)
    *out_status = status;
  if (!gw)
    return NULL;
  if (gw->listen_sock != WAMBLE_INVALID_SOCKET) {
    wamble_close_socket(gw->listen_sock);
    gw->listen_sock = WAMBLE_INVALID_SOCKET;
  }
  if (sync_ready) {
    wamble_cond_destroy(&gw->clients_done);
    wamble_mutex_destroy(&gw->mutex);
  }
  for (int i = 0; i < gw->clients_capacity; i++)
    free(gw->clients ? gw->clients[i] : NULL);
  free(gw->clients);
  free(gw->inbound_packets);
  free(gw->profile_name);
  free(gw->ws_path);
  free(gw);
  return NULL;
}

void ws_gateway_stop(WambleWsGateway *gateway) {
  if (!gateway)
    return;

  gateway->should_stop = 1;
  if (gateway->listen_sock != WAMBLE_INVALID_SOCKET) {
    wamble_close_socket(gateway->listen_sock);
    gateway->listen_sock = WAMBLE_INVALID_SOCKET;
  }

  wamble_mutex_lock(&gateway->mutex);
  ws_request_client_shutdowns(gateway);
  wamble_mutex_unlock(&gateway->mutex);

  if (gateway->running) {
    (void)wamble_thread_join(gateway->thread, NULL);
    gateway->running = 0;
  }

  wamble_mutex_lock(&gateway->mutex);
  ws_request_client_shutdowns(gateway);
  while (gateway->active_client_threads > 0) {
    wamble_cond_wait(&gateway->clients_done, &gateway->mutex);
  }
  wamble_mutex_unlock(&gateway->mutex);
  ws_route_unregister_gateway(gateway);

  wamble_cond_destroy(&gateway->clients_done);
  wamble_mutex_destroy(&gateway->mutex);
  for (int i = 0; i < gateway->clients_capacity; i++)
    free(gateway->clients ? gateway->clients[i] : NULL);
  free(gateway->clients);
  free(gateway->inbound_packets);
  free(gateway->profile_name);
  free(gateway->ws_path);
  free(gateway);
}

int ws_gateway_matches(const WambleWsGateway *gateway, int ws_port,
                       int udp_port, const char *ws_path) {
  (void)udp_port;
  if (!gateway || !ws_path)
    return 0;
  if (gateway->ws_port != ws_port)
    return 0;
  if (!gateway->ws_path)
    return 0;
  if (strcmp(gateway->ws_path, ws_path) != 0)
    return 0;
  return 1;
}

int ws_gateway_active_client_count(WambleWsGateway *gateway) {
  if (!gateway)
    return 0;
  wamble_mutex_lock(&gateway->mutex);
  int n = gateway->active_client_threads;
  wamble_mutex_unlock(&gateway->mutex);
  return n;
}

int ws_gateway_pop_packet(WambleWsGateway *gateway, uint8_t *packet,
                          size_t packet_cap, size_t *out_packet_len,
                          struct sockaddr_in *out_cliaddr) {
  if (!gateway || !packet || !out_packet_len || !out_cliaddr)
    return -1;
  wamble_mutex_lock(&gateway->mutex);
  if (gateway->inbound_count <= 0) {
    wamble_mutex_unlock(&gateway->mutex);
    return 0;
  }
  WsInboundPacket *src = &gateway->inbound_packets[gateway->inbound_head];
  if (src->len > packet_cap) {
    wamble_mutex_unlock(&gateway->mutex);
    return -1;
  }
  memcpy(packet, src->data, src->len);
  *out_packet_len = src->len;
  *out_cliaddr = src->addr;
  gateway->inbound_head = (gateway->inbound_head + 1) % gateway->inbound_cap;
  gateway->inbound_count--;
  wamble_mutex_unlock(&gateway->mutex);
  return 1;
}

int ws_gateway_is_ws_client(const struct sockaddr_in *cliaddr) {
  WambleWsGateway *gw = NULL;
  int slot_index = -1;
  uint32_t route_id = 0;
  return ws_route_lookup(cliaddr, &gw, &slot_index, &route_id);
}

int ws_gateway_queue_packet(const struct sockaddr_in *cliaddr,
                            const uint8_t *packet, size_t packet_len) {
  if (!cliaddr || !packet || packet_len == 0 ||
      packet_len > WAMBLE_MAX_PACKET_SIZE) {
    return -1;
  }
  WambleWsGateway *gw = NULL;
  int slot_index = -1;
  uint32_t route_id = 0;
  if (!ws_route_lookup(cliaddr, &gw, &slot_index, &route_id))
    return 0;
  if (!gw || slot_index < 0)
    return -1;

  int result = -1;
  wamble_mutex_lock(&gw->mutex);
  if (gw->should_stop || slot_index >= gw->clients_capacity)
    goto done;
  WsClientSlot *slot = gw->clients[slot_index];
  if (!slot || !slot->in_use || !slot->upgraded || slot->route_id != route_id ||
      !ws_sockaddr_equal(&slot->virtual_addr, cliaddr) ||
      slot->tcp_sock == WAMBLE_INVALID_SOCKET) {
    goto done;
  }
  if (packet_len > WS_FRAME_MAX)
    goto done;
  if (slot->tx_batch_len > 0 &&
      slot->tx_batch_len + packet_len > sizeof(slot->tx_batch)) {
    if (ws_slot_flush_locked(gw, slot) != 0) {
      slot->should_stop = 1;
      publish_ws_gateway_status_detail(WS_GATEWAY_STATUS_OUTBOUND_FLUSH_FAILED,
                                       gw, "queue_flush");
      goto done;
    }
  }
  if (slot->tx_batch_len + packet_len > sizeof(slot->tx_batch)) {
    publish_ws_gateway_status_detail(WS_GATEWAY_STATUS_QUEUE_REJECTED, gw,
                                     "tx_batch_capacity");
    goto done;
  }
  memcpy(slot->tx_batch + slot->tx_batch_len, packet, packet_len);
  slot->tx_batch_len += packet_len;
  if (slot->tx_batch_len == sizeof(slot->tx_batch)) {
    if (ws_slot_flush_locked(gw, slot) != 0) {
      slot->should_stop = 1;
      publish_ws_gateway_status_detail(WS_GATEWAY_STATUS_OUTBOUND_FLUSH_FAILED,
                                       gw, "full_batch_flush");
      goto done;
    }
  }
  {
    char detail[96];
    snprintf(detail, sizeof(detail), "route=%u packet_len=%zu",
             (unsigned)route_id, packet_len);
    publish_ws_gateway_status_detail(WS_GATEWAY_STATUS_OUTBOUND_QUEUED, gw,
                                     detail);
  }
  result = 1;
done:
  wamble_mutex_unlock(&gw->mutex);
  return result;
}

int ws_gateway_flush_route(const struct sockaddr_in *cliaddr) {
  if (!cliaddr)
    return -1;
  WambleWsGateway *gw = NULL;
  int slot_index = -1;
  uint32_t route_id = 0;
  if (!ws_route_lookup(cliaddr, &gw, &slot_index, &route_id))
    return -1;
  if (!gw || slot_index < 0)
    return -1;
  int rc = -1;
  wamble_mutex_lock(&gw->mutex);
  if (gw->should_stop || slot_index >= gw->clients_capacity)
    goto done;
  WsClientSlot *slot = gw->clients[slot_index];
  if (!slot || !slot->in_use || !slot->upgraded || slot->route_id != route_id ||
      !ws_sockaddr_equal(&slot->virtual_addr, cliaddr) ||
      slot->tcp_sock == WAMBLE_INVALID_SOCKET) {
    goto done;
  }
  if (ws_slot_flush_locked(gw, slot) != 0) {
    slot->should_stop = 1;
    publish_ws_gateway_status_detail(WS_GATEWAY_STATUS_OUTBOUND_FLUSH_FAILED,
                                     gw, "flush_route");
    goto done;
  }
  rc = 0;
done:
  wamble_mutex_unlock(&gw->mutex);
  return rc;
}

void ws_gateway_flush_outbound(WambleWsGateway *gateway) {
  if (!gateway)
    return;
  wamble_mutex_lock(&gateway->mutex);
  for (int i = 0; i < gateway->clients_capacity; i++) {
    WsClientSlot *slot = gateway->clients[i];
    if (!slot || !slot->in_use || !slot->upgraded || slot->should_stop ||
        slot->tcp_sock == WAMBLE_INVALID_SOCKET || slot->tx_batch_len == 0) {
      continue;
    }
    if (ws_slot_flush_locked(gateway, slot) != 0) {
      publish_ws_gateway_status_detail(WS_GATEWAY_STATUS_OUTBOUND_FLUSH_FAILED,
                                       gateway, "flush_outbound");
      slot->should_stop = 1;
    }
  }
  wamble_mutex_unlock(&gateway->mutex);
}
