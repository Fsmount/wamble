#include "../include/wamble/wamble.h"
#include <limits.h>
void crypto_blake2b(uint8_t *hash, size_t hash_size, const uint8_t *msg,
                    size_t msg_size);
#define WAMBLE_TRANSPORT_INITIAL_CAP 64
#define WAMBLE_TRANSPORT_INITIAL_RTO_MS 250u
#define WAMBLE_INBOUND_PUMP_BATCH 64u
#define WAMBLE_CLASSIFY_BATCH 64u
#define WAMBLE_DISPATCH_BATCH 64u
#define TRANSPORT_LANE_NONE ((size_t)-1)

typedef enum {
  TRANSPORT_PACKET_SOURCE_UDP = 0,
  TRANSPORT_PACKET_SOURCE_WS = 1,
} TransportPacketSource;

typedef enum {
  TRANSPORT_OUTBOUND_LANE_UNSPECIFIED = 0,
  TRANSPORT_OUTBOUND_LANE_REQUEST_ACK = 1,
  TRANSPORT_OUTBOUND_LANE_RELIABLE_TERMINAL = 2,
  TRANSPORT_OUTBOUND_LANE_RELIABLE_BUNDLE = 3,
  TRANSPORT_OUTBOUND_LANE_UNRELIABLE = 4,
} TransportOutboundLane;

typedef enum {
  TRANSPORT_OUTBOUND_UNRELIABLE,
  TRANSPORT_OUTBOUND_RELIABLE_TERMINAL,
  TRANSPORT_OUTBOUND_RELIABLE_BUNDLE_FRAGMENT,
  TRANSPORT_OUTBOUND_REQUEST_ACK,
} TransportOutboundVariant;

typedef enum {
  TRANSPORT_DRIVE_IDLE = 0,
  TRANSPORT_DRIVE_PROGRESS = 1,
  TRANSPORT_DRIVE_PENDING = 2,
  TRANSPORT_DRIVE_BACKOFF = 3,
  TRANSPORT_DRIVE_ERROR = 4,
} TransportDriveStatus;

typedef struct TransportDriveResult {
  TransportDriveStatus status;
  uint64_t next_deadline_at_ms;
  uint64_t retry_after_ms;
  size_t inbound_pending;
  size_t dispatch_pending;
  size_t outbound_pending;
  uint32_t progress_count;
  uint32_t error_count;
} TransportDriveResult;

typedef uint64_t TransportEndpointId;
#define TRANSPORT_ENDPOINT_ID_INVALID ((TransportEndpointId)0)
typedef struct WambleWsGateway WambleWsGateway;

typedef struct TransportEndpointState {
  TransportEndpointId endpoint_id;
  struct sockaddr_in addr;
  uint8_t token[TOKEN_LENGTH];
  uint32_t next_reliable_seq;
  uint32_t srtt_ms;
  uint32_t rttvar_ms;
  uint32_t rto_ms;
  uint64_t last_rtt_sample_ms;
} TransportEndpointState;

typedef struct TransportInboundEntry {
  TransportPacketSource source;
  TransportEndpointId endpoint_id;
  struct sockaddr_in addr;
  size_t packet_len;
  uint8_t packet[WAMBLE_MAX_PACKET_SIZE];
} TransportInboundEntry;

typedef struct TransportDispatchEntry {
  TransportPacketSource source;
  TransportEndpointId endpoint_id;
  struct sockaddr_in addr;
  struct WambleMsg msg;
} TransportDispatchEntry;

typedef struct ReliableBundle {
  uint64_t bundle_id;
  TransportEndpointId endpoint_id;
  uint8_t ctrl;
  uint8_t token[TOKEN_LENGTH];
  uint64_t board_id;
  uint8_t *payload;
  size_t payload_len;
  uint16_t chunk_count;
  uint16_t next_fragment_index;
  uint8_t hash_algo;
  uint8_t hash[WAMBLE_FRAGMENT_HASH_LENGTH];
  uint32_t req_seq;
  uint32_t transfer_id;
  int replayable_terminal;
  uint8_t header_version;
  uint8_t flags;
  uint16_t max_retries;
  int timeout_ms;
  struct sockaddr_in addr;
} ReliableBundle;

typedef struct TransportOutboundEntry {
  TransportOutboundVariant variant;
  TransportOutboundLane lane;
  TransportEndpointId endpoint_id;
  struct sockaddr_in addr;
  uint8_t token[TOKEN_LENGTH];
  uint8_t *payload;
  size_t payload_len;
  union {
    struct {
      uint32_t seq;
      uint64_t deadline_at_ms;
      uint64_t sent_at_ms;
      uint32_t rto_ms;
      uint16_t retry_count;
      uint16_t max_retries;
    } reliable;
    struct {
      uint32_t seq;
      uint16_t fragment_index;
      uint16_t fragment_count;
      uint64_t bundle_id;
      uint64_t deadline_at_ms;
      uint64_t sent_at_ms;
      uint32_t rto_ms;
      uint16_t retry_count;
      uint16_t max_retries;
    } reliable_fragment;
    struct {
      uint32_t ack_seq;
      uint64_t deadline_at_ms;
    } ack;
  } as;
} TransportOutboundEntry;

ServerStatus handle_message(wamble_socket_t sockfd, const struct WambleMsg *msg,
                            const struct sockaddr_in *cliaddr, int trust_tier,
                            const char *profile_name);
int ws_gateway_pop_packet(WambleWsGateway *gateway, uint8_t *packet,
                          size_t packet_cap, size_t *out_packet_len,
                          struct sockaddr_in *out_cliaddr);
int ws_gateway_is_ws_client(const struct sockaddr_in *cliaddr);
int ws_gateway_queue_packet(const struct sockaddr_in *cliaddr,
                            const uint8_t *packet, size_t packet_len);
void ws_gateway_flush_outbound(WambleWsGateway *gateway);
int ws_gateway_flush_route(const struct sockaddr_in *cliaddr);
int network_enqueue_ack_after(const struct WambleMsg *msg,
                              const struct sockaddr_in *cliaddr);
int network_enqueue_reliable(const struct WambleMsg *msg,
                             const struct sockaddr_in *cliaddr, int timeout_ms,
                             int max_retries);
int send_unreliable_packet(wamble_socket_t sockfd, const struct WambleMsg *msg,
                           const struct sockaddr_in *cliaddr);

typedef struct WambleTerminalCachePacket {
  size_t len;
  uint32_t seq;
  uint8_t token[TOKEN_LENGTH];
  uint8_t *data;
} WambleTerminalCachePacket;

typedef struct WambleTerminalCacheSlot {
  uint32_t req_seq;
  uint64_t stored_mono_ms;
  int packet_count;
  int packet_cap;
  WambleTerminalCachePacket *packets;
} WambleTerminalCacheSlot;

typedef struct WambleClientSession {
  struct sockaddr_in addr;
  uint8_t token[TOKEN_LENGTH];
  int token_next_index;
  uint32_t last_seq_num;
  time_t last_seen;
  uint32_t next_seq_num;
  char treatment_group_key[128];
  WambleTerminalCacheSlot *terminal_cache;
  int terminal_cache_count;
} WambleClientSession;

typedef struct WambleCurrentRequest {
  struct WambleClientSession *session;
  uint32_t seq_num;
} WambleCurrentRequest;

static WAMBLE_THREAD_LOCAL WambleCurrentRequest g_current_request;

static WAMBLE_THREAD_LOCAL WambleClientSession *client_sessions;
static WAMBLE_THREAD_LOCAL int num_sessions = 0;
static WAMBLE_THREAD_LOCAL int client_sessions_capacity = 0;
static WAMBLE_THREAD_LOCAL uint32_t global_seq_num = 1;
static WAMBLE_THREAD_LOCAL uint32_t global_fragment_transfer_id = 1;

static WAMBLE_THREAD_LOCAL int *session_index_map;
static WAMBLE_THREAD_LOCAL int session_index_map_capacity = 0;

typedef struct TokenSessionMapEntry {
  int used;
  uint8_t token[TOKEN_LENGTH];
  int head_index;
} TokenSessionMapEntry;

static WAMBLE_THREAD_LOCAL TokenSessionMapEntry *token_session_index_map;
static WAMBLE_THREAD_LOCAL int token_session_index_map_capacity = 0;

static int token_has_any_byte(const uint8_t *token);
static int ensure_client_session_capacity(int needed);
static int send_serialized_packet_once(wamble_socket_t sockfd,
                                       const uint8_t *send_buffer,
                                       size_t serialized_size,
                                       const struct sockaddr_in *cliaddr,
                                       int *sent_over_ws);
static TransportDriveResult network_outbound_pump(wamble_socket_t sockfd,
                                                  size_t budget);
static int network_enqueue_serialized_reliable(
    const uint8_t *token, uint32_t seq_num, const uint8_t *send_buffer,
    size_t serialized_size, const struct sockaddr_in *cliaddr, int timeout_ms,
    int max_retries, int replayable_terminal);
static int network_enqueue_fragmented_replayable_terminal(
    const struct WambleMsg *source_msg, const struct sockaddr_in *cliaddr,
    int timeout_ms, int max_retries);
static int transport_size_ensure(void **items, size_t item_size,
                                 size_t *capacity, size_t need);
static uint32_t transport_rto_cap_ms(void);
static uint32_t transport_clamp_rto_ms(uint32_t rto_ms);
static uint64_t
transport_outbound_entry_deadline(const TransportOutboundEntry *entry);
static int transport_endpoint_update_rto_by_index(size_t idx,
                                                  uint32_t sample_ms,
                                                  int retransmitted);
static uint16_t
transport_outbound_entry_retry_count(const TransportOutboundEntry *entry);
static int transport_reliable_bundle_fragment_acked(uint64_t bundle_id);
static uint16_t
transport_outbound_entry_max_retries(const TransportOutboundEntry *entry);
static void transport_outbound_entry_arm_retry(TransportOutboundEntry *entry,
                                               uint64_t now_ms,
                                               uint32_t rto_ms);
static int transport_outbound_contains_reliable(uint32_t seq,
                                                const uint8_t *token,
                                                const struct sockaddr_in *addr);
static int
transport_outbound_match_and_remove_ack(TransportEndpointId endpoint_id,
                                        uint32_t seq, const uint8_t *token,
                                        const struct sockaddr_in *cliaddr);

static inline uint64_t mix64_s(uint64_t x) {
  x ^= x >> 33;
  x *= 0xff51afd7ed558ccdULL;
  x ^= x >> 33;
  x *= 0xc4ceb9fe1a85ec53ULL;
  x ^= x >> 33;
  return x;
}

static inline uint64_t addr_hash_key(const struct sockaddr_in *addr) {
  uint64_t ip = (uint64_t)addr->sin_addr.s_addr;
  uint64_t port = (uint64_t)addr->sin_port;
  return mix64_s((ip << 16) ^ port);
}

static int sockaddr_in_equal(const struct sockaddr_in *a,
                             const struct sockaddr_in *b) {
  if (!a || !b)
    return 0;
  return a->sin_addr.s_addr == b->sin_addr.s_addr && a->sin_port == b->sin_port;
}

static int session_map_capacity(void) { return session_index_map_capacity; }

static int session_map_next(int idx, int cap) {
  idx++;
  if (idx >= cap)
    idx = 0;
  return idx;
}

static int map_capacity_for_session_capacity(int session_capacity) {
  if (session_capacity <= 0)
    return 0;
  if (session_capacity > INT_MAX / 2)
    return 0;
  return session_capacity * 2;
}

static void session_map_init(void) {
  int cap = session_map_capacity();
  if (!session_index_map || cap <= 0)
    return;
  for (int i = 0; i < cap; i++)
    session_index_map[i] = -1;
}

static void token_session_map_init(void) {
  int cap = token_session_index_map_capacity;
  if (!token_session_index_map || cap <= 0)
    return;
  memset(token_session_index_map, 0,
         (size_t)cap * sizeof(*token_session_index_map));
}

static void session_map_put(const struct sockaddr_in *addr, int index) {
  int cap = session_map_capacity();
  if (!addr || !session_index_map || cap <= 0)
    return;
  uint64_t h = addr_hash_key(addr);
  int i = (int)(h % (uint64_t)cap);
  for (int probe = 0; probe < cap; probe++) {
    if (session_index_map[i] == -1) {
      session_index_map[i] = index;
      return;
    }
    int cur = session_index_map[i];
    if (cur >= 0) {
      const struct sockaddr_in *saddr = &client_sessions[cur].addr;
      if (sockaddr_in_equal(saddr, addr)) {
        session_index_map[i] = index;
        return;
      }
    }
    i = session_map_next(i, cap);
  }
}

static void session_map_rebuild(void) {
  session_map_init();
  if (!client_sessions)
    return;
  for (int i = 0; i < num_sessions; i++)
    session_map_put(&client_sessions[i].addr, i);
}

static int session_map_get(const struct sockaddr_in *addr) {
  int cap = session_map_capacity();
  if (!addr || !session_index_map || cap <= 0)
    return -1;
  uint64_t h = addr_hash_key(addr);
  int i = (int)(h % (uint64_t)cap);
  for (int probe = 0; probe < cap; probe++) {
    int cur = session_index_map[i];
    if (cur == -1)
      return -1;
    if (cur >= 0) {
      const struct sockaddr_in *saddr = &client_sessions[cur].addr;
      if (sockaddr_in_equal(saddr, addr))
        return cur;
    }
    i = session_map_next(i, cap);
  }
  return -1;
}

static int token_session_map_slot(const uint8_t *token, int create) {
  int cap = token_session_index_map_capacity;
  if (!token || !token_session_index_map || cap <= 0)
    return -1;
  uint32_t h = wamble_token_hash32(token);
  int i = (int)(h % (uint64_t)cap);
  for (int probe = 0; probe < cap; probe++) {
    TokenSessionMapEntry *entry = &token_session_index_map[i];
    if (!entry->used) {
      if (!create)
        return -1;
      entry->used = 1;
      memcpy(entry->token, token, TOKEN_LENGTH);
      entry->head_index = -1;
      return i;
    }
    if (memcmp(entry->token, token, TOKEN_LENGTH) == 0)
      return i;
    i = session_map_next(i, cap);
  }
  return -1;
}

static void token_session_map_put(const uint8_t *token, int index) {
  if (!token || index < 0)
    return;
  int slot = token_session_map_slot(token, 1);
  if (slot < 0)
    return;
  WambleClientSession *session = &client_sessions[index];
  TokenSessionMapEntry *entry = &token_session_index_map[slot];
  session->token_next_index = entry->head_index;
  entry->head_index = index;
}

static void token_session_map_remove(const uint8_t *token, int index) {
  if (!token || index < 0)
    return;
  int slot = token_session_map_slot(token, 0);
  if (slot < 0)
    return;
  TokenSessionMapEntry *entry = &token_session_index_map[slot];
  int *link = &entry->head_index;
  while (*link >= 0) {
    WambleClientSession *session = &client_sessions[*link];
    if (*link == index) {
      *link = session->token_next_index;
      session->token_next_index = -1;
      return;
    }
    link = &session->token_next_index;
  }
}

static int token_session_map_head(const uint8_t *token) {
  int slot = token_session_map_slot(token, 0);
  if (slot < 0)
    return -1;
  return token_session_index_map[slot].head_index;
}

static void token_session_map_rebuild(void) {
  token_session_map_init();
  if (!client_sessions)
    return;
  for (int i = 0; i < num_sessions; i++)
    client_sessions[i].token_next_index = -1;
  for (int i = 0; i < num_sessions; i++) {
    if (token_has_any_byte(client_sessions[i].token))
      token_session_map_put(client_sessions[i].token, i);
  }
}

static WAMBLE_THREAD_LOCAL TransportEndpointState *transport_endpoints = NULL;
static WAMBLE_THREAD_LOCAL size_t transport_endpoint_size = 0;
static WAMBLE_THREAD_LOCAL size_t transport_endpoint_capacity = 0;
static WAMBLE_THREAD_LOCAL TransportEndpointId transport_next_endpoint_id = 1;
static WAMBLE_THREAD_LOCAL int defer_reliable_ack_wait = 0;
static WAMBLE_THREAD_LOCAL TransportInboundEntry *transport_inbound_entries =
    NULL;
static WAMBLE_THREAD_LOCAL size_t transport_inbound_capacity = 0;
static WAMBLE_THREAD_LOCAL size_t transport_inbound_head = 0;
static WAMBLE_THREAD_LOCAL size_t transport_inbound_size = 0;
static WAMBLE_THREAD_LOCAL TransportDispatchEntry *transport_dispatch_entries =
    NULL;
static WAMBLE_THREAD_LOCAL size_t transport_dispatch_capacity = 0;
static WAMBLE_THREAD_LOCAL size_t transport_dispatch_head = 0;
static WAMBLE_THREAD_LOCAL size_t transport_dispatch_size = 0;
static WAMBLE_THREAD_LOCAL TransportOutboundEntry *transport_outbound_entries =
    NULL;
static WAMBLE_THREAD_LOCAL size_t transport_outbound_size = 0;
static WAMBLE_THREAD_LOCAL size_t transport_outbound_capacity = 0;
static WAMBLE_THREAD_LOCAL ReliableBundle *transport_reliable_bundles = NULL;
static WAMBLE_THREAD_LOCAL size_t transport_reliable_bundle_size = 0;
static WAMBLE_THREAD_LOCAL size_t transport_reliable_bundle_capacity = 0;
static WAMBLE_THREAD_LOCAL uint64_t transport_next_reliable_bundle_id = 1;
static WAMBLE_THREAD_LOCAL uint64_t runtime_next_deadline_at_ms = 0;
static WAMBLE_THREAD_LOCAL uint64_t runtime_retry_after_ms = 0;

static void network_runtime_reset_drive_schedule(void) {
  runtime_next_deadline_at_ms = 0;
  runtime_retry_after_ms = 0;
}

static void transport_endpoint_init(TransportEndpointState *endpoint,
                                    const struct sockaddr_in *addr,
                                    const uint8_t *token) {
  memset(endpoint, 0, sizeof(*endpoint));
  endpoint->endpoint_id = transport_next_endpoint_id++;
  if (endpoint->endpoint_id == TRANSPORT_ENDPOINT_ID_INVALID)
    endpoint->endpoint_id = transport_next_endpoint_id++;
  if (addr)
    endpoint->addr = *addr;
  if (token)
    memcpy(endpoint->token, token, TOKEN_LENGTH);
  endpoint->next_reliable_seq = 1;
  endpoint->rto_ms = WAMBLE_TRANSPORT_INITIAL_RTO_MS;
}

static void transport_runtime_release(void) {
  for (size_t i = 0; i < transport_outbound_size; i++)
    free(transport_outbound_entries[i].payload);
  for (size_t i = 0; i < transport_reliable_bundle_size; i++)
    free(transport_reliable_bundles[i].payload);
  free(transport_endpoints);
  free(transport_inbound_entries);
  free(transport_dispatch_entries);
  free(transport_outbound_entries);
  free(transport_reliable_bundles);
  transport_endpoints = NULL;
  transport_endpoint_size = 0;
  transport_endpoint_capacity = 0;
  transport_next_endpoint_id = 1;
  transport_inbound_entries = NULL;
  transport_inbound_capacity = 0;
  transport_inbound_head = 0;
  transport_inbound_size = 0;
  transport_dispatch_entries = NULL;
  transport_dispatch_capacity = 0;
  transport_dispatch_head = 0;
  transport_dispatch_size = 0;
  transport_outbound_entries = NULL;
  transport_outbound_size = 0;
  transport_outbound_capacity = 0;
  transport_reliable_bundles = NULL;
  transport_reliable_bundle_size = 0;
  transport_reliable_bundle_capacity = 0;
  transport_next_reliable_bundle_id = 1;
  network_runtime_reset_drive_schedule();
}

static uint64_t transport_allocate_bundle_id(void) {
  uint64_t id = transport_next_reliable_bundle_id++;
  if (id == 0) {
    transport_next_reliable_bundle_id = 2;
    id = 1;
  }
  return id;
}

static ssize_t transport_reliable_bundle_find(uint64_t bundle_id) {
  for (size_t i = 0; i < transport_reliable_bundle_size; i++) {
    if (transport_reliable_bundles[i].bundle_id == bundle_id)
      return (ssize_t)i;
  }
  return -1;
}

static void transport_reliable_bundle_remove(size_t index) {
  if (!transport_reliable_bundles || index >= transport_reliable_bundle_size)
    return;
  free(transport_reliable_bundles[index].payload);
  for (size_t i = index + 1; i < transport_reliable_bundle_size; i++)
    transport_reliable_bundles[i - 1] = transport_reliable_bundles[i];
  transport_reliable_bundle_size--;
  if (transport_reliable_bundle_size == 0) {
    free(transport_reliable_bundles);
    transport_reliable_bundles = NULL;
    transport_reliable_bundle_capacity = 0;
  }
}

static int transport_size_ensure(void **items, size_t item_size,
                                 size_t *capacity, size_t need) {
  if (*capacity >= need && *items)
    return 0;
  size_t new_cap =
      *capacity > 0 ? *capacity : (size_t)WAMBLE_TRANSPORT_INITIAL_CAP;
  while (new_cap < need) {
    if (new_cap > SIZE_MAX / 2)
      return -1;
    new_cap *= 2;
  }
  void *grown = realloc(*items, new_cap * item_size);
  if (!grown)
    return -1;
  memset((uint8_t *)grown + (*capacity * item_size), 0,
         (new_cap - *capacity) * item_size);
  *items = grown;
  *capacity = new_cap;
  return 0;
}

static int transport_inbound_ensure_capacity(size_t need) {
  if (transport_inbound_capacity >= need && transport_inbound_entries)
    return 0;
  size_t old_cap = transport_inbound_capacity;
  size_t new_cap = old_cap > 0 ? old_cap : (size_t)WAMBLE_TRANSPORT_INITIAL_CAP;
  while (new_cap < need) {
    if (new_cap > SIZE_MAX / 2)
      return -1;
    new_cap *= 2;
  }
  TransportInboundEntry *grown =
      (TransportInboundEntry *)calloc(new_cap, sizeof(*grown));
  if (!grown)
    return -1;
  for (size_t i = 0; i < transport_inbound_size; i++) {
    size_t src = old_cap ? (transport_inbound_head + i) % old_cap : 0;
    grown[i] = transport_inbound_entries[src];
  }
  free(transport_inbound_entries);
  transport_inbound_entries = grown;
  transport_inbound_capacity = new_cap;
  transport_inbound_head = 0;
  return 0;
}

static int transport_dispatch_ensure_capacity(size_t need) {
  if (transport_dispatch_capacity >= need && transport_dispatch_entries)
    return 0;
  size_t old_cap = transport_dispatch_capacity;
  size_t new_cap = old_cap > 0 ? old_cap : (size_t)WAMBLE_TRANSPORT_INITIAL_CAP;
  while (new_cap < need) {
    if (new_cap > SIZE_MAX / 2)
      return -1;
    new_cap *= 2;
  }
  TransportDispatchEntry *grown =
      (TransportDispatchEntry *)calloc(new_cap, sizeof(*grown));
  if (!grown)
    return -1;
  for (size_t i = 0; i < transport_dispatch_size; i++) {
    size_t src = old_cap ? (transport_dispatch_head + i) % old_cap : 0;
    grown[i] = transport_dispatch_entries[src];
  }
  free(transport_dispatch_entries);
  transport_dispatch_entries = grown;
  transport_dispatch_capacity = new_cap;
  transport_dispatch_head = 0;
  return 0;
}

int transport_inbound_push(const TransportInboundEntry *entry) {
  if (!entry || entry->packet_len == 0 ||
      entry->packet_len > WAMBLE_MAX_PACKET_SIZE)
    return -1;
  if (transport_inbound_ensure_capacity(transport_inbound_size + 1) != 0)
    return -1;
  size_t slot = (transport_inbound_head + transport_inbound_size) %
                transport_inbound_capacity;
  transport_inbound_entries[slot] = *entry;
  transport_inbound_size++;
  return 0;
}

int transport_inbound_pop(TransportInboundEntry *out) {
  if (!out || transport_inbound_size == 0)
    return 0;
  *out = transport_inbound_entries[transport_inbound_head];
  memset(&transport_inbound_entries[transport_inbound_head], 0,
         sizeof(transport_inbound_entries[transport_inbound_head]));
  transport_inbound_head =
      (transport_inbound_head + 1) % transport_inbound_capacity;
  transport_inbound_size--;
  if (transport_inbound_size == 0)
    transport_inbound_head = 0;
  return 1;
}

size_t transport_inbound_count(void) { return transport_inbound_size; }

int transport_dispatch_push(const TransportDispatchEntry *entry) {
  if (!entry)
    return -1;
  if (transport_dispatch_ensure_capacity(transport_dispatch_size + 1) != 0)
    return -1;
  size_t slot = (transport_dispatch_head + transport_dispatch_size) %
                transport_dispatch_capacity;
  transport_dispatch_entries[slot] = *entry;
  transport_dispatch_size++;
  return 0;
}

int transport_dispatch_pop(TransportDispatchEntry *out) {
  if (!out || transport_dispatch_size == 0)
    return 0;
  *out = transport_dispatch_entries[transport_dispatch_head];
  memset(&transport_dispatch_entries[transport_dispatch_head], 0,
         sizeof(transport_dispatch_entries[transport_dispatch_head]));
  transport_dispatch_head =
      (transport_dispatch_head + 1) % transport_dispatch_capacity;
  transport_dispatch_size--;
  if (transport_dispatch_size == 0)
    transport_dispatch_head = 0;
  return 1;
}

size_t transport_dispatch_count(void) { return transport_dispatch_size; }

static int transport_endpoint_ensure_capacity(size_t need) {
  return transport_size_ensure((void **)&transport_endpoints,
                               sizeof(*transport_endpoints),
                               &transport_endpoint_capacity, need);
}

static int transport_outbound_ensure_capacity(size_t need) {
  return transport_size_ensure((void **)&transport_outbound_entries,
                               sizeof(*transport_outbound_entries),
                               &transport_outbound_capacity, need);
}

static int transport_endpoint_find_by_token(const uint8_t *token) {
  if (!token || !token_has_any_byte(token))
    return -1;
  for (size_t i = 0; i < transport_endpoint_size; i++) {
    if (memcmp(transport_endpoints[i].token, token, TOKEN_LENGTH) == 0)
      return (int)i;
  }
  return -1;
}

static int transport_endpoint_find_by_addr(const struct sockaddr_in *addr) {
  if (!addr)
    return -1;
  for (size_t i = 0; i < transport_endpoint_size; i++) {
    if (sockaddr_in_equal(&transport_endpoints[i].addr, addr))
      return (int)i;
  }
  return -1;
}

static int transport_endpoint_find_by_id(TransportEndpointId endpoint_id) {
  if (endpoint_id == TRANSPORT_ENDPOINT_ID_INVALID)
    return -1;
  for (size_t i = 0; i < transport_endpoint_size; i++) {
    if (transport_endpoints[i].endpoint_id == endpoint_id)
      return (int)i;
  }
  return -1;
}

static int
transport_endpoint_has_outbound_references(TransportEndpointId endpoint_id) {
  if (endpoint_id == TRANSPORT_ENDPOINT_ID_INVALID)
    return 0;
  for (size_t i = 0; i < transport_outbound_size; i++) {
    if (transport_outbound_entries[i].endpoint_id == endpoint_id)
      return 1;
  }
  return 0;
}

static void transport_endpoint_remove_at(size_t index) {
  if (!transport_endpoints || index >= transport_endpoint_size)
    return;
  for (size_t i = index + 1; i < transport_endpoint_size; i++)
    transport_endpoints[i - 1] = transport_endpoints[i];
  transport_endpoint_size--;
  if (transport_endpoint_size == 0) {
    free(transport_endpoints);
    transport_endpoints = NULL;
    transport_endpoint_capacity = 0;
  } else {
    memset(&transport_endpoints[transport_endpoint_size], 0,
           sizeof(transport_endpoints[transport_endpoint_size]));
  }
}

static int transport_endpoint_count_by_token(const uint8_t *token) {
  if (!token || !token_has_any_byte(token))
    return 0;
  int count = 0;
  for (size_t i = 0; i < transport_endpoint_size; i++) {
    if (memcmp(transport_endpoints[i].token, token, TOKEN_LENGTH) == 0)
      count++;
  }
  return count;
}

static int transport_endpoint_bind_index(const struct sockaddr_in *addr,
                                         const uint8_t *token) {
  if (!addr)
    return -1;
  int idx = transport_endpoint_find_by_addr(addr);
  if (idx >= 0) {
    TransportEndpointState *endpoint = &transport_endpoints[idx];
    endpoint->addr = *addr;
    if (token && token_has_any_byte(token))
      memcpy(endpoint->token, token, TOKEN_LENGTH);
    if (endpoint->rto_ms == 0)
      endpoint->rto_ms = WAMBLE_TRANSPORT_INITIAL_RTO_MS;
    return idx;
  }
  if (transport_endpoint_ensure_capacity(transport_endpoint_size + 1) != 0)
    return -1;
  idx = (int)transport_endpoint_size++;
  transport_endpoint_init(&transport_endpoints[idx], addr, token);
  return idx;
}

int transport_endpoint_bind_addr_token(const struct sockaddr_in *addr,
                                       const uint8_t token[TOKEN_LENGTH],
                                       TransportEndpointId *out_endpoint_id) {
  int idx = transport_endpoint_bind_index(addr, token);
  if (idx < 0)
    return -1;
  if (out_endpoint_id)
    *out_endpoint_id = transport_endpoints[idx].endpoint_id;
  return 0;
}

int transport_endpoint_rebind_id(TransportEndpointId endpoint_id,
                                 const struct sockaddr_in *addr) {
  if (!addr)
    return -1;
  int idx = transport_endpoint_find_by_id(endpoint_id);
  if (idx < 0)
    return -1;
  int addr_idx = transport_endpoint_find_by_addr(addr);
  if (addr_idx >= 0 && addr_idx != idx) {
    TransportEndpointState *addr_endpoint = &transport_endpoints[addr_idx];
    if (token_has_any_byte(addr_endpoint->token) ||
        transport_endpoint_has_outbound_references(addr_endpoint->endpoint_id))
      return -1;
    transport_endpoint_remove_at((size_t)addr_idx);
    idx = transport_endpoint_find_by_id(endpoint_id);
    if (idx < 0)
      return -1;
  }
  transport_endpoints[idx].addr = *addr;
  if (transport_endpoints[idx].rto_ms == 0)
    transport_endpoints[idx].rto_ms = WAMBLE_TRANSPORT_INITIAL_RTO_MS;
  return 0;
}

int transport_endpoint_resolve_addr(TransportEndpointId endpoint_id,
                                    struct sockaddr_in *out) {
  if (!out)
    return -1;
  int idx = transport_endpoint_find_by_id(endpoint_id);
  if (idx < 0)
    return -1;
  *out = transport_endpoints[idx].addr;
  return 0;
}

static int
transport_endpoint_rebind_by_addr(const struct sockaddr_in *old_addr,
                                  const uint8_t token[TOKEN_LENGTH],
                                  const struct sockaddr_in *new_addr) {
  if (!old_addr || !new_addr)
    return -1;
  int idx = transport_endpoint_find_by_addr(old_addr);
  if (idx < 0)
    return transport_endpoint_bind_addr_token(new_addr, token, NULL);
  transport_endpoints[idx].addr = *new_addr;
  if (token && token_has_any_byte(token))
    memcpy(transport_endpoints[idx].token, token, TOKEN_LENGTH);
  if (transport_endpoints[idx].rto_ms == 0)
    transport_endpoints[idx].rto_ms = WAMBLE_TRANSPORT_INITIAL_RTO_MS;
  return 0;
}

uint32_t transport_endpoint_rto_ms_by_id(TransportEndpointId endpoint_id) {
  int idx = transport_endpoint_find_by_id(endpoint_id);
  if (idx < 0 || transport_endpoints[idx].rto_ms == 0)
    return WAMBLE_TRANSPORT_INITIAL_RTO_MS;
  return transport_endpoints[idx].rto_ms;
}

int transport_endpoint_update_rto_by_id(TransportEndpointId endpoint_id,
                                        uint32_t sample_ms, int retransmitted) {
  int idx = transport_endpoint_find_by_id(endpoint_id);
  if (idx < 0)
    return -1;
  return transport_endpoint_update_rto_by_index((size_t)idx, sample_ms,
                                                retransmitted);
}

static int transport_endpoint_update_rto_by_index(size_t idx,
                                                  uint32_t sample_ms,
                                                  int retransmitted) {
  if (idx >= transport_endpoint_size)
    return -1;
  if (retransmitted)
    return 0;
  if (sample_ms == 0)
    sample_ms = 1;
  TransportEndpointState *endpoint = &transport_endpoints[idx];
  if (endpoint->srtt_ms == 0) {
    endpoint->srtt_ms = sample_ms;
    endpoint->rttvar_ms = sample_ms / 2u;
  } else {
    uint32_t srtt = endpoint->srtt_ms;
    uint32_t delta = srtt > sample_ms ? srtt - sample_ms : sample_ms - srtt;
    endpoint->rttvar_ms = (3u * endpoint->rttvar_ms + delta) / 4u;
    endpoint->srtt_ms = (7u * endpoint->srtt_ms + sample_ms) / 8u;
  }
  uint64_t rto_ms = (uint64_t)endpoint->srtt_ms + 4u * endpoint->rttvar_ms;
  if (rto_ms > UINT32_MAX)
    rto_ms = UINT32_MAX;
  endpoint->rto_ms = transport_clamp_rto_ms((uint32_t)rto_ms);
  endpoint->last_rtt_sample_ms = wamble_now_mono_millis();
  return 0;
}

static TransportOutboundLane
transport_lane_for_variant(TransportOutboundVariant variant) {
  switch (variant) {
  case TRANSPORT_OUTBOUND_REQUEST_ACK:
    return TRANSPORT_OUTBOUND_LANE_REQUEST_ACK;
  case TRANSPORT_OUTBOUND_RELIABLE_TERMINAL:
    return TRANSPORT_OUTBOUND_LANE_RELIABLE_TERMINAL;
  case TRANSPORT_OUTBOUND_RELIABLE_BUNDLE_FRAGMENT:
    return TRANSPORT_OUTBOUND_LANE_RELIABLE_BUNDLE;
  case TRANSPORT_OUTBOUND_UNRELIABLE:
  default:
    return TRANSPORT_OUTBOUND_LANE_UNRELIABLE;
  }
}

int transport_outbound_push(const TransportOutboundEntry *entry) {
  if (!entry)
    return -1;
  if (entry->payload_len > 0 && !entry->payload)
    return -1;
  if (entry->payload_len > WAMBLE_MAX_PACKET_SIZE)
    return -1;
  int endpoint =
      entry->endpoint_id != TRANSPORT_ENDPOINT_ID_INVALID
          ? transport_endpoint_find_by_id(entry->endpoint_id)
          : transport_endpoint_bind_index(&entry->addr, entry->token);
  if (endpoint < 0)
    return -1;
  if (transport_outbound_ensure_capacity(transport_outbound_size + 1) != 0)
    return -1;

  TransportOutboundEntry copy = *entry;
  copy.endpoint_id = transport_endpoints[endpoint].endpoint_id;
  if (copy.lane == TRANSPORT_OUTBOUND_LANE_UNSPECIFIED)
    copy.lane = transport_lane_for_variant(copy.variant);
  copy.payload = NULL;
  copy.payload_len = 0;
  if (entry->payload_len > 0) {
    copy.payload = (uint8_t *)malloc(entry->payload_len);
    if (!copy.payload)
      return -1;
    memcpy(copy.payload, entry->payload, entry->payload_len);
    copy.payload_len = entry->payload_len;
  }
  size_t index = transport_outbound_size++;
  transport_outbound_entries[index] = copy;
  return 0;
}

void transport_outbound_remove(size_t index) {
  if (!transport_outbound_entries || index >= transport_outbound_size)
    return;
  free(transport_outbound_entries[index].payload);
  for (size_t i = index + 1; i < transport_outbound_size; i++)
    transport_outbound_entries[i - 1] = transport_outbound_entries[i];
  transport_outbound_size--;
  if (transport_outbound_size == 0) {
    free(transport_outbound_entries);
    transport_outbound_entries = NULL;
    transport_outbound_capacity = 0;
  } else {
    memset(&transport_outbound_entries[transport_outbound_size], 0,
           sizeof(transport_outbound_entries[transport_outbound_size]));
  }
}

size_t transport_outbound_count(void) { return transport_outbound_size; }

static int network_set_deferred_reliable_ack_wait(int enabled) {
  int previous = defer_reliable_ack_wait;
  defer_reliable_ack_wait = enabled ? 1 : 0;
  return previous;
}

static uint64_t transport_min_nonzero_u64(uint64_t a, uint64_t b) {
  if (a == 0)
    return b;
  if (b == 0)
    return a;
  return a < b ? a : b;
}

static uint32_t transport_rto_cap_ms(void) {
  int cap = get_config()->rto_cap_ms;
  return cap > 0 ? (uint32_t)cap : 8000u;
}

static uint32_t transport_clamp_rto_ms(uint32_t rto_ms) {
  uint32_t cap = transport_rto_cap_ms();
  if (rto_ms == 0)
    rto_ms = WAMBLE_TRANSPORT_INITIAL_RTO_MS;
  if (rto_ms > cap)
    rto_ms = cap;
  return rto_ms;
}

static uint64_t
transport_outbound_entry_deadline(const TransportOutboundEntry *entry) {
  if (!entry)
    return 0;
  switch (entry->variant) {
  case TRANSPORT_OUTBOUND_RELIABLE_TERMINAL:
    return entry->as.reliable.deadline_at_ms;
  case TRANSPORT_OUTBOUND_RELIABLE_BUNDLE_FRAGMENT:
    return entry->as.reliable_fragment.deadline_at_ms;
  case TRANSPORT_OUTBOUND_REQUEST_ACK:
    return entry->as.ack.deadline_at_ms;
  case TRANSPORT_OUTBOUND_UNRELIABLE:
  default:
    return 0;
  }
}

static uint16_t
transport_outbound_entry_retry_count(const TransportOutboundEntry *entry) {
  if (!entry)
    return 0;
  if (entry->variant == TRANSPORT_OUTBOUND_RELIABLE_TERMINAL)
    return entry->as.reliable.retry_count;
  if (entry->variant == TRANSPORT_OUTBOUND_RELIABLE_BUNDLE_FRAGMENT)
    return entry->as.reliable_fragment.retry_count;
  return 0;
}

static uint16_t
transport_outbound_entry_max_retries(const TransportOutboundEntry *entry) {
  if (!entry)
    return 0;
  if (entry->variant == TRANSPORT_OUTBOUND_RELIABLE_TERMINAL)
    return entry->as.reliable.max_retries;
  if (entry->variant == TRANSPORT_OUTBOUND_RELIABLE_BUNDLE_FRAGMENT)
    return entry->as.reliable_fragment.max_retries;
  return 0;
}

static void transport_outbound_entry_arm_retry(TransportOutboundEntry *entry,
                                               uint64_t now_ms,
                                               uint32_t rto_ms) {
  if (!entry)
    return;
  rto_ms = transport_clamp_rto_ms(rto_ms);
  if (entry->variant == TRANSPORT_OUTBOUND_RELIABLE_TERMINAL) {
    entry->as.reliable.sent_at_ms = now_ms;
    entry->as.reliable.rto_ms = rto_ms;
    entry->as.reliable.deadline_at_ms = now_ms + rto_ms;
    entry->as.reliable.retry_count++;
  } else if (entry->variant == TRANSPORT_OUTBOUND_RELIABLE_BUNDLE_FRAGMENT) {
    entry->as.reliable_fragment.sent_at_ms = now_ms;
    entry->as.reliable_fragment.rto_ms = rto_ms;
    entry->as.reliable_fragment.deadline_at_ms = now_ms + rto_ms;
    entry->as.reliable_fragment.retry_count++;
  }
}

static TransportDriveResult
transport_drive_result_make(TransportDriveStatus status, size_t inbound_pending,
                            size_t dispatch_pending, size_t outbound_pending,
                            uint32_t progress_count, uint32_t error_count,
                            uint64_t next_deadline_at_ms,
                            uint64_t retry_after_ms) {
  TransportDriveResult result;
  memset(&result, 0, sizeof(result));
  result.status = status;
  result.inbound_pending = inbound_pending;
  result.dispatch_pending = dispatch_pending;
  result.outbound_pending = outbound_pending;
  result.progress_count = progress_count;
  result.error_count = error_count;
  result.next_deadline_at_ms = next_deadline_at_ms;
  result.retry_after_ms = retry_after_ms;
  if (status == TRANSPORT_DRIVE_IDLE &&
      (inbound_pending || dispatch_pending || outbound_pending))
    result.status = TRANSPORT_DRIVE_PENDING;
  return result;
}

TransportDriveResult transport_drive_result_idle(void) {
  return transport_drive_result_make(TRANSPORT_DRIVE_IDLE, 0, 0, 0, 0, 0, 0, 0);
}

TransportDriveResult
transport_drive_result_pending(size_t inbound_pending, size_t dispatch_pending,
                               size_t outbound_pending,
                               uint64_t next_deadline_at_ms) {
  return transport_drive_result_make(TRANSPORT_DRIVE_PENDING, inbound_pending,
                                     dispatch_pending, outbound_pending, 0, 0,
                                     next_deadline_at_ms, 0);
}

TransportDriveResult transport_drive_result_progress(uint32_t progress_count) {
  return transport_drive_result_make(TRANSPORT_DRIVE_PROGRESS, 0, 0, 0,
                                     progress_count, 0, 0, 0);
}

TransportDriveResult transport_drive_result_backoff(size_t inbound_pending,
                                                    size_t dispatch_pending,
                                                    size_t outbound_pending,
                                                    uint64_t retry_after_ms) {
  return transport_drive_result_make(TRANSPORT_DRIVE_BACKOFF, inbound_pending,
                                     dispatch_pending, outbound_pending, 0, 0,
                                     0, retry_after_ms);
}

TransportDriveResult transport_drive_result_error(size_t inbound_pending,
                                                  size_t dispatch_pending,
                                                  size_t outbound_pending,
                                                  uint32_t error_count,
                                                  uint64_t retry_after_ms) {
  return transport_drive_result_make(TRANSPORT_DRIVE_ERROR, inbound_pending,
                                     dispatch_pending, outbound_pending, 0,
                                     error_count, 0, retry_after_ms);
}

TransportDriveResult transport_drive_result_merge(TransportDriveResult a,
                                                  TransportDriveResult b) {
  TransportDriveResult result;
  memset(&result, 0, sizeof(result));
  result.inbound_pending = a.inbound_pending + b.inbound_pending;
  result.dispatch_pending = a.dispatch_pending + b.dispatch_pending;
  result.outbound_pending = a.outbound_pending + b.outbound_pending;
  result.progress_count = a.progress_count + b.progress_count;
  result.error_count = a.error_count + b.error_count;
  result.next_deadline_at_ms =
      transport_min_nonzero_u64(a.next_deadline_at_ms, b.next_deadline_at_ms);
  result.retry_after_ms =
      transport_min_nonzero_u64(a.retry_after_ms, b.retry_after_ms);

  if (a.status == TRANSPORT_DRIVE_ERROR || b.status == TRANSPORT_DRIVE_ERROR) {
    result.status = TRANSPORT_DRIVE_ERROR;
  } else if (a.status == TRANSPORT_DRIVE_BACKOFF ||
             b.status == TRANSPORT_DRIVE_BACKOFF) {
    result.status = TRANSPORT_DRIVE_BACKOFF;
  } else if (result.error_count > 0) {
    result.status = TRANSPORT_DRIVE_ERROR;
  } else if (a.status == TRANSPORT_DRIVE_PROGRESS ||
             b.status == TRANSPORT_DRIVE_PROGRESS ||
             result.progress_count > 0) {
    result.status = TRANSPORT_DRIVE_PROGRESS;
  } else if (a.status == TRANSPORT_DRIVE_PENDING ||
             b.status == TRANSPORT_DRIVE_PENDING || result.inbound_pending ||
             result.dispatch_pending || result.outbound_pending) {
    result.status = TRANSPORT_DRIVE_PENDING;
  } else {
    result.status = TRANSPORT_DRIVE_IDLE;
  }
  return result;
}

static int ctrl_is_supported(uint8_t ctrl) {
  switch (ctrl) {
  case WAMBLE_CTRL_CLIENT_HELLO:
  case WAMBLE_CTRL_SERVER_HELLO:
  case WAMBLE_CTRL_PLAYER_MOVE:
  case WAMBLE_CTRL_BOARD_UPDATE:
  case WAMBLE_CTRL_ACK:
  case WAMBLE_CTRL_LIST_PROFILES:
  case WAMBLE_CTRL_GET_PREDICTIONS:
  case WAMBLE_CTRL_SUBMIT_PREDICTION:
  case WAMBLE_CTRL_PREDICTION_DATA:
  case WAMBLE_CTRL_PROFILE_INFO:
  case WAMBLE_CTRL_GET_PROFILE_INFO:
  case WAMBLE_CTRL_PROFILES_LIST:
  case WAMBLE_CTRL_ERROR:
  case WAMBLE_CTRL_SERVER_NOTIFICATION:
  case WAMBLE_CTRL_CLIENT_GOODBYE:
  case WAMBLE_CTRL_SPECTATE_GAME:
  case WAMBLE_CTRL_SPECTATE_STOP:
  case WAMBLE_CTRL_SPECTATE_UPDATE:
  case WAMBLE_CTRL_LOGIN_REQUEST:
  case WAMBLE_CTRL_LOGOUT:
  case WAMBLE_CTRL_LOGIN_SUCCESS:
  case WAMBLE_CTRL_LOGIN_FAILED:
  case WAMBLE_CTRL_LOGIN_CHALLENGE:
  case WAMBLE_CTRL_GET_PLAYER_STATS:
  case WAMBLE_CTRL_PLAYER_STATS_DATA:
  case WAMBLE_CTRL_GET_LEGAL_MOVES:
  case WAMBLE_CTRL_LEGAL_MOVES:
  case WAMBLE_CTRL_GET_LEADERBOARD:
  case WAMBLE_CTRL_LEADERBOARD_DATA:
  case WAMBLE_CTRL_GET_PROFILE_TOS:
  case WAMBLE_CTRL_PROFILE_TOS_DATA:
  case WAMBLE_CTRL_ACCEPT_PROFILE_TOS:
  case WAMBLE_CTRL_GET_ACTIVE_RESERVATIONS:
  case WAMBLE_CTRL_ACTIVE_RESERVATIONS_DATA:
    return 1;
  default:
    return 0;
  }
}

static int ctrl_is_client_request(uint8_t ctrl) {
  switch (ctrl) {
  case WAMBLE_CTRL_CLIENT_HELLO:
  case WAMBLE_CTRL_PLAYER_MOVE:
  case WAMBLE_CTRL_LIST_PROFILES:
  case WAMBLE_CTRL_GET_PROFILE_INFO:
  case WAMBLE_CTRL_GET_PROFILE_TOS:
  case WAMBLE_CTRL_ACCEPT_PROFILE_TOS:
  case WAMBLE_CTRL_GET_ACTIVE_RESERVATIONS:
  case WAMBLE_CTRL_LOGIN_REQUEST:
  case WAMBLE_CTRL_LOGOUT:
  case WAMBLE_CTRL_CLIENT_GOODBYE:
  case WAMBLE_CTRL_SPECTATE_GAME:
  case WAMBLE_CTRL_SPECTATE_STOP:
  case WAMBLE_CTRL_GET_PLAYER_STATS:
  case WAMBLE_CTRL_GET_LEGAL_MOVES:
  case WAMBLE_CTRL_GET_LEADERBOARD:
  case WAMBLE_CTRL_GET_PREDICTIONS:
  case WAMBLE_CTRL_SUBMIT_PREDICTION:
    return 1;
  default:
    return 0;
  }
}

static int token_has_any_byte(const uint8_t *token) {
  if (!token)
    return 0;
  for (int i = 0; i < TOKEN_LENGTH; i++) {
    if (token[i] != 0)
      return 1;
  }
  return 0;
}

static int ctrl_allows_anonymous_token(uint8_t ctrl) {
  switch (ctrl) {
  case WAMBLE_CTRL_CLIENT_HELLO:
  case WAMBLE_CTRL_ACK:
  case WAMBLE_CTRL_LIST_PROFILES:
  case WAMBLE_CTRL_GET_PROFILE_INFO:
    return 1;
  default:
    return 0;
  }
}

static uint32_t next_fragment_transfer_id(void) {
  uint32_t id = global_fragment_transfer_id++;
  if (id == 0) {
    global_fragment_transfer_id = 2;
    id = 1;
  }
  return id;
}

static NetworkStatus
build_message_payload_dynamic(const struct WambleMsg *msg,
                              uint8_t **out_payload, size_t *out_payload_len,
                              uint8_t *out_transport_flags) {
  if (!msg || !out_payload || !out_payload_len)
    return NET_ERR_INVALID;
  *out_payload = NULL;
  *out_payload_len = 0;
  if (out_transport_flags)
    *out_transport_flags = 0;

  size_t cap = WAMBLE_MAX_PAYLOAD;
  const size_t max_cap = 1024u * 1024u;
  while (cap <= max_cap) {
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf)
      return NET_ERR_IO;
    size_t len = 0;
    uint8_t transport_flags = 0;
    NetworkStatus st =
        wamble_payload_serialize(msg, buf, cap, &len, &transport_flags);
    if (st == NET_OK) {
      *out_payload = buf;
      *out_payload_len = len;
      if (out_transport_flags)
        *out_transport_flags = transport_flags;
      return NET_OK;
    }
    free(buf);
    if (st != NET_ERR_TRUNCATED)
      return st;
    if (cap == max_cap)
      break;
    size_t next = cap * 2u;
    if (next < cap)
      break;
    cap = (next > max_cap) ? max_cap : next;
  }
  return NET_ERR_TRUNCATED;
}

static void network_ensure_thread_state_initialized(void) {
  if (!client_sessions || !session_index_map || !token_session_index_map)
    (void)ensure_client_session_capacity(1);
}

static WambleClientSession *
find_client_session(const struct sockaddr_in *addr) {
  network_ensure_thread_state_initialized();
  if (!client_sessions)
    return NULL;
  int idx = session_map_get(addr);
  if (idx >= 0)
    return &client_sessions[idx];
  return NULL;
}

static WambleClientSession *find_client_session_by_token(const uint8_t *token) {
  network_ensure_thread_state_initialized();
  if (!client_sessions || !token_has_any_byte(token))
    return NULL;
  int head = token_session_map_head(token);
  WambleClientSession *best = NULL;
  for (int i = head, probes = 0;
       i >= 0 && i < num_sessions && probes < num_sessions; probes++) {
    WambleClientSession *session = &client_sessions[i];
    int next = session->token_next_index;
    if (memcmp(session->token, token, TOKEN_LENGTH) == 0 &&
        (!best || session->last_seen > best->last_seen ||
         (session->last_seen == best->last_seen && session < best))) {
      best = session;
    }
    i = next;
  }
  return best;
}

static WambleClientSession *
create_client_session(const struct sockaddr_in *addr, const uint8_t *token) {
  if (ensure_client_session_capacity(num_sessions + 1) != 0)
    return NULL;
  if (num_sessions >= client_sessions_capacity) {
    return NULL;
  }

  WambleClientSession *session = &client_sessions[num_sessions++];
  session->addr = *addr;
  memcpy(session->token, token, TOKEN_LENGTH);
  session->token_next_index = -1;
  session->last_seq_num = 0;
  session->last_seen = wamble_now_wall();
  session->next_seq_num = 1;
  session->treatment_group_key[0] = '\0';
  session->terminal_cache = NULL;
  session->terminal_cache_count = 0;
  session_map_put(addr, (int)(session - client_sessions));
  if (token_has_any_byte(token))
    token_session_map_put(token, (int)(session - client_sessions));
  return session;
}

static int ensure_client_session_capacity(int needed) {
  int required_map_capacity =
      map_capacity_for_session_capacity(client_sessions_capacity);
  if (needed <= client_sessions_capacity && client_sessions &&
      session_index_map && token_session_index_map &&
      session_index_map_capacity >= required_map_capacity &&
      token_session_index_map_capacity >= required_map_capacity)
    return 0;
  int old_capacity = client_sessions_capacity;
  int new_capacity = old_capacity > 0 ? old_capacity : 1;
  while (new_capacity < needed) {
    if (new_capacity > INT_MAX / 2)
      return -1;
    new_capacity *= 2;
  }
  int map_capacity = map_capacity_for_session_capacity(new_capacity);
  if (map_capacity <= 0)
    return -1;

  int current_request_index = -1;
  if (g_current_request.session && client_sessions) {
    current_request_index = (int)(g_current_request.session - client_sessions);
    if (current_request_index < 0 || current_request_index >= num_sessions)
      current_request_index = -1;
  }

  int *new_session_map =
      (int *)malloc((size_t)map_capacity * sizeof(*new_session_map));
  if (!new_session_map)
    return -1;
  TokenSessionMapEntry *new_token_map = (TokenSessionMapEntry *)malloc(
      (size_t)map_capacity * sizeof(*new_token_map));
  if (!new_token_map) {
    free(new_session_map);
    return -1;
  }

  WambleClientSession *grown_sessions = (WambleClientSession *)realloc(
      client_sessions, (size_t)new_capacity * sizeof(*client_sessions));
  if (!grown_sessions) {
    free(new_session_map);
    free(new_token_map);
    return -1;
  }
  if (new_capacity > old_capacity) {
    memset(grown_sessions + old_capacity, 0,
           (size_t)(new_capacity - old_capacity) * sizeof(*grown_sessions));
  }
  client_sessions = grown_sessions;
  client_sessions_capacity = new_capacity;

  free(session_index_map);
  session_index_map = new_session_map;
  session_index_map_capacity = map_capacity;

  free(token_session_index_map);
  token_session_index_map = new_token_map;
  token_session_index_map_capacity = map_capacity;

  if (current_request_index >= 0)
    g_current_request.session = &client_sessions[current_request_index];
  session_map_rebuild();
  token_session_map_rebuild();
  return 0;
}

static void terminal_cache_slot_clear_packets(WambleTerminalCacheSlot *slot) {
  if (!slot)
    return;
  for (int i = 0; i < slot->packet_count; i++)
    free(slot->packets[i].data);
  slot->packet_count = 0;
}

static void terminal_cache_slot_free(WambleTerminalCacheSlot *slot) {
  if (!slot)
    return;
  terminal_cache_slot_clear_packets(slot);
  free(slot->packets);
  slot->packets = NULL;
  slot->packet_cap = 0;
}

static void terminal_cache_free_all(WambleClientSession *session) {
  if (!session || !session->terminal_cache)
    return;
  for (int i = 0; i < session->terminal_cache_count; i++)
    terminal_cache_slot_free(&session->terminal_cache[i]);
  free(session->terminal_cache);
  session->terminal_cache = NULL;
  session->terminal_cache_count = 0;
}

static void terminal_cache_remove(WambleClientSession *session,
                                  uint32_t req_seq) {
  if (!session || !session->terminal_cache)
    return;
  for (int i = 0; i < session->terminal_cache_count; i++) {
    if (session->terminal_cache[i].req_seq != req_seq)
      continue;
    terminal_cache_slot_free(&session->terminal_cache[i]);
    for (int j = i + 1; j < session->terminal_cache_count; j++)
      session->terminal_cache[j - 1] = session->terminal_cache[j];
    session->terminal_cache_count--;
    if (session->terminal_cache_count == 0) {
      free(session->terminal_cache);
      session->terminal_cache = NULL;
    }
    return;
  }
}

static void terminal_cache_expire(WambleClientSession *session,
                                  uint64_t now_ms) {
  if (!session || !session->terminal_cache)
    return;
  int ttl = get_config()->terminal_cache_ttl_ms;
  if (ttl <= 0) {
    terminal_cache_free_all(session);
    return;
  }
  int write = 0;
  for (int i = 0; i < session->terminal_cache_count; i++) {
    WambleTerminalCacheSlot *s = &session->terminal_cache[i];
    if (now_ms - s->stored_mono_ms > (uint64_t)ttl) {
      terminal_cache_slot_free(s);
      continue;
    }
    if (write != i)
      session->terminal_cache[write] = *s;
    write++;
  }
  session->terminal_cache_count = write;
  if (write == 0) {
    free(session->terminal_cache);
    session->terminal_cache = NULL;
  }
}

#define WAMBLE_TERMINAL_CACHE_MAX_SLOTS 8
#define WAMBLE_TERMINAL_CACHE_MAX_BUNDLE_PACKETS 1024

static void terminal_cache_packet_set_meta(WambleTerminalCachePacket *packet,
                                           const uint8_t *data, size_t len) {
  if (!packet || !data || len < WAMBLE_HEADER_WIRE_SIZE)
    return;
  memcpy(packet->token, data + 4, TOKEN_LENGTH);
  packet->seq = ((uint32_t)data[28] << 24) | ((uint32_t)data[29] << 16) |
                ((uint32_t)data[30] << 8) | (uint32_t)data[31];
}

static int terminal_cache_slot_append_take(WambleTerminalCacheSlot *slot,
                                           uint8_t *data, size_t len);

static int terminal_cache_slot_append(WambleTerminalCacheSlot *slot,
                                      const uint8_t *data, size_t len) {
  uint8_t *buf = NULL;
  if (!data)
    return -1;
  buf = (uint8_t *)malloc(len);
  if (!buf)
    return -1;
  memcpy(buf, data, len);
  if (terminal_cache_slot_append_take(slot, buf, len) != 0)
    return -1;
  return 0;
}

static int terminal_cache_slot_append_take(WambleTerminalCacheSlot *slot,
                                           uint8_t *data, size_t len) {
  if (!data)
    return -1;
  if (slot->packet_count >= WAMBLE_TERMINAL_CACHE_MAX_BUNDLE_PACKETS) {
    free(data);
    return -1;
  }
  if (slot->packet_count >= slot->packet_cap) {
    int new_cap = slot->packet_cap ? slot->packet_cap * 2 : 4;
    if (new_cap > WAMBLE_TERMINAL_CACHE_MAX_BUNDLE_PACKETS)
      new_cap = WAMBLE_TERMINAL_CACHE_MAX_BUNDLE_PACKETS;
    WambleTerminalCachePacket *grown = (WambleTerminalCachePacket *)realloc(
        slot->packets, (size_t)new_cap * sizeof(*slot->packets));
    if (!grown) {
      free(data);
      return -1;
    }
    slot->packets = grown;
    slot->packet_cap = new_cap;
  }
  WambleTerminalCachePacket *packet = &slot->packets[slot->packet_count];
  memset(packet, 0, sizeof(*packet));
  packet->data = data;
  packet->len = len;
  terminal_cache_packet_set_meta(packet, data, len);
  slot->packet_count++;
  return 0;
}

static int terminal_cache_store_impl(WambleClientSession *session,
                                     uint32_t req_seq, uint8_t *owned_data,
                                     const uint8_t *data, size_t len) {
  if (!session || !data || len == 0 || len > WAMBLE_MAX_PACKET_SIZE) {
    free(owned_data);
    return -1;
  }
  int ttl = get_config()->terminal_cache_ttl_ms;
  if (ttl <= 0) {
    free(owned_data);
    return -1;
  }
  uint64_t now_ms = wamble_now_mono_millis();
  terminal_cache_expire(session, now_ms);
  WambleTerminalCacheSlot *slot = NULL;
  int oldest = 0;
  for (int i = 0; i < session->terminal_cache_count; i++) {
    if (session->terminal_cache[i].req_seq == req_seq) {
      slot = &session->terminal_cache[i];
      break;
    }
    if (session->terminal_cache[i].stored_mono_ms <
        session->terminal_cache[oldest].stored_mono_ms)
      oldest = i;
  }
  if (!slot) {
    if (session->terminal_cache_count >= WAMBLE_TERMINAL_CACHE_MAX_SLOTS) {
      slot = &session->terminal_cache[oldest];
      terminal_cache_slot_clear_packets(slot);
    } else {
      int new_count = session->terminal_cache_count + 1;
      WambleTerminalCacheSlot *grown = (WambleTerminalCacheSlot *)realloc(
          session->terminal_cache,
          (size_t)new_count * sizeof(*session->terminal_cache));
      if (!grown) {
        free(owned_data);
        return -1;
      }
      session->terminal_cache = grown;
      slot = &session->terminal_cache[session->terminal_cache_count];
      slot->packets = NULL;
      slot->packet_cap = 0;
      slot->packet_count = 0;
      session->terminal_cache_count = new_count;
    }
    slot->req_seq = req_seq;
  }
  if (owned_data) {
    if (terminal_cache_slot_append_take(slot, owned_data, len) != 0) {
      return -1;
    }
  } else if (terminal_cache_slot_append(slot, data, len) != 0) {
    return -1;
  }
  slot->stored_mono_ms = now_ms;
  return 0;
}

static int terminal_cache_store(WambleClientSession *session, uint32_t req_seq,
                                const uint8_t *data, size_t len) {
  return terminal_cache_store_impl(session, req_seq, NULL, data, len);
}

static int terminal_cache_enqueue_replay(WambleClientSession *session,
                                         uint32_t req_seq,
                                         const struct sockaddr_in *cliaddr) {
  if (!session || !session->terminal_cache || !cliaddr)
    return 0;
  terminal_cache_expire(session, wamble_now_mono_millis());
  for (int i = 0; i < session->terminal_cache_count; i++) {
    WambleTerminalCacheSlot *s = &session->terminal_cache[i];
    if (s->req_seq != req_seq)
      continue;
    if (s->packet_count == 0)
      return 0;
    for (int p = 0; p < s->packet_count; p++) {
      uint32_t seq = s->packets[p].seq;
      uint8_t token[TOKEN_LENGTH];
      memcpy(token, s->packets[p].token, TOKEN_LENGTH);
      if (seq == 0 || !token_has_any_byte(token)) {
        struct WambleMsg cached;
        uint8_t flags = 0;
        memset(&cached, 0, sizeof(cached));
        if (wamble_packet_deserialize(s->packets[p].data, s->packets[p].len,
                                      &cached, &flags) != NET_OK)
          return -1;
        seq = cached.seq_num;
        memcpy(token, cached.token, TOKEN_LENGTH);
      }
      if (transport_outbound_contains_reliable(seq, token, cliaddr))
        continue;
      if (network_enqueue_serialized_reliable(
              token, seq, s->packets[p].data, s->packets[p].len, cliaddr, 0,
              get_config()->max_retries, 0) != 0)
        return -1;
    }
    return 1;
  }
  return 0;
}

static int
transport_outbound_contains_reliable(uint32_t seq, const uint8_t *token,
                                     const struct sockaddr_in *addr) {
  (void)token;
  if (!transport_outbound_entries || !addr)
    return 0;
  int endpoint_idx = transport_endpoint_find_by_addr(addr);
  if (endpoint_idx < 0)
    return 0;
  TransportEndpointId endpoint_id =
      transport_endpoints[endpoint_idx].endpoint_id;
  for (size_t i = 0; i < transport_outbound_size; i++) {
    TransportOutboundEntry *e = &transport_outbound_entries[i];
    if (e->variant != TRANSPORT_OUTBOUND_RELIABLE_TERMINAL &&
        e->variant != TRANSPORT_OUTBOUND_RELIABLE_BUNDLE_FRAGMENT)
      continue;
    uint32_t entry_seq = e->variant == TRANSPORT_OUTBOUND_RELIABLE_TERMINAL
                             ? e->as.reliable.seq
                             : e->as.reliable_fragment.seq;
    if (entry_seq == seq && e->endpoint_id == endpoint_id)
      return 1;
  }
  return 0;
}

static void terminal_cache_release(WambleClientSession *session) {
  terminal_cache_free_all(session);
}

static void begin_reliable_request_scope(WambleClientSession *session,
                                         uint32_t seq_num) {
  g_current_request.session = session;
  g_current_request.seq_num = seq_num;
}

void network_end_request(void) { g_current_request.session = NULL; }

void network_runtime_reset_thread_state(void) {
  for (int i = 0; i < num_sessions; i++)
    terminal_cache_release(&client_sessions[i]);
  free(client_sessions);
  client_sessions = NULL;
  num_sessions = 0;
  client_sessions_capacity = 0;
  global_seq_num = 1;
  global_fragment_transfer_id = 1;
  free(session_index_map);
  session_index_map = NULL;
  session_index_map_capacity = 0;
  free(token_session_index_map);
  token_session_index_map = NULL;
  token_session_index_map_capacity = 0;
  memset(&g_current_request, 0, sizeof(g_current_request));
  transport_runtime_release();
  network_runtime_reset_drive_schedule();
}

static void sync_client_session_treatment_group(WambleClientSession *session,
                                                const uint8_t *token) {
  if (!session || !token)
    return;
  WambleTreatmentAssignment assignment = {0};
  DbStatus status =
      wamble_query_get_session_treatment_assignment(token, &assignment);
  if (status == DB_OK) {
    snprintf(session->treatment_group_key, sizeof(session->treatment_group_key),
             "%s", assignment.group_key);
    return;
  }
  if (status == DB_NOT_FOUND)
    session->treatment_group_key[0] = '\0';
}

static void update_client_session(const struct sockaddr_in *addr,
                                  const uint8_t *token, uint32_t seq_num) {
  int token_valid = token_has_any_byte(token);
  WambleClientSession *session = find_client_session(addr);
  if (!session) {
    session = create_client_session(addr, token);
    if (!session)
      return;
  }

  session->last_seq_num = seq_num;
  session->last_seen = wamble_now_wall();
  int token_changed = memcmp(session->token, token, TOKEN_LENGTH) != 0;
  if (token_changed) {
    int index = (int)(session - client_sessions);
    if (token_has_any_byte(session->token))
      token_session_map_remove(session->token, index);
    memcpy(session->token, token, TOKEN_LENGTH);
    if (token_valid)
      token_session_map_put(session->token, index);
  }
  if (token_valid) {
    sync_client_session_treatment_group(session, token);
  } else {
    session->treatment_group_key[0] = '\0';
  }
}

static void rebind_client_session(WambleClientSession *session,
                                  const struct sockaddr_in *addr) {
  if (!session || !addr || sockaddr_in_equal(&session->addr, addr))
    return;
  struct sockaddr_in old_addr = session->addr;
  session->addr = *addr;
  (void)transport_endpoint_rebind_by_addr(&old_addr, session->token, addr);
  session_map_rebuild();
}

static int reliable_sequence_is_duplicate(const WambleClientSession *session,
                                          uint32_t seq_num) {
  if (!session)
    return 0;
  uint32_t last = session->last_seq_num;
  uint32_t forward = seq_num - last;
  if (forward == 0)
    return 1;
  if (forward <= (UINT32_MAX / 2u))
    return 0;
  return (last - seq_num) <= WAMBLE_DUP_WINDOW;
}

static WambleClientSession *
find_endpoint_session(const struct sockaddr_in *cliaddr, const uint8_t *token) {
  WambleClientSession *session = find_client_session(cliaddr);
  if (!session && token_has_any_byte(token))
    session = find_client_session_by_token(token);
  return session;
}

static int
replay_duplicate_reliable_request(WambleClientSession *session,
                                  const struct WambleMsg *msg,
                                  const struct sockaddr_in *cliaddr) {
  if (!msg || !cliaddr)
    return 0;
  if (!ctrl_is_client_request(msg->ctrl) ||
      (msg->flags & WAMBLE_FLAG_UNRELIABLE) != 0) {
    return 0;
  }
  if (!reliable_sequence_is_duplicate(session, msg->seq_num))
    return 0;
  if (session) {
    rebind_client_session(session, cliaddr);
    session->last_seen = wamble_now_wall();
  }
  if (terminal_cache_enqueue_replay(session, msg->seq_num, cliaddr) < 0)
    return -1;
  if (network_enqueue_ack_after(msg, cliaddr) != 0)
    return -1;
  return 1;
}

static void admit_client_packet(const struct sockaddr_in *cliaddr,
                                const struct WambleMsg *msg, int token_valid,
                                int begin_request_scope) {
  if (!cliaddr || !msg)
    return;
  if (msg->ctrl == WAMBLE_CTRL_CLIENT_HELLO && token_valid &&
      (msg->flags & WAMBLE_FLAG_UNRELIABLE) != 0) {
    update_client_session(cliaddr, msg->token, msg->seq_num);
    return;
  }
  if (msg->ctrl == WAMBLE_CTRL_ACK ||
      (msg->flags & WAMBLE_FLAG_UNRELIABLE) != 0) {
    return;
  }

  update_client_session(cliaddr, msg->token, msg->seq_num);
  WambleClientSession *admitted = find_client_session(cliaddr);
  if (begin_request_scope)
    begin_reliable_request_scope(admitted, msg->seq_num);
}

void network_init_thread_state(void) {
  for (int i = 0; i < num_sessions; i++)
    terminal_cache_release(&client_sessions[i]);
  num_sessions = 0;
  g_current_request.session = NULL;
  transport_runtime_release();
  network_runtime_reset_drive_schedule();
  session_map_init();
  token_session_map_init();
}

int network_test_store_terminal_cache_packet(const uint8_t *token,
                                             const struct sockaddr_in *addr,
                                             uint32_t req_seq) {
  if (!token || !addr)
    return -1;
  network_ensure_thread_state_initialized();
  update_client_session(addr, token, req_seq);
  WambleClientSession *session = find_client_session(addr);
  if (!session)
    return -1;
  struct WambleMsg msg;
  memset(&msg, 0, sizeof(msg));
  msg.ctrl = WAMBLE_CTRL_SERVER_HELLO;
  msg.header_version = WAMBLE_PROTO_VERSION;
  msg.seq_num = req_seq;
  memcpy(msg.token, token, TOKEN_LENGTH);
  uint8_t packet[WAMBLE_MAX_PACKET_SIZE];
  size_t packet_len = 0;
  if (wamble_packet_serialize(&msg, packet, sizeof(packet), &packet_len, 0) !=
      NET_OK)
    return -1;
  return terminal_cache_store(session, req_seq, packet, packet_len);
}

int network_protocol_thread_terminal_cache_packet_count(void) {
  if (!client_sessions)
    return 0;
  int total = 0;
  uint64_t now_ms = wamble_now_mono_millis();
  for (int i = 0; i < num_sessions; i++) {
    WambleClientSession *session = &client_sessions[i];
    terminal_cache_expire(session, now_ms);
    for (int s = 0; s < session->terminal_cache_count; s++)
      total += session->terminal_cache[s].packet_count;
  }
  return total;
}

int network_protocol_thread_pending_packet_count(void) {
  return (int)(transport_inbound_size + transport_dispatch_size);
}

static int transport_outbound_reload_drain_pending(void) {
  for (size_t i = 0; i < transport_outbound_size; i++) {
    TransportOutboundEntry *e = &transport_outbound_entries[i];
    if (e->variant == TRANSPORT_OUTBOUND_REQUEST_ACK ||
        e->variant == TRANSPORT_OUTBOUND_RELIABLE_TERMINAL ||
        e->variant == TRANSPORT_OUTBOUND_RELIABLE_BUNDLE_FRAGMENT) {
      return 1;
    }
  }
  return 0;
}

int network_runtime_reload_drain_complete(void) {
  return transport_dispatch_size == 0 && transport_reliable_bundle_size == 0 &&
         transport_outbound_reload_drain_pending() == 0 &&
         network_protocol_thread_terminal_cache_packet_count() == 0;
}

int network_runtime_has_pending_thread_state(void) {
  return network_protocol_thread_pending_packet_count() != 0 ||
         network_protocol_thread_terminal_cache_packet_count() != 0 ||
         transport_reliable_bundle_size != 0 ||
         transport_outbound_reload_drain_pending();
}

int network_get_client_addr_by_token(const uint8_t *token,
                                     struct sockaddr_in *out_addr) {
  if (!token || !out_addr)
    return -1;
  if (!client_sessions)
    network_init_thread_state();
  if (!client_sessions)
    return -1;
  WambleClientSession *session = find_client_session_by_token(token);
  if (!session)
    return -1;
  *out_addr = session->addr;
  return 0;
}

void network_bind_client_token(const struct sockaddr_in *addr,
                               const uint8_t *token) {
  if (!addr || !token || !token_has_any_byte(token))
    return;
  update_client_session(addr, token, 0);
}

int network_get_bound_token_for_addr(const struct sockaddr_in *addr,
                                     uint8_t out_token[TOKEN_LENGTH]) {
  if (!addr || !out_token)
    return -1;
  network_ensure_thread_state_initialized();
  if (!client_sessions)
    return -1;
  WambleClientSession *session = find_client_session(addr);
  if (!session || !token_has_any_byte(session->token))
    return -1;
  memcpy(out_token, session->token, TOKEN_LENGTH);
  return 0;
}

wamble_socket_t create_and_bind_socket(int port) {
  wamble_socket_t sockfd;
  struct sockaddr_in servaddr;

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == WAMBLE_INVALID_SOCKET) {

    return -1;
  }

  int optval = 1;
  (void)setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&optval,
                   sizeof(optval));

  int buffer_size = get_config()->buffer_size;
  (void)setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (const char *)&buffer_size,
                   sizeof(buffer_size));
  (void)setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const char *)&buffer_size,
                   sizeof(buffer_size));

  memset(&servaddr, 0, sizeof(servaddr));

  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = INADDR_ANY;
  servaddr.sin_port = htons((uint16_t)port);

  if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
    wamble_close_socket(sockfd);
    return -1;
  }

  (void)wamble_set_nonblocking(sockfd);

  network_init_thread_state();

  return sockfd;
}

typedef enum NetworkInboundClassification {
  NETWORK_INBOUND_INVALID = -1,
  NETWORK_INBOUND_ACK = 1,
  NETWORK_INBOUND_DUPLICATE = 2,
  NETWORK_INBOUND_REQUEST = 3,
} NetworkInboundClassification;

static int network_classify_packet_impl(
    wamble_socket_t sockfd, const uint8_t *packet, size_t packet_len,
    struct WambleMsg *msg, const struct sockaddr_in *cliaddr,
    TransportEndpointId inbound_endpoint_id,
    TransportEndpointId *out_endpoint_id,
    NetworkInboundClassification *out_kind, int begin_request_scope) {
  if (!packet || !msg || !cliaddr || packet_len == 0 ||
      packet_len > WAMBLE_MAX_PACKET_SIZE) {
    return -1;
  }
  if (out_kind)
    *out_kind = NETWORK_INBOUND_INVALID;
  network_ensure_thread_state_initialized();

  uint8_t flags = 0;
  if (wamble_packet_deserialize(packet, packet_len, msg, &flags) != NET_OK)
    return -1;

  if (!ctrl_is_supported(msg->ctrl))
    return -1;
  if (msg->text.uci_len > MAX_UCI_LENGTH)
    return -1;

  int token_valid = token_has_any_byte(msg->token);
  if (!token_valid && !ctrl_allows_anonymous_token(msg->ctrl))
    return -1;

  TransportEndpointId endpoint_id = inbound_endpoint_id;
  if (msg->ctrl == WAMBLE_CTRL_ACK) {
    if (endpoint_id == TRANSPORT_ENDPOINT_ID_INVALID &&
        transport_endpoint_bind_addr_token(cliaddr, msg->token, &endpoint_id) !=
            0)
      return -1;
    if (out_endpoint_id)
      *out_endpoint_id = endpoint_id;

    int ack_rc = transport_outbound_match_and_remove_ack(
        endpoint_id, msg->seq_num, msg->token, cliaddr);
    if (ack_rc < 0)
      return -1;
    if (out_kind)
      *out_kind = NETWORK_INBOUND_ACK;
    return (int)packet_len;
  }

  if (ctrl_is_client_request(msg->ctrl)) {
    if (token_valid && transport_endpoint_count_by_token(msg->token) == 1) {
      int token_idx = transport_endpoint_find_by_token(msg->token);
      int endpoint_idx = transport_endpoint_find_by_id(endpoint_id);
      if (token_idx >= 0 && token_idx != endpoint_idx) {
        (void)transport_endpoint_rebind_id(
            transport_endpoints[token_idx].endpoint_id, cliaddr);
        endpoint_id = transport_endpoints[token_idx].endpoint_id;
      }
    }
    if (endpoint_id == TRANSPORT_ENDPOINT_ID_INVALID) {
      if (transport_endpoint_bind_addr_token(cliaddr, msg->token,
                                             &endpoint_id) != 0)
        return -1;
    } else if (token_valid) {
      int idx = transport_endpoint_find_by_id(endpoint_id);
      if (idx >= 0)
        memcpy(transport_endpoints[idx].token, msg->token, TOKEN_LENGTH);
    }
  }
  if (out_endpoint_id)
    *out_endpoint_id = endpoint_id;

  WambleClientSession *session = find_endpoint_session(cliaddr, msg->token);
  (void)sockfd;
  int duplicate_rc = replay_duplicate_reliable_request(session, msg, cliaddr);
  if (duplicate_rc < 0)
    return -1;
  if (duplicate_rc > 0) {
    if (out_kind)
      *out_kind = NETWORK_INBOUND_DUPLICATE;
    return (int)packet_len;
  }

  admit_client_packet(cliaddr, msg, token_valid, begin_request_scope);
  if (out_kind)
    *out_kind = NETWORK_INBOUND_REQUEST;
  return (int)packet_len;
}

static int receive_message_from_packet_impl(wamble_socket_t sockfd,
                                            const uint8_t *packet,
                                            size_t packet_len,
                                            struct WambleMsg *msg,
                                            const struct sockaddr_in *cliaddr) {
  NetworkInboundClassification kind = NETWORK_INBOUND_INVALID;
  int rc = network_classify_packet_impl(sockfd, packet, packet_len, msg,
                                        cliaddr, TRANSPORT_ENDPOINT_ID_INVALID,
                                        NULL, &kind, 1);
  if (rc <= 0)
    return rc;
  if (kind == NETWORK_INBOUND_DUPLICATE)
    return -1;
  return rc;
}

static int
transport_outbound_match_and_remove_ack(TransportEndpointId endpoint_id,
                                        uint32_t seq, const uint8_t *token,
                                        const struct sockaddr_in *cliaddr) {
  (void)cliaddr;
  if (!transport_outbound_entries ||
      endpoint_id == TRANSPORT_ENDPOINT_ID_INVALID)
    return 0;
  for (size_t i = 0; i < transport_outbound_size; i++) {
    TransportOutboundEntry *e = &transport_outbound_entries[i];
    uint32_t entry_seq = 0;
    if (e->variant == TRANSPORT_OUTBOUND_RELIABLE_TERMINAL) {
      entry_seq = e->as.reliable.seq;
    } else if (e->variant == TRANSPORT_OUTBOUND_RELIABLE_BUNDLE_FRAGMENT) {
      entry_seq = e->as.reliable_fragment.seq;
    } else {
      continue;
    }
    if (entry_seq != seq || e->endpoint_id != endpoint_id)
      continue;
    if (token && token_has_any_byte(token) && token_has_any_byte(e->token) &&
        memcmp(e->token, token, TOKEN_LENGTH) != 0)
      continue;
    if (e->variant == TRANSPORT_OUTBOUND_RELIABLE_TERMINAL ||
        e->variant == TRANSPORT_OUTBOUND_RELIABLE_BUNDLE_FRAGMENT) {
      uint64_t sent_at_ms = 0;
      uint64_t deadline_at_ms = 0;
      uint32_t rto_ms = 0;
      uint16_t retry_count = 0;
      if (e->variant == TRANSPORT_OUTBOUND_RELIABLE_TERMINAL) {
        sent_at_ms = e->as.reliable.sent_at_ms;
        deadline_at_ms = e->as.reliable.deadline_at_ms;
        rto_ms = e->as.reliable.rto_ms;
        retry_count = e->as.reliable.retry_count;
      } else {
        sent_at_ms = e->as.reliable_fragment.sent_at_ms;
        deadline_at_ms = e->as.reliable_fragment.deadline_at_ms;
        rto_ms = e->as.reliable_fragment.rto_ms;
        retry_count = e->as.reliable_fragment.retry_count;
      }
      if (sent_at_ms > 0 || deadline_at_ms > rto_ms) {
        uint64_t now_ms = wamble_now_mono_millis();
        if (sent_at_ms == 0)
          sent_at_ms = deadline_at_ms - rto_ms;
        if (sent_at_ms > 0 && now_ms >= sent_at_ms) {
          uint64_t sample_ms = now_ms - sent_at_ms;
          if (sample_ms > UINT32_MAX)
            sample_ms = UINT32_MAX;
          int retransmitted = retry_count > 1;
          int endpoint_idx = transport_endpoint_find_by_id(e->endpoint_id);
          if (endpoint_idx >= 0)
            (void)transport_endpoint_update_rto_by_index(
                (size_t)endpoint_idx, (uint32_t)sample_ms, retransmitted);
        }
      }
    }
    uint64_t bundle_id =
        e->variant == TRANSPORT_OUTBOUND_RELIABLE_BUNDLE_FRAGMENT
            ? e->as.reliable_fragment.bundle_id
            : 0;
    transport_outbound_remove(i);
    if (bundle_id != 0 &&
        transport_reliable_bundle_fragment_acked(bundle_id) < 0)
      return -1;
    return 1;
  }
  return 0;
}

int transport_outbound_match_ack(TransportEndpointId endpoint_id, uint32_t seq,
                                 const uint8_t token[TOKEN_LENGTH]) {
  return transport_outbound_match_and_remove_ack(endpoint_id, seq, token, NULL);
}

int receive_message_packet(const uint8_t *packet, size_t packet_len,
                           struct WambleMsg *msg,
                           const struct sockaddr_in *cliaddr) {
  return receive_message_from_packet_impl(WAMBLE_INVALID_SOCKET, packet,
                                          packet_len, msg, cliaddr);
}

int receive_message(wamble_socket_t sockfd, struct WambleMsg *msg,
                    struct sockaddr_in *cliaddr) {
  network_ensure_thread_state_initialized();
  TransportInboundEntry pending;
  memset(&pending, 0, sizeof(pending));
  if (transport_inbound_pop(&pending)) {
    if (cliaddr)
      *cliaddr = pending.addr;
    return receive_message_from_packet_impl(
        sockfd, pending.packet, pending.packet_len, msg, &pending.addr);
  }

  wamble_socklen_t len = sizeof(*cliaddr);
  uint8_t receive_buffer[WAMBLE_MAX_PACKET_SIZE];
  ssize_t bytes_received =
      recvfrom(sockfd, (char *)receive_buffer, WAMBLE_MAX_PACKET_SIZE, 0,
               (struct sockaddr *)cliaddr, &len);

  if (bytes_received <= 0)
    return (int)bytes_received;
  return receive_message_from_packet_impl(sockfd, receive_buffer,
                                          (size_t)bytes_received, msg, cliaddr);
}

int network_ack_received_message(wamble_socket_t sockfd,
                                 const struct WambleMsg *msg,
                                 const struct sockaddr_in *cliaddr) {
  if (!msg || !cliaddr || msg->ctrl == WAMBLE_CTRL_ACK ||
      (msg->flags & WAMBLE_FLAG_UNRELIABLE) != 0)
    return 0;
  if (network_enqueue_ack_after(msg, cliaddr) != 0)
    return -1;
  TransportDriveResult drive = network_outbound_pump(sockfd, 64u);
  return drive.status == TRANSPORT_DRIVE_PROGRESS ? 0 : -1;
}

int network_enqueue_ack_after(const struct WambleMsg *msg,
                              const struct sockaddr_in *cliaddr) {
  if (!msg || !cliaddr)
    return -1;
  struct WambleMsg ack_msg;
  memset(&ack_msg, 0, sizeof(ack_msg));
  ack_msg.ctrl = WAMBLE_CTRL_ACK;
  memcpy(ack_msg.token, msg->token, TOKEN_LENGTH);
  ack_msg.board_id = msg->board_id;
  ack_msg.seq_num = msg->seq_num;

  uint8_t send_buffer[WAMBLE_MAX_PACKET_SIZE];
  size_t serialized_size = 0;
  if (wamble_packet_serialize(&ack_msg, send_buffer, sizeof(send_buffer),
                              &serialized_size, 0) != NET_OK)
    return -1;

  uint8_t *owned_payload = (uint8_t *)malloc(serialized_size);
  if (!owned_payload)
    return -1;
  memcpy(owned_payload, send_buffer, serialized_size);

  TransportOutboundEntry entry;
  memset(&entry, 0, sizeof(entry));
  entry.variant = TRANSPORT_OUTBOUND_REQUEST_ACK;
  entry.addr = *cliaddr;
  memcpy(entry.token, msg->token, TOKEN_LENGTH);
  entry.payload = owned_payload;
  entry.payload_len = serialized_size;
  entry.as.ack.ack_seq = msg->seq_num;
  entry.as.ack.deadline_at_ms = 0;
  if (transport_outbound_push(&entry) != 0) {
    free(owned_payload);
    return -1;
  }
  return 0;
}

static uint32_t
transport_endpoint_reserve_reliable_seq(TransportEndpointId endpoint_id) {
  int idx = transport_endpoint_find_by_id(endpoint_id);
  if (idx >= 0) {
    uint32_t seq_num = transport_endpoints[idx].next_reliable_seq++;
    if (transport_endpoints[idx].next_reliable_seq > (UINT32_MAX - 1000))
      transport_endpoints[idx].next_reliable_seq = 1;
    return seq_num;
  }
  uint32_t seq_num = global_seq_num++;
  if (global_seq_num > (UINT32_MAX - 1000))
    global_seq_num = 1;
  return seq_num;
}

static uint32_t reserve_reliable_seq_num(const struct sockaddr_in *cliaddr,
                                         const uint8_t *token) {
  static const uint8_t zero_token[TOKEN_LENGTH] = {0};
  const uint8_t *effective_token = token ? token : zero_token;
  TransportEndpointId endpoint_id = TRANSPORT_ENDPOINT_ID_INVALID;
  if (transport_endpoint_bind_addr_token(cliaddr, effective_token,
                                         &endpoint_id) == 0)
    return transport_endpoint_reserve_reliable_seq(endpoint_id);
  return transport_endpoint_reserve_reliable_seq(TRANSPORT_ENDPOINT_ID_INVALID);
}

static NetworkStatus serialize_packet_with_payload(
    uint8_t ctrl, uint8_t header_version, const uint8_t *token,
    uint64_t board_id, uint32_t seq_num, uint8_t flags, const uint8_t *payload,
    size_t payload_len, uint8_t *buffer, size_t buffer_capacity,
    size_t *out_len) {
  if (!buffer || !out_len || buffer_capacity < WAMBLE_HEADER_WIRE_SIZE ||
      payload_len > WAMBLE_MAX_PAYLOAD || payload_len > UINT16_MAX) {
    return NET_ERR_INVALID;
  }

  if (WAMBLE_HEADER_WIRE_SIZE + payload_len > buffer_capacity)
    return NET_ERR_TRUNCATED;

  memset(buffer, 0, WAMBLE_HEADER_WIRE_SIZE);
  buffer[0] = ctrl;
  buffer[1] = flags;
  buffer[2] = header_version ? header_version : WAMBLE_PROTO_VERSION;
  if (token)
    memcpy(buffer + 4, token, TOKEN_LENGTH);
  for (int i = 0; i < 8; i++) {
    buffer[20 + i] = (uint8_t)((board_id >> (8 * (7 - i))) & 0xFFu);
  }
  buffer[28] = (uint8_t)((seq_num >> 24) & 0xFFu);
  buffer[29] = (uint8_t)((seq_num >> 16) & 0xFFu);
  buffer[30] = (uint8_t)((seq_num >> 8) & 0xFFu);
  buffer[31] = (uint8_t)(seq_num & 0xFFu);
  buffer[32] = (uint8_t)((payload_len >> 8) & 0xFFu);
  buffer[33] = (uint8_t)(payload_len & 0xFFu);
  if (payload_len && payload)
    memcpy(buffer + WAMBLE_HEADER_WIRE_SIZE, payload, payload_len);
  *out_len = WAMBLE_HEADER_WIRE_SIZE + payload_len;
  return NET_OK;
}

static int transport_serialize_bundle_fragment(
    const ReliableBundle *bundle, uint16_t chunk_index, uint32_t seq_num,
    uint8_t *send_buffer, size_t send_buffer_size, size_t *serialized_size) {
  if (!bundle || !send_buffer || !serialized_size ||
      chunk_index >= bundle->chunk_count)
    return -1;
  size_t chunk_size = (size_t)WAMBLE_FRAGMENT_DATA_MAX;
  size_t offset = (size_t)chunk_index * chunk_size;
  size_t chunk_len = 0;
  if (offset < bundle->payload_len) {
    chunk_len = bundle->payload_len - offset;
    if (chunk_len > chunk_size)
      chunk_len = chunk_size;
  }
  struct WambleMsg fragment;
  memset(&fragment, 0, sizeof(fragment));
  fragment.ctrl = bundle->ctrl;
  fragment.header_version =
      bundle->header_version ? bundle->header_version : WAMBLE_PROTO_VERSION;
  fragment.flags =
      (uint8_t)(bundle->flags & (uint8_t)~(WAMBLE_FLAG_EXT_PAYLOAD |
                                           WAMBLE_FLAG_FRAGMENT_PAYLOAD |
                                           WAMBLE_FLAG_UNRELIABLE));
  memcpy(fragment.token, bundle->token, TOKEN_LENGTH);
  fragment.board_id = bundle->board_id;
  fragment.seq_num = seq_num;
  fragment.fragment.fragment_version = WAMBLE_FRAGMENT_VERSION;
  fragment.fragment.fragment_hash_algo = bundle->hash_algo;
  fragment.fragment.fragment_chunk_index = chunk_index;
  fragment.fragment.fragment_chunk_count = bundle->chunk_count;
  fragment.fragment.fragment_total_len = (uint32_t)bundle->payload_len;
  fragment.fragment.fragment_transfer_id = bundle->transfer_id;
  memcpy(fragment.fragment.fragment_hash, bundle->hash,
         WAMBLE_FRAGMENT_HASH_LENGTH);
  fragment.fragment.fragment_data_len = (uint16_t)chunk_len;
  if (chunk_len)
    memcpy(fragment.fragment.fragment_data, bundle->payload + offset,
           chunk_len);
  return wamble_packet_serialize(&fragment, send_buffer, send_buffer_size,
                                 serialized_size, fragment.flags) == NET_OK
             ? 0
             : -1;
}

static int transport_enqueue_bundle_fragment(ReliableBundle *bundle,
                                             uint16_t chunk_index) {
  if (!bundle || chunk_index >= bundle->chunk_count)
    return -1;
  uint32_t seq_num =
      transport_endpoint_reserve_reliable_seq(bundle->endpoint_id);
  uint8_t send_buffer[WAMBLE_MAX_PACKET_SIZE];
  size_t serialized_size = 0;
  if (transport_serialize_bundle_fragment(bundle, chunk_index, seq_num,
                                          send_buffer, sizeof(send_buffer),
                                          &serialized_size) != 0)
    return -1;
  uint8_t *owned_payload = (uint8_t *)malloc(serialized_size);
  if (!owned_payload)
    return -1;
  memcpy(owned_payload, send_buffer, serialized_size);

  TransportOutboundEntry entry;
  memset(&entry, 0, sizeof(entry));
  entry.variant = TRANSPORT_OUTBOUND_RELIABLE_BUNDLE_FRAGMENT;
  entry.endpoint_id = bundle->endpoint_id;
  entry.addr = bundle->addr;
  memcpy(entry.token, bundle->token, TOKEN_LENGTH);
  entry.payload = owned_payload;
  entry.payload_len = serialized_size;
  entry.as.reliable_fragment.seq = seq_num;
  entry.as.reliable_fragment.fragment_index = chunk_index;
  entry.as.reliable_fragment.fragment_count = bundle->chunk_count;
  entry.as.reliable_fragment.bundle_id = bundle->bundle_id;
  entry.as.reliable_fragment.rto_ms = transport_clamp_rto_ms(
      bundle->timeout_ms > 0 ? (uint32_t)bundle->timeout_ms : 0);
  entry.as.reliable_fragment.max_retries = bundle->max_retries;
  if (transport_outbound_push(&entry) != 0) {
    free(owned_payload);
    return -1;
  }
  return 0;
}

static int
transport_cache_replayable_bundle_packets(const ReliableBundle *bundle) {
  if (!bundle || !bundle->replayable_terminal || !g_current_request.session)
    return 0;
  for (uint16_t i = 0; i < bundle->chunk_count; i++) {
    uint32_t seq_num = reserve_reliable_seq_num(&bundle->addr, bundle->token);
    uint8_t send_buffer[WAMBLE_MAX_PACKET_SIZE];
    size_t serialized_size = 0;
    if (transport_serialize_bundle_fragment(bundle, i, seq_num, send_buffer,
                                            sizeof(send_buffer),
                                            &serialized_size) != 0)
      return -1;
    if (terminal_cache_store(g_current_request.session,
                             g_current_request.seq_num, send_buffer,
                             serialized_size) != 0)
      return -1;
  }
  return 0;
}

static int transport_reliable_bundle_fragment_acked(uint64_t bundle_id) {
  ssize_t idx = transport_reliable_bundle_find(bundle_id);
  if (idx < 0)
    return 0;
  ReliableBundle *bundle = &transport_reliable_bundles[idx];
  if (bundle->next_fragment_index >= bundle->chunk_count) {
    transport_reliable_bundle_remove((size_t)idx);
    return 1;
  }
  uint16_t next = bundle->next_fragment_index++;
  if (transport_enqueue_bundle_fragment(bundle, next) != 0) {
    transport_reliable_bundle_remove((size_t)idx);
    return -1;
  }
  return 1;
}

static int transport_enqueue_reliable_bundle(
    uint8_t ctrl, const uint8_t *token, uint64_t board_id,
    uint8_t header_version, uint8_t flags, const uint8_t *payload,
    size_t payload_len, const struct sockaddr_in *cliaddr, int timeout_ms,
    int max_retries, int replayable_terminal) {
  static const uint8_t zero_token[TOKEN_LENGTH] = {0};
  const uint8_t *effective_token = token ? token : zero_token;
  if (!cliaddr || (!payload && payload_len > 0) ||
      payload_len > (size_t)UINT32_MAX ||
      !ctrl_supports_fragment_payload(ctrl) || WAMBLE_FRAGMENT_DATA_MAX == 0)
    return -1;
  size_t chunk_size = (size_t)WAMBLE_FRAGMENT_DATA_MAX;
  size_t needed_chunks =
      payload_len == 0 ? 1u : (payload_len + chunk_size - 1u) / chunk_size;
  if (needed_chunks == 0 || needed_chunks > UINT16_MAX)
    return -1;
  if (timeout_ms <= 0)
    timeout_ms = get_config()->timeout_ms;
  if (max_retries <= 0)
    max_retries = get_config()->max_retries;
  if (transport_size_ensure((void **)&transport_reliable_bundles,
                            sizeof(*transport_reliable_bundles),
                            &transport_reliable_bundle_capacity,
                            transport_reliable_bundle_size + 1) != 0)
    return -1;
  ReliableBundle bundle;
  memset(&bundle, 0, sizeof(bundle));
  bundle.bundle_id = transport_allocate_bundle_id();
  if (transport_endpoint_bind_addr_token(cliaddr, effective_token,
                                         &bundle.endpoint_id) != 0)
    return -1;
  bundle.ctrl = ctrl;
  memcpy(bundle.token, effective_token, TOKEN_LENGTH);
  bundle.board_id = board_id;
  bundle.payload = payload_len > 0 ? (uint8_t *)malloc(payload_len) : NULL;
  if (payload_len > 0 && !bundle.payload)
    return -1;
  if (payload_len > 0)
    memcpy(bundle.payload, payload, payload_len);
  bundle.payload_len = payload_len;
  bundle.chunk_count = (uint16_t)needed_chunks;
  bundle.next_fragment_index = 1;
  bundle.hash_algo = WAMBLE_FRAGMENT_HASH_BLAKE2B_256;
  crypto_blake2b(bundle.hash, WAMBLE_FRAGMENT_HASH_LENGTH, payload,
                 payload_len);
  bundle.req_seq = g_current_request.seq_num;
  bundle.transfer_id = next_fragment_transfer_id();
  bundle.replayable_terminal = replayable_terminal ? 1 : 0;
  bundle.header_version =
      header_version ? header_version : WAMBLE_PROTO_VERSION;
  bundle.flags = (uint8_t)(flags & (uint8_t)~(WAMBLE_FLAG_EXT_PAYLOAD |
                                              WAMBLE_FLAG_FRAGMENT_PAYLOAD |
                                              WAMBLE_FLAG_UNRELIABLE));
  bundle.max_retries = (uint16_t)max_retries;
  bundle.timeout_ms = timeout_ms;
  bundle.addr = *cliaddr;
  size_t idx = transport_reliable_bundle_size++;
  transport_reliable_bundles[idx] = bundle;
  if (transport_enqueue_bundle_fragment(&transport_reliable_bundles[idx], 0) !=
      0) {
    transport_reliable_bundle_remove(idx);
    return -1;
  }
  if (transport_cache_replayable_bundle_packets(
          &transport_reliable_bundles[idx]) != 0) {
    terminal_cache_remove(g_current_request.session, g_current_request.seq_num);
    for (size_t i = 0; i < transport_outbound_size;) {
      TransportOutboundEntry *e = &transport_outbound_entries[i];
      if (e->variant == TRANSPORT_OUTBOUND_RELIABLE_BUNDLE_FRAGMENT &&
          e->as.reliable_fragment.bundle_id == bundle.bundle_id)
        transport_outbound_remove(i);
      else
        i++;
    }
    transport_reliable_bundle_remove(idx);
    return -1;
  }
  return 0;
}

static void terminal_cache_store_for_current_request(const uint8_t *data,
                                                     size_t len) {
  if (!g_current_request.session)
    return;
  (void)terminal_cache_store(g_current_request.session,
                             g_current_request.seq_num, data, len);
}

static int send_serialized_packet_once(wamble_socket_t sockfd,
                                       const uint8_t *send_buffer,
                                       size_t serialized_size,
                                       const struct sockaddr_in *cliaddr,
                                       int *sent_over_ws) {
  if (sent_over_ws)
    *sent_over_ws = 0;
  int ws_rc = ws_gateway_queue_packet(cliaddr, send_buffer, serialized_size);
  if (ws_rc > 0) {
    if (sent_over_ws)
      *sent_over_ws = 1;
    if (ws_gateway_flush_route(cliaddr) != 0)
      return -1;
    return 0;
  }
  if (ws_rc < 0)
    return -1;

  ssize_t bytes_sent = sendto(sockfd, (const char *)send_buffer,
#ifdef WAMBLE_PLATFORM_WINDOWS
                              (int)serialized_size,
#else
                              (size_t)serialized_size,
#endif
                              0, (const struct sockaddr *)cliaddr,
#ifdef WAMBLE_PLATFORM_WINDOWS
                              (int)sizeof(*cliaddr)
#else
                              (wamble_socklen_t)sizeof(*cliaddr)
#endif
  );
  return bytes_sent < 0 ? -1 : 0;
}

static int network_enqueue_serialized_reliable(
    const uint8_t *token, uint32_t seq_num, const uint8_t *send_buffer,
    size_t serialized_size, const struct sockaddr_in *cliaddr, int timeout_ms,
    int max_retries, int replayable_terminal) {
  static const uint8_t zero_token[TOKEN_LENGTH] = {0};
  const uint8_t *effective_token = token ? token : zero_token;
  if (!send_buffer || serialized_size == 0 ||
      serialized_size > WAMBLE_MAX_PACKET_SIZE || !cliaddr)
    return -1;
  TransportEndpointId endpoint_id = TRANSPORT_ENDPOINT_ID_INVALID;
  if (transport_endpoint_bind_addr_token(cliaddr, effective_token,
                                         &endpoint_id) != 0)
    return -1;
  if (timeout_ms <= 0)
    timeout_ms = (int)transport_endpoint_rto_ms_by_id(endpoint_id);
  if (max_retries <= 0)
    max_retries = get_config()->max_retries;

  uint8_t *owned_payload = (uint8_t *)malloc(serialized_size);
  if (!owned_payload)
    return -1;
  memcpy(owned_payload, send_buffer, serialized_size);

  TransportOutboundEntry entry;
  memset(&entry, 0, sizeof(entry));
  entry.variant = TRANSPORT_OUTBOUND_RELIABLE_TERMINAL;
  entry.endpoint_id = endpoint_id;
  entry.addr = *cliaddr;
  memcpy(entry.token, effective_token, TOKEN_LENGTH);
  entry.payload = owned_payload;
  entry.payload_len = serialized_size;
  entry.as.reliable.seq = seq_num;
  entry.as.reliable.deadline_at_ms = 0;
  entry.as.reliable.sent_at_ms = 0;
  entry.as.reliable.rto_ms = transport_clamp_rto_ms((uint32_t)timeout_ms);
  entry.as.reliable.retry_count = 0;
  entry.as.reliable.max_retries = (uint16_t)max_retries;
  if (transport_outbound_push(&entry) != 0) {
    free(owned_payload);
    return -1;
  }
  if (replayable_terminal)
    terminal_cache_store_for_current_request(send_buffer, serialized_size);
  return 0;
}

int network_enqueue_reliable(const struct WambleMsg *msg,
                             const struct sockaddr_in *cliaddr, int timeout_ms,
                             int max_retries) {
  if (!msg || !cliaddr)
    return -1;
  struct WambleMsg reliable_msg = *msg;
  reliable_msg.seq_num = reserve_reliable_seq_num(cliaddr, msg->token);
  uint8_t send_buffer[WAMBLE_MAX_PACKET_SIZE];
  size_t serialized_size = 0;
  NetworkStatus serialize_status =
      wamble_packet_serialize(&reliable_msg, send_buffer, sizeof(send_buffer),
                              &serialized_size, reliable_msg.flags);
  if (serialize_status != NET_OK)
    return -1;
  return network_enqueue_serialized_reliable(
      reliable_msg.token, reliable_msg.seq_num, send_buffer, serialized_size,
      cliaddr, timeout_ms, max_retries, 0);
}

int network_enqueue_replayable_terminal(const struct WambleMsg *msg,
                                        const struct sockaddr_in *cliaddr) {
  if (!msg || !cliaddr)
    return -1;
  struct WambleMsg reliable_msg = *msg;
  reliable_msg.flags = (uint8_t)(reliable_msg.flags & ~WAMBLE_FLAG_UNRELIABLE);
  if (reliable_msg.seq_num == 0)
    reliable_msg.seq_num = reserve_reliable_seq_num(cliaddr, msg->token);
  uint8_t send_buffer[WAMBLE_MAX_PACKET_SIZE];
  size_t serialized_size = 0;
  NetworkStatus serialize_status =
      wamble_packet_serialize(&reliable_msg, send_buffer, sizeof(send_buffer),
                              &serialized_size, reliable_msg.flags);
  if (serialize_status != NET_OK) {
    if (serialize_status == NET_ERR_TRUNCATED)
      return network_enqueue_fragmented_replayable_terminal(
          &reliable_msg, cliaddr, get_config()->timeout_ms,
          get_config()->max_retries);
    return -1;
  }
  return network_enqueue_serialized_reliable(
      reliable_msg.token, reliable_msg.seq_num, send_buffer, serialized_size,
      cliaddr, 0, get_config()->max_retries, 1);
}

int network_enqueue_replayable_terminal_for_token(const struct WambleMsg *msg,
                                                  const uint8_t *token) {
  if (!msg || !token || !client_sessions)
    return -1;
  int enqueued = 0;
  for (int idx = token_session_map_head(token); idx >= 0;) {
    WambleClientSession *session = &client_sessions[idx];
    int next_idx = session->token_next_index;
    if (network_enqueue_replayable_terminal(msg, &session->addr) == 0)
      enqueued++;
    idx = next_idx;
  }
  return enqueued > 0 ? 0 : -1;
}

int network_enqueue_unreliable(const struct WambleMsg *msg,
                               const struct sockaddr_in *cliaddr) {
  if (!msg || !cliaddr)
    return -1;
  uint8_t buffer[WAMBLE_MAX_PACKET_SIZE];
  size_t serialized_size = 0;
  uint8_t send_flags = (uint8_t)(msg->flags | WAMBLE_FLAG_UNRELIABLE);
  if (wamble_packet_serialize(msg, buffer, sizeof(buffer), &serialized_size,
                              send_flags) != NET_OK)
    return -1;
  uint8_t *owned_payload = (uint8_t *)malloc(serialized_size);
  if (!owned_payload)
    return -1;
  memcpy(owned_payload, buffer, serialized_size);

  TransportOutboundEntry entry;
  memset(&entry, 0, sizeof(entry));
  entry.variant = TRANSPORT_OUTBOUND_UNRELIABLE;
  entry.addr = *cliaddr;
  memcpy(entry.token, msg->token, TOKEN_LENGTH);
  entry.payload = owned_payload;
  entry.payload_len = serialized_size;
  if (transport_outbound_push(&entry) != 0) {
    free(owned_payload);
    return -1;
  }
  return 0;
}

int network_enqueue_unreliable_for_token(const struct WambleMsg *msg,
                                         const uint8_t *token) {
  if (!msg || !token || !client_sessions)
    return -1;
  int enqueued = 0;
  for (int idx = token_session_map_head(token); idx >= 0;) {
    WambleClientSession *session = &client_sessions[idx];
    int next_idx = session->token_next_index;
    if (network_enqueue_unreliable(msg, &session->addr) == 0)
      enqueued++;
    idx = next_idx;
  }
  return enqueued > 0 ? 0 : -1;
}

int network_enqueue_reliable_payload_bytes(uint8_t ctrl, const uint8_t *token,
                                           uint64_t board_id,
                                           const uint8_t *payload,
                                           size_t payload_len,
                                           const struct sockaddr_in *cliaddr,
                                           int timeout_ms, int max_retries,
                                           int force_fragment) {
  static const uint8_t zero_token[TOKEN_LENGTH] = {0};
  const uint8_t *effective_token = token ? token : zero_token;
  if (!cliaddr)
    return -1;
  if (timeout_ms <= 0)
    timeout_ms = get_config()->timeout_ms;
  if (max_retries <= 0)
    max_retries = get_config()->max_retries;

  if (force_fragment || payload_len > WAMBLE_MAX_PAYLOAD) {
    if (!ctrl_supports_fragment_payload(ctrl) ||
        payload_len > (size_t)UINT32_MAX || WAMBLE_FRAGMENT_DATA_MAX == 0) {
      return -1;
    }
    return transport_enqueue_reliable_bundle(
        ctrl, effective_token, board_id, WAMBLE_PROTO_VERSION, 0, payload,
        payload_len, cliaddr, timeout_ms, max_retries, 1);
  }

  if (payload_len > WAMBLE_MAX_PAYLOAD)
    return -1;

  uint32_t seq_num = reserve_reliable_seq_num(cliaddr, effective_token);
  uint8_t send_buffer[WAMBLE_MAX_PACKET_SIZE];
  size_t serialized_size = 0;
  if (serialize_packet_with_payload(ctrl, WAMBLE_PROTO_VERSION, effective_token,
                                    board_id, seq_num, 0, payload, payload_len,
                                    send_buffer, sizeof(send_buffer),
                                    &serialized_size) != NET_OK) {
    return -1;
  }

  return network_enqueue_serialized_reliable(
      effective_token, seq_num, send_buffer, serialized_size, cliaddr,
      timeout_ms, max_retries, 1);
}

static int network_enqueue_fragmented_replayable_terminal(
    const struct WambleMsg *source_msg, const struct sockaddr_in *cliaddr,
    int timeout_ms, int max_retries) {
  if (!source_msg || !cliaddr || msg_uses_fragment_payload(source_msg) ||
      !ctrl_supports_fragment_payload(source_msg->ctrl) ||
      WAMBLE_FRAGMENT_DATA_MAX == 0) {
    return -1;
  }

  uint8_t *full_payload = NULL;
  size_t full_len = 0;
  NetworkStatus st =
      build_message_payload_dynamic(source_msg, &full_payload, &full_len, NULL);
  if (st != NET_OK)
    return -1;
  if (full_len <= WAMBLE_MAX_PAYLOAD || full_len > UINT32_MAX) {
    free(full_payload);
    return -1;
  }

  int rc = transport_enqueue_reliable_bundle(
      source_msg->ctrl, source_msg->token, source_msg->board_id,
      source_msg->header_version, source_msg->flags, full_payload, full_len,
      cliaddr, timeout_ms, max_retries, 1);
  free(full_payload);
  return rc;
}

static int
send_fragmented_unreliable_payload(wamble_socket_t sockfd,
                                   const struct WambleMsg *source_msg,
                                   const struct sockaddr_in *cliaddr) {
  if (!source_msg || !cliaddr || msg_uses_fragment_payload(source_msg) ||
      !ctrl_supports_fragment_payload(source_msg->ctrl) ||
      WAMBLE_FRAGMENT_DATA_MAX == 0) {
    return -1;
  }

  uint8_t *full_payload = NULL;
  size_t full_len = 0;
  NetworkStatus st =
      build_message_payload_dynamic(source_msg, &full_payload, &full_len, NULL);
  if (st != NET_OK)
    return -1;
  if (full_len <= WAMBLE_MAX_PAYLOAD || full_len > UINT32_MAX) {
    free(full_payload);
    return -1;
  }

  size_t chunk_size = (size_t)WAMBLE_FRAGMENT_DATA_MAX;
  size_t needed_chunks = (full_len + chunk_size - 1u) / chunk_size;
  if (needed_chunks == 0 || needed_chunks > UINT16_MAX) {
    free(full_payload);
    return -1;
  }

  uint8_t payload_hash[WAMBLE_FRAGMENT_HASH_LENGTH] = {0};
  crypto_blake2b(payload_hash, WAMBLE_FRAGMENT_HASH_LENGTH, full_payload,
                 full_len);
  uint32_t transfer_id = next_fragment_transfer_id();
  uint16_t chunk_count = (uint16_t)needed_chunks;

  for (uint16_t chunk_index = 0; chunk_index < chunk_count; chunk_index++) {
    size_t offset = (size_t)chunk_index * chunk_size;
    size_t chunk_len = full_len - offset;
    if (chunk_len > chunk_size)
      chunk_len = chunk_size;

    struct WambleMsg fragment = {0};
    fragment.ctrl = source_msg->ctrl;
    fragment.flags =
        (uint8_t)(source_msg->flags & (uint8_t)~(WAMBLE_FLAG_EXT_PAYLOAD |
                                                 WAMBLE_FLAG_FRAGMENT_PAYLOAD));
    fragment.header_version = source_msg->header_version;
    memcpy(fragment.token, source_msg->token, TOKEN_LENGTH);
    fragment.board_id = source_msg->board_id;
    fragment.fragment.fragment_version = WAMBLE_FRAGMENT_VERSION;
    fragment.fragment.fragment_hash_algo = WAMBLE_FRAGMENT_HASH_BLAKE2B_256;
    fragment.fragment.fragment_chunk_index = chunk_index;
    fragment.fragment.fragment_chunk_count = chunk_count;
    fragment.fragment.fragment_total_len = (uint32_t)full_len;
    fragment.fragment.fragment_transfer_id = transfer_id;
    memcpy(fragment.fragment.fragment_hash, payload_hash,
           WAMBLE_FRAGMENT_HASH_LENGTH);
    fragment.fragment.fragment_data_len = (uint16_t)chunk_len;
    if (chunk_len) {
      memcpy(fragment.fragment.fragment_data, full_payload + offset, chunk_len);
    }

    if (send_unreliable_packet(sockfd, &fragment, cliaddr) != 0) {
      free(full_payload);
      return -1;
    }
  }

  free(full_payload);
  return 0;
}

int send_unreliable_packet(wamble_socket_t sockfd, const struct WambleMsg *msg,
                           const struct sockaddr_in *cliaddr) {
  if (!msg || !cliaddr)
    return -1;
  uint8_t buffer[WAMBLE_MAX_PACKET_SIZE];
  size_t serialized_size = 0;
  uint8_t send_flags = (uint8_t)(msg->flags | WAMBLE_FLAG_UNRELIABLE);
  NetworkStatus serialize_status = wamble_packet_serialize(
      msg, buffer, sizeof(buffer), &serialized_size, send_flags);
  if (serialize_status != NET_OK) {
    if (serialize_status == NET_ERR_TRUNCATED)
      return send_fragmented_unreliable_payload(sockfd, msg, cliaddr);
    return -1;
  }
  int ws_rc = ws_gateway_queue_packet(cliaddr, buffer, serialized_size);
  if (ws_rc > 0)
    return 0;
  if (ws_rc < 0)
    return -1;
#ifdef WAMBLE_PLATFORM_WINDOWS
  int rc = sendto(sockfd, (const char *)buffer, (int)serialized_size, 0,
                  (const struct sockaddr *)cliaddr, (int)sizeof(*cliaddr));
  return (rc >= 0) ? 0 : -1;
#else
  int tries = 0;
  while (tries < 4) {
    ssize_t rc = sendto(sockfd, (const char *)buffer, (size_t)serialized_size,
                        MSG_DONTWAIT, (const struct sockaddr *)cliaddr,
                        (wamble_socklen_t)sizeof(*cliaddr));
    if (rc >= 0)
      return 0;
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      struct timespec ts = {0, 1000000L};
      nanosleep(&ts, NULL);
      tries++;
      continue;
    }
    break;
  }
  return -1;
#endif
}

static int network_is_manager_wake_packet(const uint8_t *packet,
                                          size_t packet_len,
                                          const struct sockaddr_in *addr) {
  if (!packet || !addr || packet_len != 1 || packet[0] != 0)
    return 0;
  uint32_t ip = ntohl(addr->sin_addr.s_addr);
  return (ip >> 24) == 127u;
}

static TransportDriveResult network_inbound_pump(wamble_socket_t sockfd,
                                                 WambleWsGateway *ws_gateway,
                                                 long select_usec,
                                                 size_t budget) {
  uint32_t progress_count = 0;
  uint32_t error_count = 0;
  if (ws_gateway) {
    for (size_t drained_ws = 0; drained_ws < budget; drained_ws++) {
      TransportInboundEntry entry;
      memset(&entry, 0, sizeof(entry));
      entry.source = TRANSPORT_PACKET_SOURCE_WS;
      size_t packet_len = 0;
      struct sockaddr_in ws_cliaddr;
      int ws_rc =
          ws_gateway_pop_packet(ws_gateway, entry.packet, sizeof(entry.packet),
                                &packet_len, &ws_cliaddr);
      if (ws_rc <= 0)
        break;
      entry.addr = ws_cliaddr;
      (void)transport_endpoint_bind_addr_token(&entry.addr, NULL,
                                               &entry.endpoint_id);
      entry.packet_len = packet_len;
      if (transport_inbound_push(&entry) != 0) {
        error_count++;
        break;
      }
      progress_count++;
    }
  }

  if (sockfd != WAMBLE_INVALID_SOCKET) {
    int ready = 0;
    fd_set rfds;
    struct timeval tv;
    FD_ZERO(&rfds);
    FD_SET(sockfd, &rfds);
    tv.tv_sec = 0;
    if (select_usec < 0)
      select_usec = 0;
    if (progress_count)
      select_usec = 0;
    tv.tv_usec = select_usec;
    ready =
#ifdef WAMBLE_PLATFORM_WINDOWS
        select(0, &rfds, NULL, NULL, &tv);
#else
        select(sockfd + 1, &rfds, NULL, NULL, &tv);
#endif
    if (ready > 0 && FD_ISSET(sockfd, &rfds)) {
      for (size_t drained = 0; drained < budget; drained++) {
        TransportInboundEntry entry;
        memset(&entry, 0, sizeof(entry));
        entry.source = TRANSPORT_PACKET_SOURCE_UDP;
        struct sockaddr_in cliaddr;
        wamble_socklen_t len = sizeof(cliaddr);
        ssize_t bytes_received =
            recvfrom(sockfd, (char *)entry.packet, WAMBLE_MAX_PACKET_SIZE, 0,
                     (struct sockaddr *)&cliaddr, &len);
        if (bytes_received <= 0)
          break;
        entry.addr = cliaddr;
        entry.packet_len = (size_t)bytes_received;
        if (network_is_manager_wake_packet(entry.packet, entry.packet_len,
                                           &entry.addr)) {
          progress_count++;
          continue;
        }
        (void)transport_endpoint_bind_addr_token(&entry.addr, NULL,
                                                 &entry.endpoint_id);
        if (transport_inbound_push(&entry) != 0) {
          error_count++;
          break;
        }
        progress_count++;
      }
    } else if (ready < 0) {
      error_count++;
    }
  }

  TransportDriveStatus status = TRANSPORT_DRIVE_IDLE;
  if (error_count)
    status = TRANSPORT_DRIVE_ERROR;
  else if (progress_count)
    status = TRANSPORT_DRIVE_PROGRESS;
  return transport_drive_result_make(
      status, transport_inbound_size, transport_dispatch_size,
      transport_outbound_size, progress_count, error_count, 0,
      error_count ? (wamble_now_mono_millis() + 1u) : 0);
}

static TransportDriveResult network_classify_inbound(wamble_socket_t sockfd,
                                                     size_t budget) {
  uint32_t progress_count = 0;
  uint32_t error_count = 0;
  size_t processed = 0;
  while (processed < budget) {
    TransportInboundEntry inbound;
    memset(&inbound, 0, sizeof(inbound));
    if (!transport_inbound_pop(&inbound))
      break;
    processed++;

    struct WambleMsg msg;
    memset(&msg, 0, sizeof(msg));
    NetworkInboundClassification kind = NETWORK_INBOUND_INVALID;
    TransportEndpointId classified_endpoint_id = inbound.endpoint_id;
    int rc = network_classify_packet_impl(
        sockfd, inbound.packet, inbound.packet_len, &msg, &inbound.addr,
        inbound.endpoint_id, &classified_endpoint_id, &kind, 0);
    if (rc <= 0) {
      error_count++;
      continue;
    }
    progress_count++;
    if (kind != NETWORK_INBOUND_REQUEST)
      continue;

    TransportDispatchEntry dispatch;
    memset(&dispatch, 0, sizeof(dispatch));
    dispatch.source = inbound.source;
    dispatch.endpoint_id = classified_endpoint_id;
    dispatch.addr = inbound.addr;
    dispatch.msg = msg;
    if (transport_dispatch_push(&dispatch) != 0) {
      error_count++;
      break;
    }
  }

  TransportDriveStatus status = TRANSPORT_DRIVE_IDLE;
  if (error_count)
    status = TRANSPORT_DRIVE_ERROR;
  else if (progress_count)
    status = TRANSPORT_DRIVE_PROGRESS;
  else if (transport_inbound_size || transport_dispatch_size)
    status = TRANSPORT_DRIVE_PENDING;
  return transport_drive_result_make(
      status, transport_inbound_size, transport_dispatch_size,
      transport_outbound_size, progress_count, error_count, 0,
      error_count ? (wamble_now_mono_millis() + 1u) : 0);
}

static TransportDriveResult network_dispatch_requests(wamble_socket_t sockfd,
                                                      const char *profile_name,
                                                      size_t budget) {
  uint32_t progress_count = 0;
  uint32_t error_count = 0;
  size_t processed = 0;
  while (processed < budget) {
    TransportDispatchEntry dispatch;
    memset(&dispatch, 0, sizeof(dispatch));
    if (!transport_dispatch_pop(&dispatch))
      break;
    processed++;
    if (ctrl_is_client_request(dispatch.msg.ctrl) &&
        (dispatch.msg.flags & WAMBLE_FLAG_UNRELIABLE) == 0) {
      WambleClientSession *session =
          find_endpoint_session(&dispatch.addr, dispatch.msg.token);
      begin_reliable_request_scope(session, dispatch.msg.seq_num);
    }
    int previous_defer = network_set_deferred_reliable_ack_wait(1);
    ServerStatus status =
        handle_message(sockfd, &dispatch.msg, &dispatch.addr, 0, profile_name);
    (void)network_set_deferred_reliable_ack_wait(previous_defer);
    network_end_request();
    if (status == SERVER_ERR_SEND_FAILED)
      error_count++;
    progress_count++;
  }

  TransportDriveStatus status = TRANSPORT_DRIVE_IDLE;
  if (error_count)
    status = TRANSPORT_DRIVE_ERROR;
  else if (progress_count)
    status = TRANSPORT_DRIVE_PROGRESS;
  else if (transport_dispatch_size)
    status = TRANSPORT_DRIVE_PENDING;
  return transport_drive_result_make(
      status, transport_inbound_size, transport_dispatch_size,
      transport_outbound_size, progress_count, error_count, 0,
      error_count ? (wamble_now_mono_millis() + 1u) : 0);
}

static TransportDriveResult network_outbound_pump(wamble_socket_t sockfd,
                                                  size_t budget) {
  uint32_t progress_count = 0;
  uint32_t error_count = 0;
  uint64_t next_deadline = 0;
  uint64_t retry_after = 0;
  uint64_t now = wamble_now_mono_millis();
  TransportOutboundLane lanes[] = {TRANSPORT_OUTBOUND_LANE_REQUEST_ACK,
                                   TRANSPORT_OUTBOUND_LANE_RELIABLE_TERMINAL,
                                   TRANSPORT_OUTBOUND_LANE_RELIABLE_BUNDLE,
                                   TRANSPORT_OUTBOUND_LANE_UNRELIABLE};

  for (size_t l = 0; l < sizeof(lanes) / sizeof(lanes[0]) &&
                     progress_count + error_count < budget;
       l++) {
    for (size_t i = 0; i < transport_outbound_size &&
                       progress_count + error_count < budget;) {
      TransportOutboundEntry *entry = &transport_outbound_entries[i];
      if (entry->lane != lanes[l]) {
        i++;
        continue;
      }

      uint64_t deadline = transport_outbound_entry_deadline(entry);
      if (deadline > now) {
        if (entry->variant != TRANSPORT_OUTBOUND_REQUEST_ACK)
          next_deadline = transport_min_nonzero_u64(next_deadline, deadline);
        i++;
        continue;
      }

      struct sockaddr_in delivery_addr = entry->addr;
      if (transport_endpoint_resolve_addr(entry->endpoint_id, &delivery_addr) ==
          0) {
        entry->addr = delivery_addr;
      }
      if (sockfd == WAMBLE_INVALID_SOCKET &&
          !ws_gateway_is_ws_client(&delivery_addr)) {
        retry_after = transport_min_nonzero_u64(retry_after, now + 1u);
        error_count++;
        if (entry->variant == TRANSPORT_OUTBOUND_REQUEST_ACK ||
            entry->variant == TRANSPORT_OUTBOUND_UNRELIABLE) {
          transport_outbound_remove(i);
          continue;
        }
        uint32_t rto = entry->variant == TRANSPORT_OUTBOUND_RELIABLE_TERMINAL
                           ? entry->as.reliable.rto_ms
                           : entry->as.reliable_fragment.rto_ms;
        transport_outbound_entry_arm_retry(entry, now, rto);
        next_deadline = transport_min_nonzero_u64(
            next_deadline, transport_outbound_entry_deadline(entry));
        i++;
        continue;
      }

      uint16_t max_retries = transport_outbound_entry_max_retries(entry);
      if (max_retries > 0 &&
          transport_outbound_entry_retry_count(entry) >= max_retries) {
        uint64_t dropped_bundle_id =
            entry->variant == TRANSPORT_OUTBOUND_RELIABLE_BUNDLE_FRAGMENT
                ? entry->as.reliable_fragment.bundle_id
                : 0;
        transport_outbound_remove(i);
        if (dropped_bundle_id != 0) {
          ssize_t bundle_idx =
              transport_reliable_bundle_find(dropped_bundle_id);
          if (bundle_idx >= 0)
            transport_reliable_bundle_remove((size_t)bundle_idx);
        }
        error_count++;
        continue;
      }

      if (send_serialized_packet_once(sockfd, entry->payload,
                                      entry->payload_len, &delivery_addr,
                                      NULL) != 0) {
        error_count++;
        retry_after = transport_min_nonzero_u64(retry_after, now + 1u);
        if (entry->variant == TRANSPORT_OUTBOUND_RELIABLE_TERMINAL ||
            entry->variant == TRANSPORT_OUTBOUND_RELIABLE_BUNDLE_FRAGMENT) {
          uint32_t rto = entry->variant == TRANSPORT_OUTBOUND_RELIABLE_TERMINAL
                             ? entry->as.reliable.rto_ms
                             : entry->as.reliable_fragment.rto_ms;
          transport_outbound_entry_arm_retry(entry, now, rto);
          next_deadline = transport_min_nonzero_u64(
              next_deadline, transport_outbound_entry_deadline(entry));
          i++;
        } else {
          transport_outbound_remove(i);
        }
        continue;
      }

      progress_count++;
      if (entry->variant == TRANSPORT_OUTBOUND_RELIABLE_TERMINAL ||
          entry->variant == TRANSPORT_OUTBOUND_RELIABLE_BUNDLE_FRAGMENT) {
        uint32_t rto = entry->variant == TRANSPORT_OUTBOUND_RELIABLE_TERMINAL
                           ? entry->as.reliable.rto_ms
                           : entry->as.reliable_fragment.rto_ms;
        int endpoint_idx = transport_endpoint_find_by_id(entry->endpoint_id);
        if (rto == 0 && endpoint_idx >= 0 &&
            transport_endpoints[endpoint_idx].rto_ms != 0) {
          rto = transport_endpoints[endpoint_idx].rto_ms;
        }
        if (rto == 0)
          rto = WAMBLE_TRANSPORT_INITIAL_RTO_MS;
        transport_outbound_entry_arm_retry(entry, now, rto);
        next_deadline = transport_min_nonzero_u64(
            next_deadline, transport_outbound_entry_deadline(entry));
        i++;
        continue;
      }
      transport_outbound_remove(i);
    }
  }

  TransportDriveStatus status = TRANSPORT_DRIVE_IDLE;
  if (error_count)
    status = transport_outbound_size ? TRANSPORT_DRIVE_BACKOFF
                                     : TRANSPORT_DRIVE_ERROR;
  else if (progress_count)
    status = TRANSPORT_DRIVE_PROGRESS;
  else if (transport_outbound_size)
    status = TRANSPORT_DRIVE_PENDING;
  return transport_drive_result_make(
      status, transport_inbound_size, transport_dispatch_size,
      transport_outbound_size, progress_count, error_count, next_deadline,
      error_count ? (retry_after ? retry_after : now + 1u) : 0);
}

TransportDriveResult network_runtime_drive_once_with_gateway(
    wamble_socket_t sockfd, WambleWsGateway *ws_gateway, long select_usec,
    const char *profile_name) {
  if (transport_inbound_size || transport_dispatch_size)
    select_usec = 0;
  TransportDriveResult inbound = network_inbound_pump(
      sockfd, ws_gateway, select_usec, WAMBLE_INBOUND_PUMP_BATCH);
  TransportDriveResult classified =
      network_classify_inbound(sockfd, WAMBLE_CLASSIFY_BATCH);
  TransportDriveResult dispatched =
      network_dispatch_requests(sockfd, profile_name, WAMBLE_DISPATCH_BATCH);
  TransportDriveResult outbound = network_outbound_pump(sockfd, 64u);
  TransportDriveResult result = transport_drive_result_merge(
      transport_drive_result_merge(
          transport_drive_result_merge(inbound, classified), dispatched),
      outbound);
  result.inbound_pending = transport_inbound_size;
  result.dispatch_pending = transport_dispatch_size;
  result.outbound_pending = transport_outbound_size;
  if (result.status == TRANSPORT_DRIVE_IDLE &&
      (result.inbound_pending || result.dispatch_pending ||
       result.outbound_pending))
    result.status = TRANSPORT_DRIVE_PENDING;
  return result;
}

TransportDriveResult network_runtime_drive_once(wamble_socket_t sockfd,
                                                long select_usec,
                                                const char *profile_name) {
  return network_runtime_drive_once_with_gateway(sockfd, NULL, select_usec,
                                                 profile_name);
}

void network_runtime_drive_reload_drain(wamble_socket_t sockfd,
                                        WambleWsGateway *ws_gateway,
                                        const char *profile_name,
                                        int step_budget) {
  if (step_budget <= 0)
    step_budget = 1;
  for (int i = 0; i < step_budget; i++) {
    TransportDriveResult inbound =
        network_inbound_pump(sockfd, ws_gateway, 0, WAMBLE_INBOUND_PUMP_BATCH);
    TransportDriveResult classified =
        network_classify_inbound(sockfd, WAMBLE_CLASSIFY_BATCH);
    TransportDriveResult dispatched =
        network_dispatch_requests(sockfd, profile_name, WAMBLE_DISPATCH_BATCH);
    TransportDriveResult outbound = network_outbound_pump(sockfd, 64u);
    TransportDriveResult drive = transport_drive_result_merge(
        transport_drive_result_merge(
            transport_drive_result_merge(inbound, classified), dispatched),
        outbound);
    runtime_next_deadline_at_ms =
        drive.outbound_pending ? drive.next_deadline_at_ms : 0;
    runtime_retry_after_ms = drive.outbound_pending ? drive.retry_after_ms : 0;
    if (!drive.inbound_pending && !drive.dispatch_pending &&
        !drive.outbound_pending)
      break;
    if (drive.status != TRANSPORT_DRIVE_PROGRESS &&
        drive.status != TRANSPORT_DRIVE_PENDING)
      break;
  }
  if (ws_gateway)
    ws_gateway_flush_outbound(ws_gateway);
}

void network_runtime_drive_budget(wamble_socket_t sockfd,
                                  WambleWsGateway *ws_gateway,
                                  long base_select_usec,
                                  const char *profile_name, int step_budget) {
  if (step_budget <= 0)
    step_budget = 1;

  long select_usec = base_select_usec;
  uint64_t now_ms = wamble_now_mono_millis();
  if (transport_inbound_size || transport_dispatch_size) {
    select_usec = 0;
  } else if (transport_outbound_size) {
    uint64_t wake_ms = 0;
    if (runtime_retry_after_ms)
      wake_ms = runtime_retry_after_ms;
    if (runtime_next_deadline_at_ms &&
        (wake_ms == 0 || runtime_next_deadline_at_ms < wake_ms))
      wake_ms = runtime_next_deadline_at_ms;
    if (wake_ms == 0 || wake_ms <= now_ms) {
      select_usec = 0;
    } else {
      uint64_t delta_ms = wake_ms - now_ms;
      uint64_t delta_usec = delta_ms > ((uint64_t)LONG_MAX / 1000u)
                                ? (uint64_t)LONG_MAX
                                : delta_ms * 1000u;
      if (select_usec <= 0 || delta_usec < (uint64_t)select_usec)
        select_usec =
            delta_usec > (uint64_t)LONG_MAX ? LONG_MAX : (long)delta_usec;
    }
  }

  for (int i = 0; i < step_budget; i++) {
    TransportDriveResult drive = network_runtime_drive_once_with_gateway(
        sockfd, ws_gateway, select_usec, profile_name);
    runtime_next_deadline_at_ms =
        drive.outbound_pending ? drive.next_deadline_at_ms : 0;
    runtime_retry_after_ms = drive.outbound_pending ? drive.retry_after_ms : 0;
    if (!drive.inbound_pending && !drive.dispatch_pending &&
        !drive.outbound_pending)
      break;
    if (drive.status != TRANSPORT_DRIVE_PROGRESS &&
        drive.status != TRANSPORT_DRIVE_PENDING)
      break;
    now_ms = wamble_now_mono_millis();
    if (drive.status == TRANSPORT_DRIVE_PENDING &&
        drive.next_deadline_at_ms > now_ms)
      break;
    select_usec = 0;
  }

  if (ws_gateway)
    ws_gateway_flush_outbound(ws_gateway);
}

void cleanup_expired_sessions(void) {
  time_t now = wamble_now_wall();
  int write_idx = 0;

  for (int read_idx = 0; read_idx < num_sessions; read_idx++) {
    if (now - client_sessions[read_idx].last_seen <
        get_config()->session_timeout) {
      if (write_idx != read_idx) {
        client_sessions[write_idx] = client_sessions[read_idx];
      }
      write_idx++;
    } else {
      terminal_cache_release(&client_sessions[read_idx]);
    }
  }

  if (write_idx != num_sessions) {
    num_sessions = write_idx;
    g_current_request.session = NULL;
    session_map_rebuild();
    token_session_map_rebuild();
  }
}

int wamble_socket_bound_port(wamble_socket_t sock) {
  struct sockaddr_in addr;
  wamble_socklen_t len = (wamble_socklen_t)sizeof(addr);
  if (getsockname(sock, (struct sockaddr *)&addr, &len) != 0)
    return -1;
  return (int)ntohs(addr.sin_port);
}
