#ifndef WAMBLE_TEST_HELPERS_H
#define WAMBLE_TEST_HELPERS_H

#include "wamble/wamble.h"
#include <stddef.h>
#include <stdint.h>

typedef struct WambleWsGateway WambleWsGateway;

typedef enum {
  WS_GATEWAY_OK = 0,
  WS_GATEWAY_STATUS_UPGRADE_ACCEPTED = 1,
  WS_GATEWAY_STATUS_ROUTE_REGISTERED = 2,
  WS_GATEWAY_STATUS_STREAM_STARTED = 3,
  WS_GATEWAY_STATUS_CLOSE_RECEIVED = 4,
  WS_GATEWAY_STATUS_OUTBOUND_FLUSHED = 5,
  WS_GATEWAY_STATUS_OUTBOUND_QUEUED = 6,
  WS_GATEWAY_STATUS_STREAM_EXITED = 7,
  WS_GATEWAY_STATUS_HANDSHAKE_READ_FAILED = 8,
  WS_GATEWAY_STATUS_BAD_REQUEST_LINE = 9,
  WS_GATEWAY_STATUS_PATH_MISMATCH = 10,
  WS_GATEWAY_STATUS_UPGRADE_HEADER_INVALID = 11,
  WS_GATEWAY_STATUS_SEND_101_FAILED = 12,
  WS_GATEWAY_STATUS_ROUTE_REGISTER_FAILED = 13,
  WS_GATEWAY_STATUS_WAIT_FAILED = 14,
  WS_GATEWAY_STATUS_OUTBOUND_FLUSH_FAILED = 15,
  WS_GATEWAY_STATUS_READ_FAILED = 16,
  WS_GATEWAY_STATUS_CLOSE_TOO_LARGE = 17,
  WS_GATEWAY_STATUS_NON_BINARY_OPCODE = 18,
  WS_GATEWAY_STATUS_BINARY_REJECTED = 19,
  WS_GATEWAY_STATUS_QUEUE_REJECTED = 20,
  WS_GATEWAY_ERR_CONFIG = -1,
  WS_GATEWAY_ERR_BIND = -2,
  WS_GATEWAY_ERR_THREAD = -3,
  WS_GATEWAY_ERR_ALLOC = -4,
} WsGatewayStatus;

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

void network_init_thread_state(void);
void cleanup_expired_sessions(void);
int receive_message_packet(const uint8_t *packet, size_t packet_len,
                           struct WambleMsg *msg,
                           const struct sockaddr_in *cliaddr);
void network_bind_client_token(const struct sockaddr_in *addr,
                               const uint8_t *token);
int network_get_bound_token_for_addr(const struct sockaddr_in *addr,
                                     uint8_t out_token[TOKEN_LENGTH]);
void network_end_request(void);
wamble_socket_t create_and_bind_socket(int port);
int receive_message(wamble_socket_t sockfd, struct WambleMsg *msg,
                    struct sockaddr_in *cliaddr);
int send_unreliable_packet(wamble_socket_t sockfd, const struct WambleMsg *msg,
                           const struct sockaddr_in *cliaddr);
int wamble_socket_bound_port(wamble_socket_t sock);
ServerStatus handle_message(wamble_socket_t sockfd, const struct WambleMsg *msg,
                            const struct sockaddr_in *cliaddr, int trust_tier,
                            const char *profile_name);
WambleWsGateway *ws_gateway_start(const char *profile_name, int ws_port,
                                  int udp_port, const char *ws_path,
                                  WsGatewayStatus *out_status);
void ws_gateway_stop(WambleWsGateway *gateway);
void ws_gateway_request_restart_clients(WambleWsGateway *gateway);
int ws_gateway_matches(const WambleWsGateway *gateway, int ws_port,
                       int udp_port, const char *ws_path);
int ws_gateway_pop_packet(WambleWsGateway *gateway, uint8_t *packet,
                          size_t packet_cap, size_t *out_packet_len,
                          struct sockaddr_in *out_cliaddr);
int ws_gateway_is_ws_client(const struct sockaddr_in *cliaddr);
int ws_gateway_queue_packet(const struct sockaddr_in *cliaddr,
                            const uint8_t *packet, size_t packet_len);
void ws_gateway_flush_outbound(WambleWsGateway *gateway);
int ws_gateway_flush_route(const struct sockaddr_in *cliaddr);
int ws_gateway_active_client_count(WambleWsGateway *gateway);
int server_protocol_thread_pending_login_challenge_count(void);
int server_protocol_test_issue_login_challenge(const uint8_t *token,
                                               const uint8_t *public_key);
void server_protocol_test_clear_login_challenges(void);
int board_manager_count_active_or_reserved(void);
int spectator_collect_state_snapshot(const uint8_t *token,
                                     struct SpectatorUpdate *out, int max);
int spectator_collect_updates(struct SpectatorUpdate *out, int max);
int spectator_collect_notifications(struct SpectatorUpdate *out, int max);
int spectator_manager_active_count_for_port(int owner_port);
int board_collect_reservation_release_notifications(
    ReservationReleaseNotification *out, int max);

int network_ack_received_message(wamble_socket_t sockfd,
                                 const struct WambleMsg *msg,
                                 const struct sockaddr_in *cliaddr);
int network_enqueue_reliable(const struct WambleMsg *msg,
                             const struct sockaddr_in *cliaddr, int timeout_ms,
                             int max_retries);
int network_enqueue_replayable_terminal(const struct WambleMsg *msg,
                                        const struct sockaddr_in *cliaddr);
int network_enqueue_ack_after(const struct WambleMsg *msg,
                              const struct sockaddr_in *cliaddr);
int network_enqueue_unreliable(const struct WambleMsg *msg,
                               const struct sockaddr_in *cliaddr);
int network_get_client_addr_by_token(const uint8_t *token,
                                     struct sockaddr_in *out_addr);
int network_protocol_thread_pending_packet_count(void);
int network_protocol_thread_terminal_cache_packet_count(void);
int network_test_store_terminal_cache_packet(const uint8_t *token,
                                             const struct sockaddr_in *addr,
                                             uint32_t req_seq);
int network_runtime_reload_drain_complete(void);
int network_enqueue_reliable_payload_bytes(uint8_t ctrl, const uint8_t *token,
                                           uint64_t board_id,
                                           const uint8_t *payload,
                                           size_t payload_len,
                                           const struct sockaddr_in *cliaddr,
                                           int timeout_ms, int max_retries,
                                           int force_fragment);
int transport_inbound_push(const TransportInboundEntry *entry);
int transport_inbound_pop(TransportInboundEntry *out);
size_t transport_inbound_count(void);
int transport_dispatch_push(const TransportDispatchEntry *entry);
int transport_dispatch_pop(TransportDispatchEntry *out);
size_t transport_dispatch_count(void);
int transport_outbound_push(const TransportOutboundEntry *entry);
void transport_outbound_remove(size_t index);
size_t transport_outbound_count(void);
int transport_endpoint_bind_addr_token(const struct sockaddr_in *addr,
                                       const uint8_t token[TOKEN_LENGTH],
                                       TransportEndpointId *out_endpoint_id);
int transport_endpoint_rebind_id(TransportEndpointId endpoint_id,
                                 const struct sockaddr_in *addr);
int transport_endpoint_resolve_addr(TransportEndpointId endpoint_id,
                                    struct sockaddr_in *out);
uint32_t transport_endpoint_rto_ms_by_id(TransportEndpointId endpoint_id);
int transport_endpoint_update_rto_by_id(TransportEndpointId endpoint_id,
                                        uint32_t sample_ms, int retransmitted);
TransportDriveResult transport_drive_result_idle(void);
TransportDriveResult
transport_drive_result_pending(size_t inbound_pending, size_t dispatch_pending,
                               size_t outbound_pending,
                               uint64_t next_deadline_at_ms);
TransportDriveResult transport_drive_result_progress(uint32_t progress_count);
TransportDriveResult transport_drive_result_error(size_t inbound_pending,
                                                  size_t dispatch_pending,
                                                  size_t outbound_pending,
                                                  uint32_t error_count,
                                                  uint64_t retry_after_ms);
TransportDriveResult transport_drive_result_merge(TransportDriveResult a,
                                                  TransportDriveResult b);
TransportDriveResult network_runtime_drive_once(wamble_socket_t sockfd,
                                                long select_usec,
                                                const char *profile_name);
TransportDriveResult network_runtime_drive_once_with_gateway(
    wamble_socket_t sockfd, WambleWsGateway *ws_gateway, long select_usec,
    const char *profile_name);

const char *wamble_test_dsn(void);
int wamble_db_available(void);
int wamble_should_skip_db_tests(void);
int wamble_test_ensure_dir(const char *path);
int wamble_test_path(char *out, size_t out_len, const char *subdir,
                     const char *name);
int wamble_test_mkstemp_file(char *out, size_t out_len, const char *subdir,
                             const char *prefix);
int wamble_test_write_text_file(const char *path, const char *text);
int wamble_test_write_optional_db_config_file(const char *path,
                                              const char *suffix);
int wamble_test_write_db_config_file(const char *path, const char *suffix);
int wamble_test_prepare_db(const char *cfg_path, const char *cfg_suffix,
                           const char *extra_sql);

int wamble_test_write_config(const char *path, int port, int timeout_ms,
                             int inactivity_timeout, int reservation_timeout,
                             const char *db_host, const char *db_user,
                             const char *db_pass, const char *db_name,
                             int log_level);
int wamble_test_db_config_lines(char *out, size_t out_len);

int wamble_test_state_dir(char *out, size_t out_len);
int wamble_test_set_state_env(void);
int wamble_test_set_state_dir_env(void);

void wamble_metric(const char *name, const char *fmt, ...);

int send_reliable_terminal_and_drive(wamble_socket_t sockfd,
                                     const struct WambleMsg *msg,
                                     const struct sockaddr_in *addr,
                                     int timeout_ms, int max_retries);

int test_db_create_schema_if_needed(const char *schema_name);
int test_db_set_search_path(const char *schema_name);
int test_db_apply_sql(const char *sql);
int test_db_apply_sql_file(const char *sql_path);
int test_db_apply_migrations(const char *schema_name);
int test_db_apply_fixture(const char *schema_name);
int test_db_reset(const char *schema_name);
int test_db_drop_schema(const char *schema_name);
int test_db_reset_schema(const char *schema_name);

#endif
