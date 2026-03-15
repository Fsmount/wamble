#ifndef WAMBLE_NET_HELPERS_H
#define WAMBLE_NET_HELPERS_H

#include "wamble/wamble.h"

int wamble_test_alloc_udp_port(void);
int wamble_test_wait_readable(wamble_socket_t sock, int timeout_ms);

#ifdef __unix__
#include <pthread.h>

int wamble_test_join_thread_with_timeout(pthread_t thr, int timeout_ms);
#endif

#if defined(WAMBLE_PLATFORM_WINDOWS)
typedef int ws_test_io_count_t;
#else
typedef ssize_t ws_test_io_count_t;
#endif

wamble_socket_t wamble_test_ws_connect(int port);
int wamble_test_ws_handshake(wamble_socket_t sock, const char *path,
                             const char *key, const char *version);
int wamble_test_ws_send_frame_ex(wamble_socket_t sock, uint8_t fin,
                                 uint8_t opcode, const uint8_t *payload,
                                 size_t len, int force_ext126);
int wamble_test_ws_send_frame(wamble_socket_t sock, uint8_t opcode,
                              const uint8_t *payload, size_t len,
                              int force_ext126);
int wamble_test_ws_recv_frame(wamble_socket_t sock, uint8_t *out_opcode,
                              uint8_t *payload, size_t payload_cap,
                              size_t *out_len);
int wamble_test_ws_recv_http(wamble_socket_t sock, char *out, size_t cap);
int wamble_test_ws_send_handshake_with_first_frame(wamble_socket_t sock,
                                                   const char *path,
                                                   const uint8_t *payload,
                                                   size_t payload_len);
WambleWsGateway *wamble_test_start_gateway(int *out_tcp_port,
                                           wamble_socket_t *out_udp_sock,
                                           WsGatewayStatus *out_status,
                                           int *out_last_port);

#endif
