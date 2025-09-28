#ifndef WAMBLE_NET_HELPERS_H
#define WAMBLE_NET_HELPERS_H

#include "wamble/wamble.h"

int wamble_test_alloc_udp_port(void);
int wamble_test_wait_readable(wamble_socket_t sock, int timeout_ms);

#ifdef __unix__
#include <pthread.h>

int wamble_test_join_thread_with_timeout(pthread_t thr, int timeout_ms);
#endif

#endif
