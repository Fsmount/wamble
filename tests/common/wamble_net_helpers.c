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
