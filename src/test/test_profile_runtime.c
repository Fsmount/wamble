#ifdef TEST_PROFILE_RUNTIME
#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <stdarg.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "../../include/wamble/wamble.h"

void network_init_thread_state(void) {}
int receive_message(int sockfd, struct WambleMsg *msg, struct sockaddr_in *a) {
  (void)sockfd;
  (void)msg;
  (void)a;
  return -1;
}
void handle_message(int sockfd, const struct WambleMsg *msg,
                    const struct sockaddr_in *cliaddr) {
  (void)sockfd;
  (void)msg;
  (void)cliaddr;
}
void cleanup_expired_sessions(void) {}

typedef struct {
  int fd;
  int port;
} BindRec;
static BindRec binds[32];
static int bind_count = 0;
static int next_fd = 100;
static int closes[64];
static int close_count = 0;

int socket(int domain, int type, int protocol) {
  (void)domain;
  (void)type;
  (void)protocol;
  return next_fd++;
}
int setsockopt(int sockfd, int level, int optname, const void *optval,
               socklen_t optlen) {
  (void)sockfd;
  (void)level;
  (void)optname;
  (void)optval;
  (void)optlen;
  return 0;
}
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  (void)addrlen;
  const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
  if (bind_count < (int)(sizeof(binds) / sizeof(binds[0]))) {
    binds[bind_count].fd = sockfd;
    binds[bind_count].port = ntohs(in->sin_port);
    bind_count++;
  }
  return 0;
}
int fcntl(int fd, int cmd, ...) {
  (void)fd;
  (void)cmd;
  return 0;
}
int select(int nfds, fd_set *rfds, fd_set *wfds, fd_set *efds,
           struct timeval *tv) {
  (void)nfds;
  (void)rfds;
  (void)wfds;
  (void)efds;

  if (tv) {
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = (long)tv->tv_usec * 1000L;
    nanosleep(&ts, NULL);
  }
  return 0;
}
int close(int fd) {
  if (close_count < (int)(sizeof(closes) / sizeof(closes[0]))) {
    closes[close_count++] = fd;
  }
  return 0;
}

#include "../profile_runtime.c"

static const char *conf_path = "build/test_profiles.conf";

static void write_conf(const char *content) {
  FILE *f = fopen(conf_path, "w");
  assert(f);
  fwrite(content, 1, strlen(content), f);
  fclose(f);
}

static void test_lifecycle(void) {
  bind_count = 0;
  close_count = 0;
  next_fd = 100;
  write_conf("(defprofile a ((def port 12012) (def advertise 1)))\n"
             "(defprofile b ((def port 12013) (def advertise 1)))\n");
  config_load(conf_path, NULL, NULL, 0);
  int started = start_profile_listeners();
  assert(started == 2);
  assert(bind_count >= 2);
  assert(binds[0].port == 12012 || binds[1].port == 12012);
  assert(binds[0].port == 12013 || binds[1].port == 12013);

  write_conf("(defprofile c ((def port 12014) (def advertise 1)))\n"
             "(defprofile d ((def port 12015) (def advertise 1)))\n");
  config_load(conf_path, NULL, NULL, 0);
  reconcile_profile_listeners();
  assert(bind_count >= 4);
  int saw_12014 = 0, saw_12015 = 0;
  for (int i = 0; i < bind_count; i++) {
    if (binds[i].port == 12014)
      saw_12014 = 1;
    if (binds[i].port == 12015)
      saw_12015 = 1;
  }
  assert(saw_12014 && saw_12015);

  stop_profile_listeners();
  assert(close_count >= 2);
}

static void test_overlap(void) {
  bind_count = 0;
  close_count = 0;
  next_fd = 200;
  write_conf("(defprofile a ((def port 12020) (def advertise 1)))\n"
             "(defprofile b ((def port 12021) (def advertise 1)))\n");
  config_load(conf_path, NULL, NULL, 0);
  start_profile_listeners();
  assert(bind_count == 2);

  write_conf("(def select-timeout-usec 5000)\n"
             "(defprofile a ((def port 12020) (def advertise 1)))\n"
             "(defprofile b ((def port 12021) (def advertise 1)))\n");
  config_load(conf_path, NULL, NULL, 0);
  reconcile_profile_listeners();
  assert(bind_count == 2);
  assert(close_count == 0);

  stop_profile_listeners();
  assert(close_count == 2);
}

static void test_empty_config(void) {
  bind_count = 0;
  close_count = 0;
  next_fd = 300;
  write_conf("(defprofile a ((def port 12030) (def advertise 1)))\n");
  config_load(conf_path, NULL, NULL, 0);
  start_profile_listeners();
  assert(bind_count == 1);

  write_conf("");
  config_load(conf_path, NULL, NULL, 0);
  reconcile_profile_listeners();
  assert(close_count == 1);

  stop_profile_listeners();
}

static void test_inheritance(void) {
  bind_count = 0;
  close_count = 0;
  next_fd = 400;
  write_conf("(defprofile base ((def port 12040)))\n"
             "(defprofile child (:inherits base ((def advertise 1))))\n");
  config_load(conf_path, NULL, NULL, 0);
  start_profile_listeners();
  assert(bind_count == 1);
  assert(binds[0].port == 12040);

  const WambleProfile *p = config_find_profile("child");
  assert(p != NULL);
  assert(p->config.port == 12040);
  assert(p->advertise == 1);

  stop_profile_listeners();
  assert(close_count == 1);
}

typedef struct {
  const char *name;
  void (*func)(void);
} Case;

static const Case cases[] = {
    {"basic lifecycle", test_lifecycle},
    {"overlapping config", test_overlap},
    {"empty config", test_empty_config},
    {"inheritance", test_inheritance},
};

int main(int argc, char **argv) {
  const char *filter = (argc > 1 ? argv[1] : "");
  int pass = 0, total = 0;

  for (size_t i = 0; i < (sizeof(cases) / sizeof((cases)[0])); ++i) {
    if (*filter && !strstr(cases[i].name, filter))
      continue;

    ++total;
    cases[i].func();
    printf("%s PASSED\n", cases[i].name);
    ++pass;
  }
  printf("%d/%d passed\n", pass, total);
  return (pass == total) ? 0 : 1;
}

#endif
