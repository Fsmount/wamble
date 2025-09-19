#ifdef TEST_PROFILE_RUNTIME

#include <assert.h>
#include <pthread.h>
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

static void clear_manual_profiles(void) {
  ensure_mutex_init();
  wamble_mutex_lock(&g_mutex);
  RunningProfile *profiles = g_running;
  int count = g_running_count;
  g_running = NULL;
  g_running_count = 0;
  g_prepare_exec = 0;
  wamble_mutex_unlock(&g_mutex);
  if (!profiles)
    return;
  for (int i = 0; i < count; i++) {
    free(profiles[i].name);
    free(profiles[i].state_path);
  }
  free(profiles);
}

static void install_manual_profiles(int count, char **names, char **states) {
  clear_manual_profiles();
  ensure_mutex_init();
  wamble_mutex_lock(&g_mutex);
  g_running = calloc((size_t)count, sizeof(RunningProfile));
  g_running_count = count;
  for (int i = 0; i < count; i++) {
    g_running[i].name = strdup(names[i]);
    g_running[i].sockfd = (wamble_socket_t)(100 + i);
    g_running[i].state_path = states ? strdup(states[i]) : NULL;
    g_running[i].ready_for_exec = 1;
  }
  g_prepare_exec = 0;
  wamble_mutex_unlock(&g_mutex);
}

static void *ready_marker_thread(void *arg) {
  (void)arg;
  for (int i = 0; i < 200; i++) {
    if (g_prepare_exec) {
      wamble_mutex_lock(&g_mutex);
      for (int j = 0; j < g_running_count; j++) {
        g_running[j].ready_for_exec = 1;
      }
      wamble_mutex_unlock(&g_mutex);
      break;
    }
    usleep(1000);
  }
  return NULL;
}

static void test_lifecycle(void) {
  bind_count = 0;
  close_count = 0;
  next_fd = 100;
  write_conf("(defprofile a ((def port 12012) (def advertise 1)))\n"
             "(defprofile b ((def port 12013) (def advertise 1)))\n");
  config_load(conf_path, NULL, NULL, 0);
  int started = 0;
  ProfileStartStatus pst = start_profile_listeners(&started);
  assert(pst == PROFILE_START_OK);
  assert(started == 2);
  assert(bind_count >= 2);
  assert(binds[0].port == 12012 || binds[1].port == 12012);
  assert(binds[0].port == 12013 || binds[1].port == 12013);

  write_conf("(defprofile c ((def port 12014) (def advertise 1)))\n"
             "(defprofile d ((def port 12015) (def advertise 1)))\n");
  config_load(conf_path, NULL, NULL, 0);
  {
    ProfileStartStatus r = reconcile_profile_listeners();
    assert(r == PROFILE_START_OK);
  }
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
  int started = 0;
  ProfileStartStatus pst = start_profile_listeners(&started);
  assert(pst == PROFILE_START_OK);
  assert(bind_count == 2);

  write_conf("(def select-timeout-usec 5000)\n"
             "(defprofile a ((def port 12020) (def advertise 1)))\n"
             "(defprofile b ((def port 12021) (def advertise 1)))\n");
  config_load(conf_path, NULL, NULL, 0);
  {
    ProfileStartStatus r = reconcile_profile_listeners();
    assert(r == PROFILE_START_OK);
  }
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
  int started = 0;
  ProfileStartStatus pst = start_profile_listeners(&started);
  assert(pst == PROFILE_START_OK);
  assert(bind_count == 1);

  write_conf("");
  config_load(conf_path, NULL, NULL, 0);
  {
    ProfileStartStatus r = reconcile_profile_listeners();
    assert(r == PROFILE_START_NONE || r == PROFILE_START_OK);
  }
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
  int started = 0;
  ProfileStartStatus pst = start_profile_listeners(&started);
  assert(pst == PROFILE_START_OK);
  assert(bind_count == 1);
  assert(binds[0].port == 12040);

  const WambleProfile *p = config_find_profile("child");
  assert(p != NULL);
  assert(p->config.port == 12040);
  assert(p->advertise == 1);

  stop_profile_listeners();
  assert(close_count == 1);
}

static void test_export_many_profiles(void) {
  stop_profile_listeners();
  const int count = 32;
  char **names = calloc((size_t)count, sizeof(char *));
  char **states = calloc((size_t)count, sizeof(char *));
  assert(names && states);
  for (int i = 0; i < count; i++) {
    char name_buf[32];
    char state_buf[32];
    snprintf(name_buf, sizeof(name_buf), "prof_%02d", i);
    snprintf(state_buf, sizeof(state_buf), "/tmp/state_%02d", i);
    names[i] = strdup(name_buf);
    states[i] = strdup(state_buf);
    assert(names[i] && states[i]);
  }

  install_manual_profiles(count, names, states);

  char small[64];
  int small_count = 0;
  ProfileExportStatus rc =
      profile_export_inherited_sockets(small, sizeof(small), &small_count);
  assert(rc == PROFILE_EXPORT_BUFFER_TOO_SMALL);
  assert(small_count == 0);
  assert(strlen(small) < sizeof(small));

  pthread_t ready;
  assert(pthread_create(&ready, NULL, ready_marker_thread, NULL) == 0);
  char state_small[64];
  int small_state_count = 0;
  ProfileExportStatus state_rc = profile_prepare_state_save_and_inherit(
      state_small, sizeof(state_small), &small_state_count);
  assert(pthread_join(ready, NULL) == 0);
  assert(state_rc == PROFILE_EXPORT_BUFFER_TOO_SMALL);
  assert(small_state_count == 0);

  char large[4096];
  int large_count = 0;
  ProfileExportStatus ok =
      profile_export_inherited_sockets(large, sizeof(large), &large_count);
  assert(ok == PROFILE_EXPORT_OK);
  assert(large_count == count);
  char expect_last[32];
  snprintf(expect_last, sizeof(expect_last), "prof_%02d=", count - 1);
  assert(strstr(large, expect_last) != NULL);

  assert(pthread_create(&ready, NULL, ready_marker_thread, NULL) == 0);
  char state_large[4096];
  int large_state_count = 0;
  ProfileExportStatus ok_state = profile_prepare_state_save_and_inherit(
      state_large, sizeof(state_large), &large_state_count);
  assert(pthread_join(ready, NULL) == 0);
  assert(ok_state == PROFILE_EXPORT_OK);
  assert(large_state_count == count);
  snprintf(expect_last, sizeof(expect_last), "state_%02d", count - 1);
  assert(strstr(state_large, expect_last) != NULL);

  clear_manual_profiles();
  for (int i = 0; i < count; i++) {
    free(names[i]);
    free(states[i]);
  }
  free(names);
  free(states);
}

static void test_export_long_names(void) {
  stop_profile_listeners();

  const int count = 2;
  char **names = calloc((size_t)count, sizeof(char *));
  char **states = calloc((size_t)count, sizeof(char *));
  assert(names && states);

  const char *base =
      "profile_with_a_very_long_name_exercising_hot_reload_behavior_";
  const char *state_base =
      "/tmp/state_with_a_surprisingly_verbose_file_name_for_testing_";

  for (int i = 0; i < count; i++) {
    char name_buf[256];
    char state_buf[256];
    snprintf(name_buf, sizeof(name_buf), "%s%02d", base, i);
    snprintf(state_buf, sizeof(state_buf), "%s%02d", state_base, i);
    names[i] = strdup(name_buf);
    states[i] = strdup(state_buf);
    assert(names[i] && states[i]);
  }

  install_manual_profiles(count, names, states);

  char tight[64];
  int tight_count = 0;
  ProfileExportStatus tight_rc =
      profile_export_inherited_sockets(tight, sizeof(tight), &tight_count);
  assert(tight_rc == PROFILE_EXPORT_BUFFER_TOO_SMALL);
  assert(tight_count == 0);

  char buf[2048];
  int ok_count = 0;
  ProfileExportStatus ok =
      profile_export_inherited_sockets(buf, sizeof(buf), &ok_count);
  assert(ok == PROFILE_EXPORT_OK);
  assert(ok_count == count);
  assert(strstr(buf, base) != NULL);

  pthread_t ready;
  assert(pthread_create(&ready, NULL, ready_marker_thread, NULL) == 0);
  char state_buf_out[2048];
  int state_count = 0;
  ProfileExportStatus state_ok = profile_prepare_state_save_and_inherit(
      state_buf_out, sizeof(state_buf_out), &state_count);
  assert(pthread_join(ready, NULL) == 0);
  assert(state_ok == PROFILE_EXPORT_OK);
  assert(state_count == count);
  assert(strstr(state_buf_out, state_base) != NULL);

  clear_manual_profiles();
  for (int i = 0; i < count; i++) {
    free(names[i]);
    free(states[i]);
  }
  free(names);
  free(states);
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
    {"export many profiles", test_export_many_profiles},
    {"export long names", test_export_long_names},
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
