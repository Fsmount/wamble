#include "common/wamble_test.h"
#include "common/wamble_test_helpers.h"
#include "wamble/wamble.h"

#include <string.h>
#if defined(WAMBLE_PLATFORM_POSIX)
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#endif

static const char *conf_path = "build/test_profiles_runtime.conf";

static int write_conf(const char *content) {
  FILE *f = fopen(conf_path, "w");
  if (!f)
    return -1;
  fwrite(content, 1, strlen(content), f);
  fclose(f);
  return 0;
}

WAMBLE_TEST(profile_start_export_and_state_files) {
  T_ASSERT_STATUS_OK(wamble_net_init());

  const char *cfg = "(defprofile alpha ((def port 19080) (def advertise 1)))\n"
                    "(defprofile beta ((def port 19081) (def advertise 1)))\n";
  T_ASSERT_EQ_INT(write_conf(cfg), 0);

  char status[128];
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));
  T_ASSERT_EQ_INT(config_profile_count(), 2);

  int started = 0;
  T_ASSERT_EQ_INT(start_profile_listeners(&started), PROFILE_START_OK);
  T_ASSERT_EQ_INT(started, 2);

  char socket_map[256];
  int exported = 0;
  T_ASSERT_EQ_INT(profile_export_inherited_sockets(
                      socket_map, sizeof(socket_map), &exported),
                  PROFILE_EXPORT_OK);
  T_ASSERT_EQ_INT(exported, started);
  T_ASSERT(strstr(socket_map, "alpha=") != NULL);
  T_ASSERT(strstr(socket_map, "beta=") != NULL);

  profile_mark_sockets_inheritable();

  char state_map[512];
  int state_count = 0;
  T_ASSERT_EQ_INT(profile_prepare_state_save_and_inherit(
                      state_map, sizeof(state_map), &state_count),
                  PROFILE_EXPORT_OK);
  T_ASSERT_EQ_INT(state_count, started);
  T_ASSERT(strstr(state_map, "alpha=") != NULL);
  T_ASSERT(strstr(state_map, "beta=") != NULL);

#if defined(WAMBLE_PLATFORM_POSIX)
  char tmp[512];
  strncpy(tmp, state_map, sizeof(tmp));
  tmp[sizeof(tmp) - 1] = '\0';
  char *saveptr = NULL;
  for (char *tok = strtok_r(tmp, ",", &saveptr); tok;
       tok = strtok_r(NULL, ",", &saveptr)) {
    char *eq = strchr(tok, '=');
    T_ASSERT(eq != NULL);
    char *path = eq + 1;
    T_ASSERT(*path);
    T_ASSERT(access(path, F_OK) == 0);
  }
#endif

  stop_profile_listeners();
  wamble_net_cleanup();
  return 0;
}

WAMBLE_TEST(profile_export_buffer_too_small) {
  T_ASSERT_STATUS_OK(wamble_net_init());

  const char *cfg = "(defprofile solo ((def port 19100) (def advertise 1)))\n";
  T_ASSERT_EQ_INT(write_conf(cfg), 0);
  char status[64];
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));
  int started = 0;
  T_ASSERT_EQ_INT(start_profile_listeners(&started), PROFILE_START_OK);
  T_ASSERT(started >= 1);

  char small[4];
  int count = 0;
  T_ASSERT_EQ_INT(
      profile_export_inherited_sockets(small, sizeof(small), &count),
      PROFILE_EXPORT_BUFFER_TOO_SMALL);
  T_ASSERT_EQ_INT(count, 0);

  char s2[8];
  int c2 = 0;
  T_ASSERT_EQ_INT(profile_prepare_state_save_and_inherit(s2, sizeof(s2), &c2),
                  PROFILE_EXPORT_BUFFER_TOO_SMALL);
  T_ASSERT_EQ_INT(c2, 0);

  stop_profile_listeners();
  wamble_net_cleanup();
  return 0;
}

WAMBLE_TEST(profile_hot_reload_state_roundtrip) {
#if defined(WAMBLE_PLATFORM_POSIX)
  T_ASSERT_STATUS_OK(wamble_net_init());

  const char *cfg = "(defprofile alpha ((def port 18080) (def advertise 1)))\n"
                    "(defprofile beta ((def port 18081) (def advertise 1)))\n";
  T_ASSERT_EQ_INT(write_conf(cfg), 0);

  char status[128];
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));
  T_ASSERT_EQ_INT(config_profile_count(), 2);

  int pair_alpha[2];
  int pair_beta[2];
  T_ASSERT_EQ_INT(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair_alpha), 0);
  T_ASSERT_EQ_INT(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair_beta), 0);
  wamble_socket_t sock_alpha = (wamble_socket_t)pair_alpha[0];
  wamble_socket_t sock_beta = (wamble_socket_t)pair_beta[0];

  char inherited_env[128];
  snprintf(inherited_env, sizeof(inherited_env), "alpha=%d,beta=%d",
           (int)sock_alpha, (int)sock_beta);
  T_ASSERT_EQ_INT(setenv("WAMBLE_PROFILES_INHERITED", inherited_env, 1), 0);

  int started = 0;
  T_ASSERT_EQ_INT(start_profile_listeners(&started), PROFILE_START_OK);
  T_ASSERT_EQ_INT(started, 2);

  unsetenv("WAMBLE_PROFILES_INHERITED");

  struct timespec wait = {.tv_sec = 0, .tv_nsec = 50 * 1000 * 1000};
  nanosleep(&wait, NULL);

  char socket_map[256];
  int exported = 0;
  T_ASSERT_EQ_INT(profile_export_inherited_sockets(
                      socket_map, sizeof(socket_map), &exported),
                  PROFILE_EXPORT_OK);
  T_ASSERT_EQ_INT(exported, started);
  T_ASSERT(strstr(socket_map, "alpha=") != NULL);
  T_ASSERT(strstr(socket_map, "beta=") != NULL);

  profile_mark_sockets_inheritable();

  char state_map[512];
  int state_count = 0;
  T_ASSERT_EQ_INT(profile_prepare_state_save_and_inherit(
                      state_map, sizeof(state_map), &state_count),
                  PROFILE_EXPORT_OK);
  T_ASSERT_EQ_INT(state_count, started);
  T_ASSERT(strstr(state_map, "alpha=") != NULL);
  T_ASSERT(strstr(state_map, "beta=") != NULL);

  char tmp[512];
  strncpy(tmp, state_map, sizeof(tmp));
  tmp[sizeof(tmp) - 1] = '\0';
  char *saveptr = NULL;
  for (char *tok = strtok_r(tmp, ",", &saveptr); tok;
       tok = strtok_r(NULL, ",", &saveptr)) {
    char *eq = strchr(tok, '=');
    T_ASSERT(eq != NULL);
    char *path = eq + 1;
    T_ASSERT(*path);
    T_ASSERT(access(path, F_OK) == 0);
  }

  stop_profile_listeners();

  board_manager_init();
  strncpy(tmp, state_map, sizeof(tmp));
  tmp[sizeof(tmp) - 1] = '\0';
  saveptr = NULL;
  for (char *tok = strtok_r(tmp, ",", &saveptr); tok;
       tok = strtok_r(NULL, ",", &saveptr)) {
    char *eq = strchr(tok, '=');
    T_ASSERT(eq != NULL);
    char *path = eq + 1;
    T_ASSERT(*path);
    T_ASSERT_STATUS_OK(state_load_from_file(path));
  }

  strncpy(tmp, state_map, sizeof(tmp));
  tmp[sizeof(tmp) - 1] = '\0';
  saveptr = NULL;
  for (char *tok = strtok_r(tmp, ",", &saveptr); tok;
       tok = strtok_r(NULL, ",", &saveptr)) {
    char *eq = strchr(tok, '=');
    if (!eq)
      continue;
    char *path = eq + 1;
    if (*path)
      wamble_unlink(path);
  }

  wamble_close_socket((wamble_socket_t)pair_alpha[1]);
  wamble_close_socket((wamble_socket_t)pair_beta[1]);

  wamble_net_cleanup();
#endif
  return 0;
}

WAMBLE_TEST(profile_config_inheritance_child_uses_base_port) {
  const char *cfg = "(defprofile base ((def port 19200)))\n"
                    "(defprofile child (:inherits base ((def advertise 1))))\n";
  T_ASSERT_EQ_INT(write_conf(cfg), 0);
  char status[64];
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));
  const WambleProfile *p = config_find_profile("child");
  T_ASSERT(p != NULL);
  T_ASSERT_EQ_INT(p->config.port, 19200);
  return 0;
}

WAMBLE_TEST(profile_single_listener_runs_inline) {
  T_ASSERT_STATUS_OK(wamble_net_init());
  const char *cfg = "(defprofile solo ((def port 19300) (def advertise 1)))\n";
  T_ASSERT_EQ_INT(write_conf(cfg), 0);
  char status[64];
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));
  int started = 0;
  T_ASSERT_EQ_INT(start_profile_listeners(&started), PROFILE_START_OK);
  T_ASSERT_EQ_INT(started, 1);
  T_ASSERT_EQ_INT(profile_runtime_pump_inline(), 1);
  stop_profile_listeners();
  wamble_net_cleanup();
  return 0;
}

WAMBLE_TEST(profile_multi_listener_not_inline) {
  T_ASSERT_STATUS_OK(wamble_net_init());
  const char *cfg = "(defprofile alpha ((def port 19310) (def advertise 1)))\n"
                    "(defprofile beta ((def port 19311) (def advertise 1)))\n";
  T_ASSERT_EQ_INT(write_conf(cfg), 0);
  char status[64];
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));
  int started = 0;
  T_ASSERT_EQ_INT(start_profile_listeners(&started), PROFILE_START_OK);
  T_ASSERT_EQ_INT(started, 2);
  T_ASSERT_EQ_INT(profile_runtime_pump_inline(), 0);
  stop_profile_listeners();
  wamble_net_cleanup();
  return 0;
}

WAMBLE_TESTS_BEGIN_NAMED(profile_runtime_tests) {
  WAMBLE_TESTS_ADD_FM(profile_start_export_and_state_files, "profile_runtime");
  WAMBLE_TESTS_ADD_FM(profile_export_buffer_too_small, "profile_runtime");
  WAMBLE_TESTS_ADD_FM(profile_hot_reload_state_roundtrip, "profile_runtime");
  WAMBLE_TESTS_ADD_FM(profile_config_inheritance_child_uses_base_port,
                      "profile_runtime");
  WAMBLE_TESTS_ADD_FM(profile_single_listener_runs_inline, "profile_runtime");
  WAMBLE_TESTS_ADD_FM(profile_multi_listener_not_inline, "profile_runtime");
}
WAMBLE_TESTS_END()
