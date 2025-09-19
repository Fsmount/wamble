#include "../../include/wamble/wamble.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifdef WAMBLE_PLATFORM_POSIX
#include <time.h>
#include <unistd.h>
#endif

void handle_message(int sockfd, const struct WambleMsg *msg,
                    const struct sockaddr_in *cliaddr) {
  (void)sockfd;
  (void)msg;
  (void)cliaddr;
}

static const char *conf_path = "build/test_profiles_hot.conf";

static void write_conf(const char *content) {
  FILE *f = fopen(conf_path, "w");
  assert(f);
  fwrite(content, 1, strlen(content), f);
  fclose(f);
}

#ifdef WAMBLE_PLATFORM_POSIX
static void unlink_state_files(const char *state_map) {
  if (!state_map || !*state_map)
    return;
  char buf[512];
  strncpy(buf, state_map, sizeof(buf));
  buf[sizeof(buf) - 1] = '\0';
  char *saveptr = NULL;
  for (char *tok = strtok_r(buf, ",", &saveptr); tok;
       tok = strtok_r(NULL, ",", &saveptr)) {
    char *eq = strchr(tok, '=');
    if (!eq)
      continue;
    char *path = eq + 1;
    if (*path)
      wamble_unlink(path);
  }
}
#endif

int main(void) {
#ifndef WAMBLE_PLATFORM_POSIX
  printf("hot reload integration test skipped on non-POSIX platform\n");
  return 0;
#else
  const char *cfg = "(defprofile alpha ((def port 18080) (def advertise 1)))\n"
                    "(defprofile beta ((def port 18081) (def advertise 1)))\n";
  write_conf(cfg);

  int net_rc = wamble_net_init();
  assert(net_rc == 0);

  char status[128];
  ConfigLoadStatus cfg_status =
      config_load(conf_path, NULL, status, sizeof(status));
  assert(cfg_status == CONFIG_LOAD_OK);

  assert(db_init("integration-test") == 0);
  SpectatorInitStatus sst = spectator_manager_init();
  assert(sst == SPECTATOR_INIT_OK);

  int pair_alpha[2];
  int pair_beta[2];
  assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair_alpha) == 0);
  assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair_beta) == 0);
  wamble_socket_t sock_alpha = pair_alpha[0];
  wamble_socket_t sock_beta = pair_beta[0];

  char inherited_env[128];
  snprintf(inherited_env, sizeof(inherited_env), "alpha=%d,beta=%d",
           (int)sock_alpha, (int)sock_beta);
  setenv("WAMBLE_PROFILES_INHERITED", inherited_env, 1);

  int total_profiles = config_profile_count();
  assert(total_profiles == 2);

  int started = 0;
  ProfileStartStatus pst = start_profile_listeners(&started);
  if (pst != PROFILE_START_OK) {
    printf("start_profile_listeners status=%d\n", pst);
    fflush(stdout);
    unsetenv("WAMBLE_PROFILES_INHERITED");
    wamble_close_socket(sock_alpha);
    wamble_close_socket(sock_beta);
    wamble_close_socket(pair_alpha[1]);
    wamble_close_socket(pair_beta[1]);
    return 1;
  }
  assert(started == 2);
  printf("[hot_reload] started profiles=%d\n", started);
  fflush(stdout);

  unsetenv("WAMBLE_PROFILES_INHERITED");

  struct timespec wait = {.tv_sec = 0, .tv_nsec = 50 * 1000 * 1000};
  nanosleep(&wait, NULL);

  char socket_map[256];
  int exported = 0;
  ProfileExportStatus sock_status = profile_export_inherited_sockets(
      socket_map, sizeof(socket_map), &exported);
  assert(sock_status == PROFILE_EXPORT_OK);
  assert(exported == started);
  printf("[hot_reload] exported sockets=%d map=%s\n", exported, socket_map);
  fflush(stdout);
  assert(strstr(socket_map, "alpha=") != NULL);
  assert(strstr(socket_map, "beta=") != NULL);

  profile_mark_sockets_inheritable();
  printf("[hot_reload] marked sockets inheritable\n");
  fflush(stdout);

  char state_map[512];
  int state_count = 0;
  ProfileExportStatus state_status = profile_prepare_state_save_and_inherit(
      state_map, sizeof(state_map), &state_count);
  assert(state_status == PROFILE_EXPORT_OK);
  assert(state_count == started);
  printf("[hot_reload] prepared state files count=%d map=%s\n", state_count,
         state_map);
  fflush(stdout);
  assert(strstr(state_map, "alpha=") != NULL);
  assert(strstr(state_map, "beta=") != NULL);

  char tmp[512];
  strncpy(tmp, state_map, sizeof(tmp));
  tmp[sizeof(tmp) - 1] = '\0';
  char *saveptr = NULL;
  for (char *tok = strtok_r(tmp, ",", &saveptr); tok;
       tok = strtok_r(NULL, ",", &saveptr)) {
    char *eq = strchr(tok, '=');
    assert(eq);
    char *path = eq + 1;
    assert(*path);
    assert(access(path, F_OK) == 0);
  }

  stop_profile_listeners();

  board_manager_init();
  strncpy(tmp, state_map, sizeof(tmp));
  tmp[sizeof(tmp) - 1] = '\0';
  saveptr = NULL;
  for (char *tok = strtok_r(tmp, ",", &saveptr); tok;
       tok = strtok_r(NULL, ",", &saveptr)) {
    char *eq = strchr(tok, '=');
    assert(eq);
    char *path = eq + 1;
    assert(*path);
    int rc = state_load_from_file(path);
    assert(rc == 0);
  }

  unlink_state_files(state_map);

  wamble_close_socket(pair_alpha[1]);
  wamble_close_socket(pair_beta[1]);
  spectator_manager_shutdown();
  db_cleanup();
  wamble_net_cleanup();

  wamble_unlink(conf_path);

  return 0;
#endif
}
