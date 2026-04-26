#include "common/wamble_test.h"
#include "common/wamble_test_helpers.h"
#include "wamble/wamble.h"
#include "wamble/wamble_db.h"

#include <string.h>
#if defined(WAMBLE_PLATFORM_POSIX)
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#endif

static const char *conf_path = "build/test_profiles_runtime.conf";
static int g_profile_runtime_net_active = 0;
static wamble_socket_t g_profile_runtime_tracked_sockets[8];
static int g_profile_runtime_tracked_socket_count = 0;
static char g_profile_runtime_tracked_files[16][512];
static int g_profile_runtime_tracked_file_count = 0;

static void profile_test_track_state_files(const char *state_map) {
  if (!state_map || !*state_map)
    return;
  const char *cursor = state_map;
  while (*cursor) {
    const char *entry_end = strchr(cursor, ',');
    size_t entry_len =
        entry_end ? (size_t)(entry_end - cursor) : strlen(cursor);
    const char *eq = memchr(cursor, '=', entry_len);
    if (!eq || !eq[1])
      goto next_entry;
    if (g_profile_runtime_tracked_file_count >=
        (int)(sizeof(g_profile_runtime_tracked_files) /
              sizeof(g_profile_runtime_tracked_files[0]))) {
      return;
    }
    size_t path_len = entry_len - (size_t)(eq - cursor) - 1;
    snprintf(
        g_profile_runtime_tracked_files[g_profile_runtime_tracked_file_count++],
        sizeof(g_profile_runtime_tracked_files[0]), "%.*s", (int)path_len,
        eq + 1);
  next_entry:
    if (!entry_end)
      break;
    cursor = entry_end + 1;
  }
}

static void profile_test_setup(void) {
  g_profile_runtime_net_active = 0;
  g_profile_runtime_tracked_socket_count = 0;
  g_profile_runtime_tracked_file_count = 0;
#if defined(WAMBLE_PLATFORM_POSIX)
  unsetenv("WAMBLE_PROFILES_INHERITED");
  unsetenv("WAMBLE_STATE_FILES");
#endif
}

static void profile_test_teardown(void) {
  stop_profile_listeners();
  for (int i = 0; i < g_profile_runtime_tracked_file_count; i++) {
    if (g_profile_runtime_tracked_files[i][0] != '\0')
      wamble_unlink(g_profile_runtime_tracked_files[i]);
  }
  for (int i = 0; i < g_profile_runtime_tracked_socket_count; i++) {
    if (g_profile_runtime_tracked_sockets[i] != WAMBLE_INVALID_SOCKET)
      wamble_close_socket(g_profile_runtime_tracked_sockets[i]);
  }
#if defined(WAMBLE_PLATFORM_POSIX)
  unsetenv("WAMBLE_PROFILES_INHERITED");
  unsetenv("WAMBLE_STATE_FILES");
#endif
  if (g_profile_runtime_net_active) {
    wamble_net_cleanup();
    g_profile_runtime_net_active = 0;
  }
}

WAMBLE_TEST(profile_start_export_and_state_files) {
  g_profile_runtime_net_active = 1;
  T_ASSERT_STATUS_OK(wamble_net_init());

  const char *cfg = "(defprofile alpha ((def port 19080) (def advertise 1)))\n"
                    "(defprofile beta ((def port 19081) (def advertise 1)))\n";
  T_ASSERT_EQ_INT(wamble_test_write_optional_db_config_file(conf_path, cfg), 0);

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

  char state_map[512];
  int state_count = 0;
  T_ASSERT_EQ_INT(profile_prepare_state_save_and_inherit(
                      state_map, sizeof(state_map), &state_count),
                  PROFILE_EXPORT_OK);
  T_ASSERT_EQ_INT(state_count, started);
  T_ASSERT(strstr(state_map, "alpha=") != NULL);
  T_ASSERT(strstr(state_map, "beta=") != NULL);
  profile_test_track_state_files(state_map);

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

  return 0;
}

WAMBLE_TEST(profile_state_dir_used_for_exec_snapshots) {
#if defined(WAMBLE_PLATFORM_POSIX)
  g_profile_runtime_net_active = 1;
  T_ASSERT_STATUS_OK(wamble_net_init());

  char state_dir[512];
  T_ASSERT_EQ_INT(wamble_test_path(state_dir, sizeof(state_dir),
                                   "profile_runtime", "state_dir_snapshots"),
                  0);
  T_ASSERT_EQ_INT(wamble_test_ensure_dir(state_dir), 0);

  char cfg[1024];
  snprintf(cfg, sizeof(cfg),
           "(def state-dir \"%s\")\n"
           "(defprofile alpha ((def port 19090) (def advertise 1)))\n",
           state_dir);
  T_ASSERT_EQ_INT(wamble_test_write_optional_db_config_file(conf_path, cfg), 0);

  char status[128];
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));

  int started = 0;
  T_ASSERT_EQ_INT(start_profile_listeners(&started), PROFILE_START_OK);
  T_ASSERT_EQ_INT(started, 1);

  char state_map[512];
  int state_count = 0;
  T_ASSERT_EQ_INT(profile_prepare_state_save_and_inherit(
                      state_map, sizeof(state_map), &state_count),
                  PROFILE_EXPORT_OK);
  T_ASSERT_EQ_INT(state_count, 1);
  T_ASSERT(strstr(state_map, state_dir) != NULL);
  profile_test_track_state_files(state_map);

  char tmp[512];
  strncpy(tmp, state_map, sizeof(tmp));
  tmp[sizeof(tmp) - 1] = '\0';
  char *eq = strchr(tmp, '=');
  T_ASSERT(eq != NULL);
  char *path = eq + 1;
  T_ASSERT(strncmp(path, state_dir, strlen(state_dir)) == 0);

#endif
  return 0;
}

WAMBLE_TEST(profile_export_buffer_too_small) {
  g_profile_runtime_net_active = 1;
  T_ASSERT_STATUS_OK(wamble_net_init());

  const char *cfg = "(defprofile solo ((def port 19100) (def advertise 1)))\n";
  T_ASSERT_EQ_INT(wamble_test_write_optional_db_config_file(conf_path, cfg), 0);
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

  return 0;
}

WAMBLE_TEST(profile_hot_reload_state_roundtrip) {
#if defined(WAMBLE_PLATFORM_POSIX)
  g_profile_runtime_net_active = 1;
  T_ASSERT_STATUS_OK(wamble_net_init());

  const char *cfg = "(defprofile alpha ((def port 18080) (def advertise 1)))\n"
                    "(defprofile beta ((def port 18081) (def advertise 1)))\n";
  T_ASSERT_EQ_INT(wamble_test_write_optional_db_config_file(conf_path, cfg), 0);

  char status[128];
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));
  T_ASSERT_EQ_INT(config_profile_count(), 2);

  int pair_alpha[2];
  int pair_beta[2];
  T_ASSERT_EQ_INT(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair_alpha), 0);
  T_ASSERT_EQ_INT(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair_beta), 0);
  wamble_socket_t sock_alpha = (wamble_socket_t)pair_alpha[0];
  wamble_socket_t sock_beta = (wamble_socket_t)pair_beta[0];
  if (g_profile_runtime_tracked_socket_count < 8)
    g_profile_runtime_tracked_sockets
        [g_profile_runtime_tracked_socket_count++] =
            (wamble_socket_t)pair_alpha[1];
  if (g_profile_runtime_tracked_socket_count < 8)
    g_profile_runtime_tracked_sockets
        [g_profile_runtime_tracked_socket_count++] =
            (wamble_socket_t)pair_beta[1];

  char inherited_env[128];
  snprintf(inherited_env, sizeof(inherited_env), "alpha=%d,beta=%d",
           (int)sock_alpha, (int)sock_beta);
  T_ASSERT_EQ_INT(setenv("WAMBLE_PROFILES_INHERITED", inherited_env, 1), 0);

  int started = 0;
  T_ASSERT_EQ_INT(start_profile_listeners(&started), PROFILE_START_OK);
  T_ASSERT_EQ_INT(started, 2);

  unsetenv("WAMBLE_PROFILES_INHERITED");

  wamble_sleep_ms(50);

  char socket_map[256];
  int exported = 0;
  T_ASSERT_EQ_INT(profile_export_inherited_sockets(
                      socket_map, sizeof(socket_map), &exported),
                  PROFILE_EXPORT_OK);
  T_ASSERT_EQ_INT(exported, started);
  T_ASSERT(strstr(socket_map, "alpha=") != NULL);
  T_ASSERT(strstr(socket_map, "beta=") != NULL);

  char state_map[512];
  int state_count = 0;
  T_ASSERT_EQ_INT(profile_prepare_state_save_and_inherit(
                      state_map, sizeof(state_map), &state_count),
                  PROFILE_EXPORT_OK);
  T_ASSERT_EQ_INT(state_count, started);
  T_ASSERT(strstr(state_map, "alpha=") != NULL);
  T_ASSERT(strstr(state_map, "beta=") != NULL);
  profile_test_track_state_files(state_map);

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

#endif
  return 0;
}

WAMBLE_TEST(default_runtime_hot_reload_exports_socket_and_state) {
#if defined(WAMBLE_PLATFORM_POSIX)
  g_profile_runtime_net_active = 1;
  T_ASSERT_STATUS_OK(wamble_net_init());

  const char *cfg = "(def port 0)\n";
  T_ASSERT_EQ_INT(wamble_test_write_optional_db_config_file(conf_path, cfg), 0);

  char status[128];
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));

  int started = 0;
  T_ASSERT_EQ_INT(start_profile_listeners(&started), PROFILE_START_OK);
  T_ASSERT_EQ_INT(started, 1);
  T_ASSERT_EQ_INT(profile_runtime_pump_inline(), 1);

  char socket_map[256];
  int exported = 0;
  T_ASSERT_EQ_INT(profile_export_inherited_sockets(
                      socket_map, sizeof(socket_map), &exported),
                  PROFILE_EXPORT_OK);
  T_ASSERT_EQ_INT(exported, 1);
  T_ASSERT(strstr(socket_map, "__wamble_default_runtime__=") != NULL);

  char state_map[512];
  int state_count = 0;
  T_ASSERT_EQ_INT(profile_prepare_state_save_and_inherit(
                      state_map, sizeof(state_map), &state_count),
                  PROFILE_EXPORT_OK);
  T_ASSERT_EQ_INT(state_count, 1);
  T_ASSERT(strstr(state_map, "__wamble_default_runtime__=") != NULL);
  profile_test_track_state_files(state_map);
#endif
  return 0;
}

WAMBLE_TEST(profile_exec_snapshot_flushes_pending_create_session_intent) {
#if defined(WAMBLE_PLATFORM_POSIX)
  if (!wamble_db_available())
    T_FAIL_SIMPLE("db not available");
  if (test_db_apply_migrations(NULL) != 0)
    T_FAIL_SIMPLE("test_db_apply_migrations failed");
  if (test_db_reset(NULL) != 0)
    T_FAIL_SIMPLE("test_db_reset failed");
  if (wamble_test_write_optional_db_config_file(conf_path, "(def port 0)\n") !=
      0)
    T_FAIL_SIMPLE("write config failed");
  if (config_load(conf_path, NULL, NULL, 0) < 0)
    T_FAIL_SIMPLE("config_load failed");
  if (db_set_global_store_connection(NULL) != 0)
    T_FAIL_SIMPLE("db_set_global_store_connection failed");
  if (db_init(NULL) != 0)
    T_FAIL_SIMPLE("db_init failed");
  wamble_set_query_service(wamble_get_db_query_service());

  g_profile_runtime_net_active = 1;
  T_ASSERT_STATUS_OK(wamble_net_init());

  const char *cfg = "(def port 0)\n";
  T_ASSERT_EQ_INT(wamble_test_write_optional_db_config_file(conf_path, cfg), 0);

  char status[128];
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));

  int started = 0;
  T_ASSERT_EQ_INT(start_profile_listeners(&started), PROFILE_START_OK);
  T_ASSERT_EQ_INT(started, 1);
  T_ASSERT_EQ_INT(profile_runtime_pump_inline(), 1);

  WamblePlayer *player = create_new_player();
  T_ASSERT(player != NULL);

  char state_map[512];
  int state_count = 0;
  T_ASSERT_EQ_INT(profile_prepare_state_save_and_inherit(
                      state_map, sizeof(state_map), &state_count),
                  PROFILE_EXPORT_OK);
  T_ASSERT_EQ_INT(state_count, 1);
  profile_test_track_state_files(state_map);

  db_cleanup_thread();
  uint64_t session_id = 0;
  T_ASSERT_STATUS(wamble_query_get_session_by_token(player->token, &session_id),
                  DB_OK);
  T_ASSERT(session_id > 0);
#endif
  return 0;
}

WAMBLE_TEST(profile_exec_snapshot_blocks_while_reservation_in_flight) {
#if defined(WAMBLE_PLATFORM_POSIX)
  g_profile_runtime_net_active = 1;
  T_ASSERT_STATUS_OK(wamble_net_init());

  const char *cfg = "(def port 0)\n";
  T_ASSERT_EQ_INT(wamble_test_write_optional_db_config_file(conf_path, cfg), 0);

  char status[128];
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));

  int started = 0;
  T_ASSERT_EQ_INT(start_profile_listeners(&started), PROFILE_START_OK);
  T_ASSERT_EQ_INT(started, 1);
  T_ASSERT_EQ_INT(profile_runtime_pump_inline(), 1);

  char state_map[512];
  int state_count = 0;
  T_ASSERT_EQ_INT(profile_prepare_state_save_and_inherit(
                      state_map, sizeof(state_map), &state_count),
                  PROFILE_EXPORT_OK);
  T_ASSERT_EQ_INT(state_count, 1);
  profile_test_track_state_files(state_map);

  WamblePlayer *player = create_new_player();
  T_ASSERT(player != NULL);
  WambleBoard *board = find_board_for_player(player);
  T_ASSERT(board != NULL);
  T_ASSERT(board_manager_count_active_or_reserved() > 0);

  state_count = 0;
  T_ASSERT_EQ_INT(profile_prepare_state_save_and_inherit(
                      state_map, sizeof(state_map), &state_count),
                  PROFILE_EXPORT_NOT_READY);
  T_ASSERT_EQ_INT(state_count, 0);
#endif
  return 0;
}

WAMBLE_TEST(profile_config_inheritance_child_uses_base_port) {
  const char *cfg = "(defprofile base ((def port 19200)))\n"
                    "(defprofile child (:inherits base ((def advertise 1))))\n";
  T_ASSERT_EQ_INT(wamble_test_write_optional_db_config_file(conf_path, cfg), 0);
  char status[64];
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));
  const WambleProfile *p = config_find_profile("child");
  T_ASSERT(p != NULL);
  T_ASSERT_EQ_INT(p->config.port, 19200);
  return 0;
}

WAMBLE_TEST(profile_single_listener_runs_inline) {
  g_profile_runtime_net_active = 1;
  T_ASSERT_STATUS_OK(wamble_net_init());
  const char *cfg = "(defprofile solo ((def port 19300) (def advertise 1)))\n";
  T_ASSERT_EQ_INT(wamble_test_write_optional_db_config_file(conf_path, cfg), 0);
  char status[64];
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));
  int started = 0;
  T_ASSERT_EQ_INT(start_profile_listeners(&started), PROFILE_START_OK);
  T_ASSERT_EQ_INT(started, 1);
  T_ASSERT_EQ_INT(profile_runtime_pump_inline(), 1);
  return 0;
}

WAMBLE_TEST(profile_multi_listener_not_inline) {
  g_profile_runtime_net_active = 1;
  T_ASSERT_STATUS_OK(wamble_net_init());
  const char *cfg = "(defprofile alpha ((def port 19310) (def advertise 1)))\n"
                    "(defprofile beta ((def port 19311) (def advertise 1)))\n";
  T_ASSERT_EQ_INT(wamble_test_write_optional_db_config_file(conf_path, cfg), 0);
  char status[64];
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));
  int started = 0;
  T_ASSERT_EQ_INT(start_profile_listeners(&started), PROFILE_START_OK);
  T_ASSERT_EQ_INT(started, 2);
  T_ASSERT_EQ_INT(profile_runtime_pump_inline(), 0);
  return 0;
}

WAMBLE_TEST(profile_hidden_listener_enabled_by_discover_override_rule) {
  g_profile_runtime_net_active = 1;
  T_ASSERT_STATUS_OK(wamble_net_init());
  const char *cfg =
      "(defprofile hidden ((def port 19320) (def advertise 0)))\n"
      "(policy-allow \"*\" \"profile.discover.override\" \"profile:hidden\" 1 "
      "\"enable hidden listener\")\n";
  T_ASSERT_EQ_INT(wamble_test_write_optional_db_config_file(conf_path, cfg), 0);
  char status[128];
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));
  int started = 0;
  T_ASSERT_EQ_INT(start_profile_listeners(&started), PROFILE_START_OK);
  T_ASSERT_EQ_INT(started, 1);
  return 0;
}

WAMBLE_TEST(profile_non_socket_reload_keeps_listener_socket) {
  g_profile_runtime_net_active = 1;
  T_ASSERT_STATUS_OK(wamble_net_init());

  const char *cfg_a = "(defprofile alpha ((def port 19330) (def advertise 1) "
                      "(def spectator-visibility 0)))\n";
  T_ASSERT_EQ_INT(wamble_test_write_optional_db_config_file(conf_path, cfg_a),
                  0);

  char status[128];
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));

  int started = 0;
  T_ASSERT_EQ_INT(start_profile_listeners(&started), PROFILE_START_OK);
  T_ASSERT_EQ_INT(started, 1);

  char socket_map_before[256];
  int exported_before = 0;
  T_ASSERT_EQ_INT(profile_export_inherited_sockets(socket_map_before,
                                                   sizeof(socket_map_before),
                                                   &exported_before),
                  PROFILE_EXPORT_OK);
  T_ASSERT_EQ_INT(exported_before, 1);

  const char *cfg_b = "(defprofile alpha ((def port 19330) (def advertise 1) "
                      "(def spectator-visibility 5)))\n";
  T_ASSERT_EQ_INT(wamble_test_write_optional_db_config_file(conf_path, cfg_b),
                  0);
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));
  T_ASSERT_EQ_INT(reconcile_profile_listeners(), PROFILE_START_OK);

  char socket_map_after[256];
  int exported_after = 0;
  T_ASSERT_EQ_INT(profile_export_inherited_sockets(socket_map_after,
                                                   sizeof(socket_map_after),
                                                   &exported_after),
                  PROFILE_EXPORT_OK);
  T_ASSERT_EQ_INT(exported_after, 1);
  T_ASSERT_STREQ(socket_map_before, socket_map_after);

  return 0;
}

WAMBLE_TEST(profile_capacity_reload_restarts_inline_runtime_state) {
  g_profile_runtime_net_active = 1;
  T_ASSERT_STATUS_OK(wamble_net_init());

  const char *cfg_a = "(def max-players 5)\n"
                      "(defprofile alpha ((def port 19331) (def advertise 1) "
                      "(def spectator-visibility 0)))\n";
  T_ASSERT_EQ_INT(wamble_test_write_optional_db_config_file(conf_path, cfg_a),
                  0);

  char status[128];
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));

  int started = 0;
  T_ASSERT_EQ_INT(start_profile_listeners(&started), PROFILE_START_OK);
  T_ASSERT_EQ_INT(started, 1);
  T_ASSERT_EQ_INT(profile_runtime_pump_inline(), 1);

  WamblePlayer *p1 = create_new_player();
  WamblePlayer *p2 = create_new_player();
  WamblePlayer *p3 = create_new_player();
  T_ASSERT(p1 != NULL);
  T_ASSERT(p2 != NULL);
  T_ASSERT(p3 != NULL);
  uint8_t stale_token[TOKEN_LENGTH];
  memcpy(stale_token, p3->token, TOKEN_LENGTH);

  const char *cfg_b = "(def max-players 2)\n"
                      "(defprofile alpha ((def port 19331) (def advertise 1) "
                      "(def spectator-visibility 0)))\n";
  T_ASSERT_EQ_INT(wamble_test_write_optional_db_config_file(conf_path, cfg_b),
                  0);
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));
  T_ASSERT_EQ_INT(reconcile_profile_listeners(), PROFILE_START_OK);
  T_ASSERT_EQ_INT(profile_runtime_pump_inline(), 1);

  T_ASSERT(get_player_by_token(stale_token) == NULL);
  T_ASSERT(create_new_player() != NULL);
  T_ASSERT(create_new_player() != NULL);
  T_ASSERT(create_new_player() == NULL);

  return 0;
}

WAMBLE_TEST(profile_db_reload_restarts_inline_runtime_state) {
  g_profile_runtime_net_active = 1;
  T_ASSERT_STATUS_OK(wamble_net_init());

  const char *cfg_a = "(def db-name \"alpha_a\")\n"
                      "(defprofile alpha ((def port 19332) (def advertise 1) "
                      "(def spectator-visibility 0)))\n";
  T_ASSERT_EQ_INT(wamble_test_write_optional_db_config_file(conf_path, cfg_a),
                  0);

  char status[128];
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));

  int started = 0;
  T_ASSERT_EQ_INT(start_profile_listeners(&started), PROFILE_START_OK);
  T_ASSERT_EQ_INT(started, 1);
  T_ASSERT_EQ_INT(profile_runtime_pump_inline(), 1);

  WamblePlayer *player = create_new_player();
  T_ASSERT(player != NULL);
  uint8_t stale_token[TOKEN_LENGTH];
  memcpy(stale_token, player->token, TOKEN_LENGTH);

  const char *cfg_b = "(def db-name \"alpha_b\")\n"
                      "(defprofile alpha ((def port 19332) (def advertise 1) "
                      "(def spectator-visibility 0)))\n";
  T_ASSERT_EQ_INT(wamble_test_write_optional_db_config_file(conf_path, cfg_b),
                  0);
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));
  T_ASSERT_EQ_INT(reconcile_profile_listeners(), PROFILE_START_OK);
  T_ASSERT_EQ_INT(profile_runtime_pump_inline(), 1);

  T_ASSERT(get_player_by_token(stale_token) == NULL);

  return 0;
}

WAMBLE_TEST(default_runtime_capacity_reload_restarts_inline_state) {
  g_profile_runtime_net_active = 1;
  T_ASSERT_STATUS_OK(wamble_net_init());

  const char *cfg_a = "(def port 19333)\n"
                      "(def max-players 5)\n";
  T_ASSERT_EQ_INT(wamble_test_write_optional_db_config_file(conf_path, cfg_a),
                  0);

  char status[128];
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));

  int started = 0;
  T_ASSERT_EQ_INT(start_profile_listeners(&started), PROFILE_START_OK);
  T_ASSERT_EQ_INT(started, 1);
  T_ASSERT_EQ_INT(profile_runtime_pump_inline(), 1);

  WamblePlayer *p1 = create_new_player();
  WamblePlayer *p2 = create_new_player();
  WamblePlayer *p3 = create_new_player();
  T_ASSERT(p1 != NULL);
  T_ASSERT(p2 != NULL);
  T_ASSERT(p3 != NULL);

  const char *cfg_b = "(def port 19333)\n"
                      "(def max-players 2)\n";
  T_ASSERT_EQ_INT(wamble_test_write_optional_db_config_file(conf_path, cfg_b),
                  0);
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));
  T_ASSERT_EQ_INT(reconcile_profile_listeners(), PROFILE_START_OK);
  T_ASSERT_EQ_INT(profile_runtime_pump_inline(), 1);

  T_ASSERT(create_new_player() != NULL);
  T_ASSERT(create_new_player() != NULL);
  T_ASSERT(create_new_player() == NULL);

  return 0;
}

WAMBLE_TEST(
    profile_runtime_spectator_focus_disable_falls_back_with_reliable_summary) {
  g_profile_runtime_net_active = 1;
  T_ASSERT_STATUS_OK(wamble_net_init());

  const char *cfg_a = "(def rate-limit-requests-per-sec 100)\n"
                      "(defprofile p1 ((def port 19340) (def advertise 1)))\n"
                      "(defprofile p2 ((def port 19341) (def advertise 1)))\n";
  if (wamble_test_prepare_db(
          conf_path, cfg_a,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test'), "
          "(0, 'protocol.ctrl', 'client_hello', '*', 'allow', 0, "
          "'hello_access', 'test'), "
          "(0, 'protocol.ctrl', 'spectate_game', '*', 'allow', 0, "
          "'spectate_game_access', 'test'), "
          "(0, 'protocol.ctrl', 'spectate_stop', '*', 'allow', 0, "
          "'spectate_stop_access', 'test'), "
          "(0, 'spectate.access', 'view', '*', 'allow', 0, "
          "'spectate_view_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  char status[128];
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));

  int started = 0;
  T_ASSERT_EQ_INT(start_profile_listeners(&started), PROFILE_START_OK);
  T_ASSERT_EQ_INT(started, 2);
  wamble_sleep_ms(50);

  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_EQ_INT(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)), 0);

  struct sockaddr_in dst;
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons(19340);

  struct WambleMsg tx = {0};
  struct WambleMsg rx = {0};
  struct sockaddr_in from;

  tx.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  tx.header_version = WAMBLE_PROTO_VERSION;
  tx.flags = WAMBLE_FLAG_UNRELIABLE;
  tx.token[0] = 0x31;
  T_ASSERT_STATUS_OK(send_unreliable_packet(cli, &tx, &dst));

  {
    fd_set rfds;
    struct timeval tv;
    FD_ZERO(&rfds);
    FD_SET(cli, &rfds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
#ifdef WAMBLE_PLATFORM_WINDOWS
    T_ASSERT(select(0, &rfds, NULL, NULL, &tv) > 0);
#else
    T_ASSERT(select(cli + 1, &rfds, NULL, NULL, &tv) > 0);
#endif
    T_ASSERT(receive_message(cli, &rx, &from) > 0);
    T_ASSERT_EQ_INT(rx.ctrl, WAMBLE_CTRL_SERVER_HELLO);
    send_ack(cli, &rx, &from);
  }

  tx.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  tx.header_version = WAMBLE_PROTO_VERSION;
  tx.flags = WAMBLE_FLAG_UNRELIABLE;
  tx.token[0] = 0x71;
  tx.board_id = rx.board_id;
  T_ASSERT_STATUS_OK(send_unreliable_packet(cli, &tx, &dst));

  {
    fd_set rfds;
    struct timeval tv;
    FD_ZERO(&rfds);
    FD_SET(cli, &rfds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
#ifdef WAMBLE_PLATFORM_WINDOWS
    T_ASSERT(select(0, &rfds, NULL, NULL, &tv) > 0);
#else
    T_ASSERT(select(cli + 1, &rfds, NULL, NULL, &tv) > 0);
#endif
    T_ASSERT(receive_message(cli, &rx, &from) > 0);
    T_ASSERT_EQ_INT(rx.ctrl, WAMBLE_CTRL_SPECTATE_UPDATE);
    send_ack(cli, &rx, &from);
  }

  const char *cfg_b = "(def rate-limit-requests-per-sec 100)\n"
                      "(defprofile p1 ((def port 19340) (def advertise 1) "
                      "(def spectator-max-focus-per-session 0)))\n"
                      "(defprofile p2 ((def port 19341) (def advertise 1)))\n";
  T_ASSERT_EQ_INT(wamble_test_write_optional_db_config_file(conf_path, cfg_b),
                  0);
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));
  T_ASSERT_EQ_INT(reconcile_profile_listeners(), PROFILE_START_OK);

  int saw_notice = 0;
  int saw_summary = 0;
  int saw_generation = 0;
  uint64_t deadline_ms = wamble_now_mono_millis() + 2500;
  while (wamble_now_mono_millis() < deadline_ms &&
         !(saw_notice && saw_summary && saw_generation)) {
    fd_set rfds;
    struct timeval tv;
    FD_ZERO(&rfds);
    FD_SET(cli, &rfds);
    tv.tv_sec = 0;
    tv.tv_usec = 250 * 1000;
#ifdef WAMBLE_PLATFORM_WINDOWS
    int ready = select(0, &rfds, NULL, NULL, &tv);
#else
    int ready = select(cli + 1, &rfds, NULL, NULL, &tv);
#endif
    if (ready <= 0)
      continue;
    T_ASSERT(receive_message(cli, &rx, &from) > 0);
    if ((rx.flags & WAMBLE_FLAG_UNRELIABLE) == 0)
      send_ack(cli, &rx, &from);
    if (rx.ctrl == WAMBLE_CTRL_SERVER_NOTIFICATION &&
        rx.session.notification_type ==
            WAMBLE_NOTIFICATION_TYPE_SPECTATE_ENDED) {
      saw_notice = 1;
      T_ASSERT((rx.flags & WAMBLE_FLAG_SPECTATE_NOTICE_SUMMARY_FALLBACK) != 0);
      T_ASSERT((rx.flags & WAMBLE_FLAG_SPECTATE_NOTICE_STOPPED) == 0);
    }
    if (rx.ctrl == WAMBLE_CTRL_SPECTATE_UPDATE &&
        (rx.flags & WAMBLE_FLAG_UNRELIABLE) == 0) {
      const WambleMessageExtField *state =
          wamble_msg_ext_find(&rx, "spectate.state");
      if (state && state->value_type == WAMBLE_TREATMENT_VALUE_STRING &&
          strcmp(state->string_value, "summary") == 0) {
        saw_summary = 1;
      }
      if (wamble_msg_ext_find(&rx, "spectate.summary_generation"))
        saw_generation = 1;
    }
  }

  T_ASSERT(saw_notice);
  T_ASSERT(saw_summary);
  T_ASSERT(saw_generation);

  wamble_close_socket(cli);
  return 0;
}

WAMBLE_TEST(profile_runtime_spectator_zero_cap_stops_with_reliable_idle) {
  g_profile_runtime_net_active = 1;
  T_ASSERT_STATUS_OK(wamble_net_init());

  const char *cfg_a = "(def rate-limit-requests-per-sec 100)\n"
                      "(defprofile p1 ((def port 19342) (def advertise 1)))\n"
                      "(defprofile p2 ((def port 19343) (def advertise 1)))\n";
  if (wamble_test_prepare_db(
          conf_path, cfg_a,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test'), "
          "(0, 'protocol.ctrl', 'client_hello', '*', 'allow', 0, "
          "'hello_access', 'test'), "
          "(0, 'protocol.ctrl', 'spectate_game', '*', 'allow', 0, "
          "'spectate_game_access', 'test'), "
          "(0, 'protocol.ctrl', 'spectate_stop', '*', 'allow', 0, "
          "'spectate_stop_access', 'test'), "
          "(0, 'spectate.access', 'view', '*', 'allow', 0, "
          "'spectate_view_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  char status[128];
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));

  int started = 0;
  T_ASSERT_EQ_INT(start_profile_listeners(&started), PROFILE_START_OK);
  T_ASSERT_EQ_INT(started, 2);
  wamble_sleep_ms(50);

  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_EQ_INT(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)), 0);

  struct sockaddr_in dst;
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons(19342);

  struct WambleMsg tx = {0};
  struct WambleMsg rx = {0};
  struct sockaddr_in from;

  tx.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  tx.header_version = WAMBLE_PROTO_VERSION;
  tx.flags = WAMBLE_FLAG_UNRELIABLE;
  tx.token[0] = 0x32;
  T_ASSERT_STATUS_OK(send_unreliable_packet(cli, &tx, &dst));

  {
    fd_set rfds;
    struct timeval tv;
    FD_ZERO(&rfds);
    FD_SET(cli, &rfds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
#ifdef WAMBLE_PLATFORM_WINDOWS
    T_ASSERT(select(0, &rfds, NULL, NULL, &tv) > 0);
#else
    T_ASSERT(select(cli + 1, &rfds, NULL, NULL, &tv) > 0);
#endif
    T_ASSERT(receive_message(cli, &rx, &from) > 0);
    T_ASSERT_EQ_INT(rx.ctrl, WAMBLE_CTRL_SERVER_HELLO);
    send_ack(cli, &rx, &from);
  }

  tx.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  tx.header_version = WAMBLE_PROTO_VERSION;
  tx.flags = WAMBLE_FLAG_UNRELIABLE;
  tx.token[0] = 0x72;
  tx.board_id = rx.board_id;
  T_ASSERT_STATUS_OK(send_unreliable_packet(cli, &tx, &dst));

  {
    fd_set rfds;
    struct timeval tv;
    FD_ZERO(&rfds);
    FD_SET(cli, &rfds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
#ifdef WAMBLE_PLATFORM_WINDOWS
    T_ASSERT(select(0, &rfds, NULL, NULL, &tv) > 0);
#else
    T_ASSERT(select(cli + 1, &rfds, NULL, NULL, &tv) > 0);
#endif
    T_ASSERT(receive_message(cli, &rx, &from) > 0);
    T_ASSERT_EQ_INT(rx.ctrl, WAMBLE_CTRL_SPECTATE_UPDATE);
    send_ack(cli, &rx, &from);
  }

  const char *cfg_b =
      "(def rate-limit-requests-per-sec 100)\n"
      "(defprofile p1 ((def port 19342) (def advertise 1) "
      "(def spectator-max-focus-per-session 0) (def max-spectators 0)))\n"
      "(defprofile p2 ((def port 19343) (def advertise 1)))\n";
  T_ASSERT_EQ_INT(wamble_test_write_optional_db_config_file(conf_path, cfg_b),
                  0);
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));
  T_ASSERT_EQ_INT(reconcile_profile_listeners(), PROFILE_START_OK);

  int saw_notice = 0;
  int saw_idle = 0;
  uint64_t deadline_ms = wamble_now_mono_millis() + 2500;
  while (wamble_now_mono_millis() < deadline_ms && !(saw_notice && saw_idle)) {
    fd_set rfds;
    struct timeval tv;
    FD_ZERO(&rfds);
    FD_SET(cli, &rfds);
    tv.tv_sec = 0;
    tv.tv_usec = 250 * 1000;
#ifdef WAMBLE_PLATFORM_WINDOWS
    int ready = select(0, &rfds, NULL, NULL, &tv);
#else
    int ready = select(cli + 1, &rfds, NULL, NULL, &tv);
#endif
    if (ready <= 0)
      continue;
    T_ASSERT(receive_message(cli, &rx, &from) > 0);
    if ((rx.flags & WAMBLE_FLAG_UNRELIABLE) == 0)
      send_ack(cli, &rx, &from);
    if (rx.ctrl == WAMBLE_CTRL_SERVER_NOTIFICATION &&
        rx.session.notification_type ==
            WAMBLE_NOTIFICATION_TYPE_SPECTATE_ENDED) {
      saw_notice = 1;
      T_ASSERT((rx.flags & WAMBLE_FLAG_SPECTATE_NOTICE_STOPPED) != 0);
      T_ASSERT((rx.flags & WAMBLE_FLAG_SPECTATE_NOTICE_SUMMARY_FALLBACK) == 0);
    }
    if (rx.ctrl == WAMBLE_CTRL_SPECTATE_UPDATE &&
        (rx.flags & WAMBLE_FLAG_UNRELIABLE) == 0) {
      const WambleMessageExtField *state =
          wamble_msg_ext_find(&rx, "spectate.state");
      if (state && state->value_type == WAMBLE_TREATMENT_VALUE_STRING &&
          strcmp(state->string_value, "idle") == 0) {
        saw_idle = 1;
        T_ASSERT_EQ_INT((int)rx.board_id, 0);
      }
    }
  }

  T_ASSERT(saw_notice);
  T_ASSERT(saw_idle);

  wamble_close_socket(cli);
  return 0;
}

WAMBLE_TEST(profile_runtime_expires_idle_players_and_reclaims_capacity) {
  g_profile_runtime_net_active = 1;
  T_ASSERT_STATUS_OK(wamble_net_init());

  char cfg[256];
  snprintf(cfg, sizeof(cfg),
           "(def max-players 2)\n"
           "(def token-expiration 1)\n"
           "(defprofile solo ((def port 19340) (def advertise 1)))\n");
  T_ASSERT_EQ_INT(wamble_test_write_optional_db_config_file(conf_path, cfg), 0);

  char status[128];
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));

  int started = 0;
  T_ASSERT_EQ_INT(start_profile_listeners(&started), PROFILE_START_OK);
  T_ASSERT_EQ_INT(started, 1);
  T_ASSERT_EQ_INT(profile_runtime_pump_inline(), 1);

  WamblePlayer *p1 = create_new_player();
  WamblePlayer *p2 = create_new_player();
  T_ASSERT(p1 != NULL);
  T_ASSERT(p2 != NULL);
  T_ASSERT(create_new_player() == NULL);

  p1->last_seen_time = wamble_now_wall() - get_config()->token_expiration - 1;
  p2->last_seen_time = wamble_now_wall() - get_config()->token_expiration - 1;
  wamble_sleep_ms(2100);
  T_ASSERT_EQ_INT(profile_runtime_pump_inline(), 1);

  T_ASSERT(create_new_player() != NULL);

  return 0;
}

WAMBLE_TEST(profile_runtime_reservation_timeout_emits_reliable_board_update) {
  g_profile_runtime_net_active = 1;
  T_ASSERT_STATUS_OK(wamble_net_init());

  const char *cfg = "(def reservation-timeout 1)\n"
                    "(def rate-limit-requests-per-sec 100)\n"
                    "(defprofile solo ((def port 19344) (def advertise 1)))\n";
  T_ASSERT_EQ_INT(wamble_test_write_optional_db_config_file(conf_path, cfg), 0);

  if (wamble_test_prepare_db(
          conf_path, cfg,
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, reason, source) VALUES "
          "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test'), "
          "(0, 'protocol.ctrl', 'client_hello', '*', 'allow', 0, "
          "'hello_access', 'test');") != 0) {
    T_FAIL_SIMPLE("wamble_test_prepare_db failed");
  }

  char status[128];
  T_ASSERT_STATUS_OK(config_load(conf_path, NULL, status, sizeof(status)));

  int started = 0;
  T_ASSERT_EQ_INT(start_profile_listeners(&started), PROFILE_START_OK);
  T_ASSERT_EQ_INT(started, 1);
  T_ASSERT_EQ_INT(profile_runtime_pump_inline(), 1);

  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  T_ASSERT(cli != WAMBLE_INVALID_SOCKET);

  struct sockaddr_in bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bindaddr.sin_port = 0;
  T_ASSERT_EQ_INT(bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr)), 0);

  struct sockaddr_in dst;
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons(19344);

  struct WambleMsg tx = {0};
  struct WambleMsg rx = {0};
  struct sockaddr_in from;

  tx.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  tx.header_version = WAMBLE_PROTO_VERSION;
  tx.flags = WAMBLE_FLAG_UNRELIABLE;
  tx.token[0] = 0x41;
  T_ASSERT_STATUS_OK(send_unreliable_packet(cli, &tx, &dst));
  T_ASSERT_EQ_INT(profile_runtime_pump_inline(), 1);

  {
    fd_set rfds;
    struct timeval tv;
    FD_ZERO(&rfds);
    FD_SET(cli, &rfds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
#ifdef WAMBLE_PLATFORM_WINDOWS
    T_ASSERT(select(0, &rfds, NULL, NULL, &tv) > 0);
#else
    T_ASSERT(select(cli + 1, &rfds, NULL, NULL, &tv) > 0);
#endif
    T_ASSERT(receive_message(cli, &rx, &from) > 0);
    T_ASSERT_EQ_INT(rx.ctrl, WAMBLE_CTRL_SERVER_HELLO);
    send_ack(cli, &rx, &from);
  }

  WambleBoard *board = get_board_by_id(rx.board_id);
  T_ASSERT(board != NULL);
  board->reservation_time -= (get_config()->reservation_timeout + 1);

  int saw_update = 0;
  uint64_t deadline_ms = wamble_now_mono_millis() + 2500;
  while (wamble_now_mono_millis() < deadline_ms && !saw_update) {
    wamble_sleep_ms(1100);
    T_ASSERT_EQ_INT(profile_runtime_pump_inline(), 1);

    fd_set rfds;
    struct timeval tv;
    FD_ZERO(&rfds);
    FD_SET(cli, &rfds);
    tv.tv_sec = 0;
    tv.tv_usec = 250 * 1000;
#ifdef WAMBLE_PLATFORM_WINDOWS
    int ready = select(0, &rfds, NULL, NULL, &tv);
#else
    int ready = select(cli + 1, &rfds, NULL, NULL, &tv);
#endif
    if (ready <= 0)
      continue;
    T_ASSERT(receive_message(cli, &rx, &from) > 0);
    if ((rx.flags & WAMBLE_FLAG_UNRELIABLE) == 0)
      send_ack(cli, &rx, &from);
    if (rx.ctrl != WAMBLE_CTRL_BOARD_UPDATE)
      continue;
    const WambleMessageExtField *reserved_at =
        wamble_msg_ext_find(&rx, "reservation.reserved_at");
    T_ASSERT(reserved_at != NULL);
    T_ASSERT_EQ_INT(reserved_at->value_type, WAMBLE_TREATMENT_VALUE_INT);
    saw_update = 1;
  }

  T_ASSERT(saw_update);
  wamble_close_socket(cli);
  return 0;
}

WAMBLE_TESTS_BEGIN_NAMED(profile_runtime_tests) {
  WAMBLE_TESTS_ADD_EX_SM(profile_start_export_and_state_files,
                         WAMBLE_SUITE_FUNCTIONAL, "profile_runtime",
                         profile_test_setup, profile_test_teardown, 0);
  WAMBLE_TESTS_ADD_EX_SM(profile_state_dir_used_for_exec_snapshots,
                         WAMBLE_SUITE_FUNCTIONAL, "profile_runtime",
                         profile_test_setup, profile_test_teardown, 0);
  WAMBLE_TESTS_ADD_EX_SM(profile_export_buffer_too_small,
                         WAMBLE_SUITE_FUNCTIONAL, "profile_runtime",
                         profile_test_setup, profile_test_teardown, 0);
  WAMBLE_TESTS_ADD_EX_SM(profile_hot_reload_state_roundtrip,
                         WAMBLE_SUITE_FUNCTIONAL, "profile_runtime",
                         profile_test_setup, profile_test_teardown, 0);
  WAMBLE_TESTS_ADD_EX_SM(default_runtime_hot_reload_exports_socket_and_state,
                         WAMBLE_SUITE_FUNCTIONAL, "profile_runtime",
                         profile_test_setup, profile_test_teardown, 0);
  WAMBLE_TESTS_ADD_DB_EX_SM(
      profile_exec_snapshot_flushes_pending_create_session_intent,
      WAMBLE_SUITE_FUNCTIONAL, "profile_runtime", profile_test_setup,
      profile_test_teardown, 0);
  WAMBLE_TESTS_ADD_EX_SM(
      profile_exec_snapshot_blocks_while_reservation_in_flight,
      WAMBLE_SUITE_FUNCTIONAL, "profile_runtime", profile_test_setup,
      profile_test_teardown, 0);
  WAMBLE_TESTS_ADD_EX_SM(profile_config_inheritance_child_uses_base_port,
                         WAMBLE_SUITE_FUNCTIONAL, "profile_runtime",
                         profile_test_setup, profile_test_teardown, 0);
  WAMBLE_TESTS_ADD_EX_SM(profile_single_listener_runs_inline,
                         WAMBLE_SUITE_FUNCTIONAL, "profile_runtime",
                         profile_test_setup, profile_test_teardown, 0);
  WAMBLE_TESTS_ADD_EX_SM(profile_multi_listener_not_inline,
                         WAMBLE_SUITE_FUNCTIONAL, "profile_runtime",
                         profile_test_setup, profile_test_teardown, 0);
  WAMBLE_TESTS_ADD_EX_SM(
      profile_hidden_listener_enabled_by_discover_override_rule,
      WAMBLE_SUITE_FUNCTIONAL, "profile_runtime", profile_test_setup,
      profile_test_teardown, 0);
  WAMBLE_TESTS_ADD_EX_SM(profile_non_socket_reload_keeps_listener_socket,
                         WAMBLE_SUITE_FUNCTIONAL, "profile_runtime",
                         profile_test_setup, profile_test_teardown, 0);
  WAMBLE_TESTS_ADD_EX_SM(profile_capacity_reload_restarts_inline_runtime_state,
                         WAMBLE_SUITE_FUNCTIONAL, "profile_runtime",
                         profile_test_setup, profile_test_teardown, 0);
  WAMBLE_TESTS_ADD_EX_SM(profile_db_reload_restarts_inline_runtime_state,
                         WAMBLE_SUITE_FUNCTIONAL, "profile_runtime",
                         profile_test_setup, profile_test_teardown, 0);
  WAMBLE_TESTS_ADD_EX_SM(default_runtime_capacity_reload_restarts_inline_state,
                         WAMBLE_SUITE_FUNCTIONAL, "profile_runtime",
                         profile_test_setup, profile_test_teardown, 0);
  WAMBLE_TESTS_ADD_DB_EX_SM(
      profile_runtime_spectator_focus_disable_falls_back_with_reliable_summary,
      WAMBLE_SUITE_FUNCTIONAL, "profile_runtime", profile_test_setup,
      profile_test_teardown, 0);
  WAMBLE_TESTS_ADD_DB_EX_SM(
      profile_runtime_spectator_zero_cap_stops_with_reliable_idle,
      WAMBLE_SUITE_FUNCTIONAL, "profile_runtime", profile_test_setup,
      profile_test_teardown, 0);
  WAMBLE_TESTS_ADD_EX_SM(
      profile_runtime_expires_idle_players_and_reclaims_capacity,
      WAMBLE_SUITE_FUNCTIONAL, "profile_runtime", profile_test_setup,
      profile_test_teardown, 0);
  WAMBLE_TESTS_ADD_DB_EX_SM(
      profile_runtime_reservation_timeout_emits_reliable_board_update,
      WAMBLE_SUITE_FUNCTIONAL, "profile_runtime", profile_test_setup,
      profile_test_teardown, 0);
}
WAMBLE_TESTS_END()
