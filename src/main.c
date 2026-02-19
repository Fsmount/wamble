#include "../include/wamble/wamble.h"
#include "../include/wamble/wamble_db.h"
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#ifdef WAMBLE_PLATFORM_POSIX
#include <unistd.h>
#endif
#ifdef WAMBLE_PLATFORM_WINDOWS
#include <process.h>
#endif

static volatile sig_atomic_t g_reload_requested = 0;
static volatile sig_atomic_t g_shutdown_requested = 0;
static volatile sig_atomic_t g_exec_reload_requested = 0;

static void wamble_set_env(const char *key, const char *value) {
#ifdef WAMBLE_PLATFORM_WINDOWS
  if (value)
    _putenv_s(key, value);
  else
    _putenv_s(key, "");
#else
  if (value)
    setenv(key, value, 1);
  else
    unsetenv(key);
#endif
}

static void clear_hot_reload_env(void) {
  wamble_set_env("WAMBLE_HOT_RELOAD", NULL);
  wamble_set_env("WAMBLE_INHERITED_SOCKFD", NULL);
  wamble_set_env("WAMBLE_PROFILES_INHERITED", NULL);
  wamble_set_env("WAMBLE_STATE_FILES", NULL);
  wamble_set_env("WAMBLE_STATE_FILE", NULL);
}

static void unlink_state_map_entries(const char *state_map) {
  if (!state_map || !*state_map)
    return;
  const char *cursor = state_map;
  while (*cursor) {
    const char *next = strchr(cursor, ',');
    size_t seg_len = next ? (size_t)(next - cursor) : strlen(cursor);
    const char *eq = memchr(cursor, '=', seg_len);
    if (eq && (eq > cursor) && (size_t)(eq - cursor) < seg_len - 1) {
      size_t path_len = seg_len - (size_t)(eq - cursor) - 1;
      char *path = (char *)malloc(path_len + 1);
      if (path) {
        memcpy(path, eq + 1, path_len);
        path[path_len] = '\0';
        wamble_unlink(path);
        free(path);
      }
    }
    if (!next)
      break;
    cursor = next + 1;
  }
}

static int exec_self(char *argv[]) {
#ifdef WAMBLE_PLATFORM_WINDOWS
  _execvp(argv[0], argv);
  return errno;
#else
  execvp(argv[0], argv);
  return wamble_last_error();
#endif
}

static int perform_profile_exec_reload(char *argv[]) {
  char statebuf[2048];
  char mapbuf[1024];
  int scnt = 0;
  ProfileExportStatus state_status =
      profile_prepare_state_save_and_inherit(statebuf, sizeof(statebuf), &scnt);
  if (state_status == PROFILE_EXPORT_BUFFER_TOO_SMALL) {
    LOG_WARN("Hot reload requested but state export truncated");
    return -1;
  }
  if (state_status == PROFILE_EXPORT_NOT_READY) {
    LOG_WARN("Hot reload requested but profile state not ready");
    return -1;
  }

  int cnt = 0;
  ProfileExportStatus sock_status =
      profile_export_inherited_sockets(mapbuf, sizeof(mapbuf), &cnt);
  if (sock_status == PROFILE_EXPORT_BUFFER_TOO_SMALL) {
    LOG_WARN("Hot reload requested but socket export truncated");
    return -1;
  }
  if (sock_status == PROFILE_EXPORT_NOT_READY) {
    LOG_WARN("Hot reload requested but socket export unavailable");
    return -1;
  }
  if (sock_status == PROFILE_EXPORT_EMPTY || cnt == 0) {
    LOG_WARN("Hot reload requested but no active profile sockets");
    return -1;
  }
  wamble_set_env("WAMBLE_PROFILES_INHERITED", mapbuf);
  if (state_status == PROFILE_EXPORT_OK && scnt > 0) {
    wamble_set_env("WAMBLE_STATE_FILES", statebuf);
  }
  wamble_set_env("WAMBLE_HOT_RELOAD", "1");
  LOG_INFO("Exec-based hot reload (profiles=%d)", cnt);
  int err = exec_self(argv);
  LOG_ERROR("execvp failed: %s", wamble_strerror(err));
  if (scnt > 0)
    unlink_state_map_entries(statebuf);
  clear_hot_reload_env();
  return -1;
}

static void handle_sighup(int signo) {
  (void)signo;
  g_reload_requested = 1;
}

static void handle_sigterm(int signo) {
  (void)signo;
  g_shutdown_requested = 1;
}

#ifdef WAMBLE_PLATFORM_POSIX
static void handle_sigusr2(int signo) {
  (void)signo;
  g_exec_reload_requested = 1;
}
#endif

int main(int argc, char *argv[]) {
  if (wamble_net_init() != 0) {
    LOG_FATAL("Network initialization failed");
    return 1;
  }
  const char *config_file = "wamble.conf";
  const char *profile = NULL;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
      if (i + 1 < argc) {
        config_file = argv[++i];
      } else {
        fprintf(stderr, "Option %s requires an argument.\n", argv[i]);
        return 1;
      }
    } else if (strcmp(argv[i], "-p") == 0 ||
               strcmp(argv[i], "--profile") == 0) {
      if (i + 1 < argc) {
        profile = argv[++i];
      } else {
        fprintf(stderr, "Option %s requires an argument.\n", argv[i]);
        return 1;
      }
    } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      printf("Usage: %s [-c|--config <config_file>] [-p|--profile <profile>]\n",
             argv[0]);
      return 0;
    }
  }

  LOG_INFO("Wamble server starting up");
  if (profile) {
    LOG_INFO("Using profile: %s from config file: %s", profile, config_file);
  } else {
    LOG_INFO("Using default configuration from config file: %s", config_file);
  }

  char cfg_status[128];
  ConfigLoadStatus cfg =
      config_load(config_file, profile, cfg_status, sizeof(cfg_status));
  if (cfg != CONFIG_LOAD_OK) {
    LOG_WARN("Config load status=%d", (int)cfg);
  }

#ifdef WAMBLE_PLATFORM_POSIX
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_sighup;
  sigaction(SIGHUP, &sa, NULL);

  struct sigaction sb;
  memset(&sb, 0, sizeof(sb));
  sb.sa_handler = handle_sigterm;
  sigaction(SIGINT, &sb, NULL);
  sigaction(SIGTERM, &sb, NULL);
#else
  signal(SIGINT, handle_sigterm);
  signal(SIGTERM, handle_sigterm);
#endif

#ifdef WAMBLE_PLATFORM_POSIX
  struct sigaction sc;
  memset(&sc, 0, sizeof(sc));
  sc.sa_handler = handle_sigusr2;
  sigaction(SIGUSR2, &sc, NULL);
#endif

  char db_conn_str[256];
  snprintf(db_conn_str, sizeof(db_conn_str),
           "dbname=%s user=%s password=%s host=%s", get_config()->db_name,
           get_config()->db_user, get_config()->db_pass, get_config()->db_host);

  if (db_init(db_conn_str) != 0) {
    LOG_FATAL("Failed to initialize database");
    return 1;
  }
  LOG_INFO("Database initialized successfully");

  static WambleIntentBuffer g_intents_main;
  wamble_intents_init(&g_intents_main);
  const WambleQueryService *qs = wamble_get_db_query_service();
  wamble_set_query_service(qs);
  wamble_set_intent_buffer(&g_intents_main);
  if (!wamble_get_query_service()) {
    LOG_FATAL("Query service not configured");
    return 1;
  }

  {
    SpectatorInitStatus sst = spectator_manager_init();
    if (sst != SPECTATOR_INIT_OK) {
      LOG_WARN("Spectator manager init failed status=%d", (int)sst);
    } else {
      LOG_INFO("Spectator manager initialized");
    }
  }

  int started = 0;
  ProfileStartStatus pst = start_profile_listeners(&started);
  if (pst == PROFILE_START_OK && started > 0) {
    LOG_INFO("Started %d runtime listener(s)", started);
  } else {
    LOG_FATAL("Listener startup failed (status=%d)", (int)pst);
    return 1;
  }

#if defined(WAMBLE_PLATFORM_POSIX) || defined(WAMBLE_PLATFORM_WINDOWS)
  const char *env_reload = getenv("WAMBLE_HOT_RELOAD");
  const char *env_state = getenv("WAMBLE_STATE_FILE");
#else
  const char *env_state = NULL;
#endif
#if defined(WAMBLE_PLATFORM_POSIX) || defined(WAMBLE_PLATFORM_WINDOWS)

  if (env_reload && strcmp(env_reload, "1") == 0 && env_state && *env_state) {
    if (state_load_from_file(env_state) == 0) {
      LOG_INFO("Restored in-memory state from %s", env_state);
      wamble_unlink(env_state);
      wamble_set_env("WAMBLE_STATE_FILE", NULL);
    } else {
      LOG_WARN("Failed to restore state from %s", env_state);
    }
  }
#endif

  time_t last_cleanup = wamble_now_wall();

  LOG_INFO("Server main loop starting");
  while (!g_shutdown_requested) {
    LOG_DEBUG("Main loop iteration start");
    int inline_runtime = profile_runtime_pump_inline();

    time_t now = wamble_now_wall();
    if (!inline_runtime &&
        now - last_cleanup > get_config()->cleanup_interval_sec) {
      LOG_INFO("Cleaning up expired client sessions");
      cleanup_expired_sessions();
      last_cleanup = now;
      LOG_INFO("Finished cleaning up expired client sessions");
    }
    if (g_reload_requested) {
      LOG_INFO("Reload requested; reloading config and reconciling listeners");
      ConfigLoadStatus rcfg =
          config_load(config_file, profile, cfg_status, sizeof(cfg_status));
      if (rcfg != CONFIG_LOAD_OK) {
        LOG_WARN("Config reload status=%d", (int)rcfg);
      }
      ProfileStartStatus rst = reconcile_profile_listeners();
      if (rst != PROFILE_START_OK) {
        LOG_FATAL("Listener reconcile failed (status=%d)", (int)rst);
      }
      g_reload_requested = 0;
    }

    if (g_exec_reload_requested) {
      int exec_rc = perform_profile_exec_reload(argv);
      if (exec_rc != 0)
        g_exec_reload_requested = 0;
    }

    {
      char profile_name[64];
      WsGatewayStatus rst = WS_GATEWAY_OK;
      while (profile_runtime_take_ws_gateway_status(&rst, profile_name,
                                                    sizeof(profile_name))) {
        LOG_ERROR("WS gateway issue profile=%s status=%d",
                  profile_name[0] ? profile_name : "default", (int)rst);
      }
    }

    LOG_DEBUG("Main loop iteration end");
  }
  LOG_INFO("Server main loop ending");
  stop_profile_listeners();
  spectator_manager_shutdown();
  db_cleanup();
  wamble_net_cleanup();
  return 0;
}
