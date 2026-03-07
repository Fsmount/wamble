#include "../include/wamble/wamble.h"
#include "../include/wamble/wamble_db.h"
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#ifdef WAMBLE_PLATFORM_POSIX
#include <fcntl.h>
#include <unistd.h>
#endif
#ifdef WAMBLE_PLATFORM_WINDOWS
#include <io.h>
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

static int close_fd_local(int fd) {
#ifdef WAMBLE_PLATFORM_WINDOWS
  return _close(fd);
#else
  return close(fd);
#endif
}

static int read_text_file(const char *path, char **out_text) {
  if (!path || !out_text)
    return -1;
  *out_text = NULL;
  FILE *f = fopen(path, "rb");
  if (!f)
    return -1;
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return -1;
  }
  long sz = ftell(f);
  if (sz < 0) {
    fclose(f);
    return -1;
  }
  if (fseek(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return -1;
  }
  char *buf = (char *)malloc((size_t)sz + 1);
  if (!buf) {
    fclose(f);
    return -1;
  }
  size_t rd = fread(buf, 1, (size_t)sz, f);
  fclose(f);
  if (rd != (size_t)sz) {
    free(buf);
    return -1;
  }
  buf[rd] = '\0';
  *out_text = buf;
  return 0;
}

static int load_config_from_text_blob(const char *text, const char *profile,
                                      char *status_msg,
                                      size_t status_msg_size) {
  if (!text || !text[0])
    return -1;
  char tmpl[] = "wamble_cfg_XXXXXX";
  int fd = wamble_mkstemp(tmpl);
  if (fd < 0)
    return -1;
  if (close_fd_local(fd) != 0) {
    wamble_unlink(tmpl);
    return -1;
  }
  FILE *f = fopen(tmpl, "wb");
  if (!f) {
    wamble_unlink(tmpl);
    return -1;
  }
  size_t len = strlen(text);
  size_t wr = fwrite(text, 1, len, f);
  fclose(f);
  if (wr != len) {
    wamble_unlink(tmpl);
    return -1;
  }
  ConfigLoadStatus st = config_load(tmpl, profile, status_msg, status_msg_size);
  wamble_unlink(tmpl);
  return (st == CONFIG_LOAD_OK) ? 0 : -1;
}

static int db_endpoint_equal(const char *host_a, const char *user_a,
                             const char *db_a, const char *host_b,
                             const char *user_b, const char *db_b) {
  const char *ha = host_a ? host_a : "";
  const char *ua = user_a ? user_a : "";
  const char *da = db_a ? db_a : "";
  const char *hb = host_b ? host_b : "";
  const char *ub = user_b ? user_b : "";
  const char *db = db_b ? db_b : "";
  return strcmp(ha, hb) == 0 && strcmp(ua, ub) == 0 && strcmp(da, db) == 0;
}

static int validate_db_topology(char *err, size_t err_size) {
  const WambleConfig *cfg = get_config();
  if (!cfg)
    return -1;

  const char *global_host = cfg->global_db_host;
  const char *global_user = cfg->global_db_user;
  const char *global_name = cfg->global_db_name;

  int count = config_profile_count();
  if (count > 0) {
    const WambleProfile *first = config_get_profile(0);
    if (first) {
      global_host = first->config.global_db_host;
      global_user = first->config.global_db_user;
      global_name = first->config.global_db_name;
    }
  }

  if (db_endpoint_equal(cfg->db_host, cfg->db_user, cfg->db_name, global_host,
                        global_user, global_name)) {
    if (err && err_size) {
      snprintf(
          err, err_size,
          "profile DB endpoint must differ from shared global DB endpoint");
    }
    return -1;
  }

  for (int i = 0; i < count; i++) {
    const WambleProfile *p = config_get_profile(i);
    if (!p)
      continue;
    if (!db_endpoint_equal(p->config.global_db_host, p->config.global_db_user,
                           p->config.global_db_name, global_host, global_user,
                           global_name)) {
      if (err && err_size) {
        snprintf(err, err_size,
                 "profile '%s' overrides global DB endpoint; all profiles must "
                 "share one global identity store",
                 p->name ? p->name : "");
      }
      return -1;
    }
    if (db_endpoint_equal(p->config.db_host, p->config.db_user,
                          p->config.db_name, global_host, global_user,
                          global_name)) {
      if (err && err_size) {
        snprintf(err, err_size,
                 "profile '%s' DB endpoint overlaps shared global DB endpoint",
                 p->name ? p->name : "");
      }
      return -1;
    }
  }

  return 0;
}

static const char *profile_key_for_runtime(const char *profile) {
  return (profile && profile[0]) ? profile : "__default__";
}

static int bind_active_config_policy(const char *profile_key,
                                     char *global_conn_str,
                                     size_t global_conn_str_size) {
  if (global_conn_str && global_conn_str_size > 0)
    global_conn_str[0] = '\0';
  if (db_set_global_store_connection(NULL) != 0 ||
      db_apply_config_policy_rules(profile_key) != 0 ||
      db_validate_global_policy() != 0 ||
      db_apply_config_treatment_rules(profile_key) != 0 ||
      db_validate_global_treatments() != 0) {
    return -1;
  }
  return 0;
}

static int restore_previous_config_and_policy(void *cfg_snapshot,
                                              const char *profile_key,
                                              char *global_conn_str,
                                              size_t global_conn_str_size) {
  if (config_restore_snapshot(cfg_snapshot) != 0)
    return -1;
  return bind_active_config_policy(profile_key, global_conn_str,
                                   global_conn_str_size);
}

static void process_config_reload_request(
    const char *config_file, const char *profile, char *cfg_status,
    size_t cfg_status_size, char *topology_err, size_t topology_err_size,
    char *global_conn_str, size_t global_conn_str_size) {
  char *attempt_cfg_text = NULL;
  void *cfg_snapshot = NULL;
  const char *profile_key = profile_key_for_runtime(profile);
  int loaded_from_db_snapshot = 0;

  LOG_INFO("Config reload requested");
  (void)read_text_file(config_file, &attempt_cfg_text);

  cfg_snapshot = config_create_snapshot();
  if (!cfg_snapshot) {
    LOG_WARN("Config reload skipped: failed to snapshot current config");
    free(attempt_cfg_text);
    return;
  }

  LOG_INFO("Config reload: loading candidate config");
  ConfigLoadStatus rcfg =
      config_load(config_file, profile, cfg_status, cfg_status_size);
  if (rcfg != CONFIG_LOAD_OK) {
    char errbuf[128];
    snprintf(errbuf, sizeof(errbuf), "config_load_status=%d", (int)rcfg);
    (void)db_record_config_event(profile_key, attempt_cfg_text, "file",
                                 "rejected", errbuf);
    char *db_cfg = NULL;
    if (db_load_config_snapshot(profile_key, &db_cfg) == 0 && db_cfg) {
      LOG_WARN("Config reload parse/load failed status=%d; attempting DB "
               "snapshot restore",
               (int)rcfg);
      if (load_config_from_text_blob(db_cfg, profile, cfg_status,
                                     cfg_status_size) == 0) {
        LOG_INFO("Recovered config from DB snapshot for profile key %s",
                 profile_key);
        loaded_from_db_snapshot = 1;
      } else {
        LOG_WARN("DB snapshot restore failed; keeping in-memory previous "
                 "config");
        (void)config_restore_snapshot(cfg_snapshot);
        free(db_cfg);
        config_free_snapshot(cfg_snapshot);
        free(attempt_cfg_text);
        return;
      }
      free(db_cfg);
    } else {
      LOG_WARN("Config reload rejected status=%d; no DB snapshot available, "
               "keeping previous config",
               (int)rcfg);
      (void)config_restore_snapshot(cfg_snapshot);
      config_free_snapshot(cfg_snapshot);
      free(attempt_cfg_text);
      return;
    }
  }

  LOG_INFO("Config reload: validating topology and policy");
  if (validate_db_topology(topology_err, topology_err_size) != 0) {
    LOG_WARN("Config reload rejected: invalid DB topology (%s); keeping "
             "previous config",
             topology_err);
    (void)db_record_config_event(profile_key, attempt_cfg_text, "file",
                                 "rejected", topology_err);
    (void)config_restore_snapshot(cfg_snapshot);
    config_free_snapshot(cfg_snapshot);
    free(attempt_cfg_text);
    return;
  }

  if (bind_active_config_policy(profile_key, global_conn_str,
                                global_conn_str_size) != 0) {
    LOG_WARN("Config reload rejected: invalid global store/policy; keeping "
             "previous config");
    (void)db_record_config_event(profile_key, attempt_cfg_text, "file",
                                 "rejected",
                                 "global_store_or_policy_validation_failed");
    (void)config_restore_snapshot(cfg_snapshot);
    if (bind_active_config_policy(profile_key, global_conn_str,
                                  global_conn_str_size) != 0) {
      LOG_WARN("Failed to rebind policy after rejected config reload");
    }
    config_free_snapshot(cfg_snapshot);
    free(attempt_cfg_text);
    return;
  }

  LOG_INFO("Config reload: applying runtime changes");
  ProfileStartStatus rst = reconcile_profile_listeners();
  if (rst != PROFILE_START_OK) {
    char errbuf[128];
    snprintf(errbuf, sizeof(errbuf), "runtime_apply_status=%d", (int)rst);
    LOG_WARN("Config reload apply failed (status=%d); restoring previous "
             "config",
             (int)rst);
    (void)db_record_config_event(profile_key, attempt_cfg_text, "file",
                                 "rejected", errbuf);
    if (restore_previous_config_and_policy(cfg_snapshot, profile_key,
                                           global_conn_str,
                                           global_conn_str_size) != 0) {
      LOG_FATAL("Failed to restore previous config snapshot");
    }
    if (reconcile_profile_listeners() != PROFILE_START_OK) {
      LOG_FATAL("Failed to reapply runtime state back to previous config");
    }
    config_free_snapshot(cfg_snapshot);
    free(attempt_cfg_text);
    return;
  }

  LOG_INFO("Config reload applied");
  if (!loaded_from_db_snapshot && attempt_cfg_text && attempt_cfg_text[0]) {
    LOG_INFO("Config reload: persisting active snapshot");
    if (db_store_config_snapshot(profile_key, attempt_cfg_text) != 0) {
      LOG_WARN("Failed to persist updated config snapshot to global store");
    } else if (bind_active_config_policy(profile_key, global_conn_str,
                                         global_conn_str_size) != 0) {
      LOG_WARN("Failed to bind policy to persisted active config snapshot");
    }
  }

  config_free_snapshot(cfg_snapshot);
  free(attempt_cfg_text);
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

typedef struct MainOptions {
  const char *config_file;
  const char *profile;
} MainOptions;

static int parse_main_options(int argc, char *argv[], MainOptions *opts) {
  if (!opts)
    return -1;

  opts->config_file = "wamble.conf";
  opts->profile = NULL;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Option %s requires an argument.\n", argv[i]);
        return -1;
      }
      opts->config_file = argv[++i];
      continue;
    }

    if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--profile") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Option %s requires an argument.\n", argv[i]);
        return -1;
      }
      opts->profile = argv[++i];
      continue;
    }

    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      printf("Usage: %s [-c|--config <config_file>] [-p|--profile <profile>]\n",
             argv[0]);
      return 1;
    }
  }

  return 0;
}

static void install_signal_handlers(void) {
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

  struct sigaction sc;
  memset(&sc, 0, sizeof(sc));
  sc.sa_handler = handle_sigusr2;
  sigaction(SIGUSR2, &sc, NULL);
#else
  signal(SIGINT, handle_sigterm);
  signal(SIGTERM, handle_sigterm);
#endif
}

static void persist_initial_config_snapshot(const char *config_file,
                                            const char *profile) {
  char *cfg_text = NULL;
  if (read_text_file(config_file, &cfg_text) != 0 || !cfg_text)
    return;

  const char *profile_key = profile_key_for_runtime(profile);
  if (db_store_config_snapshot(profile_key, cfg_text) != 0) {
    LOG_WARN("Failed to persist initial config snapshot to global store");
  }
  free(cfg_text);
}

static int initialize_config_and_policy(
    const char *config_file, const char *profile, char *cfg_status,
    size_t cfg_status_size, char *topology_err, size_t topology_err_size,
    char *global_conn_str, size_t global_conn_str_size) {
  ConfigLoadStatus cfg =
      config_load(config_file, profile, cfg_status, cfg_status_size);
  if (cfg != CONFIG_LOAD_OK) {
    LOG_WARN("Config load status=%d", (int)cfg);
  }

  if (validate_db_topology(topology_err, topology_err_size) != 0) {
    LOG_FATAL("Invalid DB topology: %s", topology_err);
    return -1;
  }

  if (db_set_global_store_connection(NULL) != 0) {
    LOG_FATAL("Failed to configure shared global store connection");
    return -1;
  }

  persist_initial_config_snapshot(config_file, profile);

  if (bind_active_config_policy(profile_key_for_runtime(profile),
                                global_conn_str, global_conn_str_size) != 0) {
    LOG_FATAL("Failed to load/validate trust policy");
    return -1;
  }

  return 0;
}

static int initialize_services(void) {
  if (db_init(NULL) != 0) {
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

  SpectatorInitStatus sst = spectator_manager_init();
  if (sst != SPECTATOR_INIT_OK) {
    LOG_WARN("Spectator manager init failed status=%d", (int)sst);
  } else {
    LOG_INFO("Spectator manager initialized");
  }

  int started = 0;
  ProfileStartStatus pst = start_profile_listeners(&started);
  if (pst != PROFILE_START_OK || started <= 0) {
    LOG_FATAL("Listener startup failed (status=%d)", (int)pst);
    return 1;
  }
  LOG_INFO("Started %d runtime listener(s)", started);
  return 0;
}

static void restore_hot_reload_state(void) {
#if defined(WAMBLE_PLATFORM_POSIX) || defined(WAMBLE_PLATFORM_WINDOWS)
  const char *env_reload = getenv("WAMBLE_HOT_RELOAD");
  const char *env_state = getenv("WAMBLE_STATE_FILE");
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
}

static void drain_runtime_issue_queues(void) {
  char profile_name[64];
  WsGatewayStatus gateway_status = WS_GATEWAY_OK;
  while (profile_runtime_take_ws_gateway_status(&gateway_status, profile_name,
                                                sizeof(profile_name))) {
    LOG_ERROR("WS gateway issue profile=%s status=%d",
              profile_name[0] ? profile_name : "default", (int)gateway_status);
  }

  ProfileTrustDecisionStatus trust_status = PROFILE_TRUST_DECISION_DENIED;
  while (profile_runtime_take_trust_decision_status(&trust_status, profile_name,
                                                    sizeof(profile_name))) {
    LOG_DEBUG("trust decision profile=%s status=%d",
              profile_name[0] ? profile_name : "default", (int)trust_status);
  }

  PredictionManagerStatus prediction_status = PREDICTION_MANAGER_OK;
  while (profile_runtime_take_prediction_manager_status(
      &prediction_status, profile_name, sizeof(profile_name))) {
    if (prediction_status < 0) {
      LOG_ERROR("prediction manager issue profile=%s status=%d",
                profile_name[0] ? profile_name : "default",
                (int)prediction_status);
    } else {
      LOG_WARN("prediction manager issue profile=%s status=%d",
               profile_name[0] ? profile_name : "default",
               (int)prediction_status);
    }
  }
}

static void run_main_loop(const char *config_file, const char *profile,
                          char *cfg_status, size_t cfg_status_size,
                          char *topology_err, size_t topology_err_size,
                          char *global_conn_str, size_t global_conn_str_size,
                          char *argv[]) {
  time_t last_cleanup = wamble_now_wall();
  LOG_INFO("Server main loop starting");
  while (!g_shutdown_requested) {
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
      process_config_reload_request(
          config_file, profile, cfg_status, cfg_status_size, topology_err,
          topology_err_size, global_conn_str, global_conn_str_size);
      g_reload_requested = 0;
    }

    if (g_exec_reload_requested) {
      int exec_rc = perform_profile_exec_reload(argv);
      if (exec_rc != 0)
        g_exec_reload_requested = 0;
    }

    drain_runtime_issue_queues();
  }
  LOG_INFO("Server main loop ending");
}

static void shutdown_services(void) {
  stop_profile_listeners();
  spectator_manager_shutdown();
  db_cleanup();
  wamble_net_cleanup();
}

int main(int argc, char *argv[]) {
  MainOptions opts;
  int parse_rc = parse_main_options(argc, argv, &opts);
  if (parse_rc < 0)
    return 1;
  if (parse_rc > 0)
    return 0;

  if (wamble_net_init() != 0) {
    LOG_FATAL("Network initialization failed");
    return 1;
  }

  LOG_INFO("Wamble server starting up");
  if (opts.profile) {
    LOG_INFO("Using profile: %s from config file: %s", opts.profile,
             opts.config_file);
  } else {
    LOG_INFO("Using default configuration from config file: %s",
             opts.config_file);
  }

  char cfg_status[128];
  char global_conn_str[512];
  char topology_err[256];
  install_signal_handlers();
  if (initialize_config_and_policy(opts.config_file, opts.profile, cfg_status,
                                   sizeof(cfg_status), topology_err,
                                   sizeof(topology_err), global_conn_str,
                                   sizeof(global_conn_str)) != 0) {
    wamble_net_cleanup();
    return 1;
  }
  if (initialize_services() != 0) {
    wamble_net_cleanup();
    return 1;
  }
  restore_hot_reload_state();
  run_main_loop(opts.config_file, opts.profile, cfg_status, sizeof(cfg_status),
                topology_err, sizeof(topology_err), global_conn_str,
                sizeof(global_conn_str), argv);
  shutdown_services();
  return 0;
}
