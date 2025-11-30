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
#include <process.h>
#endif

#if defined(_MSC_VER) && !defined(strtoull)
#define strtoull _strtoui64
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

static void log_server_status(ServerStatus st, const struct WambleMsg *msg) {
  char token_str[TOKEN_LENGTH * 2 + 1];
  format_token_for_url(msg->token, token_str);
  int uci_len = msg->uci_len < MAX_UCI_LENGTH ? msg->uci_len : MAX_UCI_LENGTH;
  char uci[MAX_UCI_LENGTH + 1];
  memcpy(uci, msg->uci, (size_t)uci_len);
  uci[uci_len] = '\0';

  switch (st) {
  case SERVER_OK:
    LOG_DEBUG("SERVER_OK: handled ctrl=0x%02x seq=%u token=%s", msg->ctrl,
              msg->seq_num, token_str);
    break;
  case SERVER_ERR_UNSUPPORTED_VERSION:
    LOG_WARN(
        "SERVER_ERR_UNSUPPORTED_VERSION: unsupported protocol version %u from "
        "token=%s (server=%u)",
        msg->seq_num, token_str, WAMBLE_PROTO_VERSION);
    break;
  case SERVER_ERR_UNKNOWN_CTRL:
    LOG_WARN("SERVER_ERR_UNKNOWN_CTRL: unknown ctrl=0x%02x seq=%u token=%s",
             msg->ctrl, msg->seq_num, token_str);
    break;
  case SERVER_ERR_UNKNOWN_PLAYER:
    LOG_WARN("SERVER_ERR_UNKNOWN_PLAYER: unknown player token=%s ctrl=0x%02x "
             "board=%lu",
             token_str, msg->ctrl, msg->board_id);
    break;
  case SERVER_ERR_UNKNOWN_BOARD:
    LOG_WARN("SERVER_ERR_UNKNOWN_BOARD: unknown board %lu ctrl=0x%02x token=%s",
             msg->board_id, msg->ctrl, token_str);
    break;
  case SERVER_ERR_MOVE_REJECTED:
    LOG_WARN(
        "SERVER_ERR_MOVE_REJECTED: move rejected token=%s board=%lu uci=%s",
        token_str, msg->board_id, uci);
    break;
  case SERVER_ERR_LOGIN_FAILED:
    LOG_WARN("SERVER_ERR_LOGIN_FAILED: login failed for provided key "
             "(ctrl=0x%02x seq=%u)",
             msg->ctrl, msg->seq_num);
    break;
  case SERVER_ERR_SPECTATOR:
    LOG_WARN("SERVER_ERR_SPECTATOR: spectator request failed token=%s "
             "board=%lu ctrl=0x%02x",
             token_str, msg->board_id, msg->ctrl);
    break;
  case SERVER_ERR_LEGAL_MOVES:
    LOG_WARN("SERVER_ERR_LEGAL_MOVES: legal move request failed token=%s "
             "board=%lu square=%u",
             token_str, msg->board_id, (unsigned)msg->move_square);
    break;
  case SERVER_ERR_SEND_FAILED:
    LOG_ERROR("SERVER_ERR_SEND_FAILED: failed to send response ctrl=0x%02x "
              "token=%s board=%lu",
              msg->ctrl, token_str, msg->board_id);
    break;
  case SERVER_ERR_INTERNAL:
    LOG_ERROR("SERVER_ERR_INTERNAL: internal error handling ctrl=0x%02x "
              "token=%s board=%lu",
              msg->ctrl, token_str, msg->board_id);
    break;
  default:
    LOG_WARN("SERVER_STATUS_UNKNOWN: unknown server status %d for ctrl=0x%02x "
             "token=%s",
             (int)st, msg->ctrl, token_str);
    break;
  }
}

static void configure_inherited_socket(wamble_socket_t sockfd) {
  if (sockfd == WAMBLE_INVALID_SOCKET)
    return;
  wamble_set_nonblocking(sockfd);
  int buffer_size = get_config()->buffer_size;
  (void)setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (const char *)&buffer_size,
                   sizeof(buffer_size));
  (void)setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const char *)&buffer_size,
                   sizeof(buffer_size));
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

static int make_socket_inheritable(wamble_socket_t sockfd) {
#ifdef WAMBLE_PLATFORM_WINDOWS
  HANDLE h = (HANDLE)sockfd;
  if (!SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
    return -1;
  return 0;
#else
  int flags = fcntl(sockfd, F_GETFD);
  if (flags < 0)
    return -1;
  if (fcntl(sockfd, F_SETFD, flags & ~FD_CLOEXEC) < 0)
    return -1;
  return 0;
#endif
}

static int save_process_state_snapshot(char *out_path, size_t out_path_len) {
#ifdef WAMBLE_PLATFORM_WINDOWS
  const char *default_tmpl = "wamble_state_XXXXXX";
#else
  const char *default_tmpl = "/tmp/wamble_state_XXXXXX";
#endif
  const char *cfg_dir = get_config() ? get_config()->state_dir : NULL;
  if (cfg_dir && *cfg_dir) {
    const char *fname = "wamble_state_XXXXXX";
    size_t need = strlen(cfg_dir) + 1 + strlen(fname) + 1;
    if (!out_path || out_path_len < need)
      return -1;
    snprintf(out_path, out_path_len, "%s/%s", cfg_dir, fname);
  } else {
    size_t tmpl_len = strlen(default_tmpl);
    if (!out_path || out_path_len <= tmpl_len)
      return -1;
    memcpy(out_path, default_tmpl, tmpl_len + 1);
  }
  int fd = wamble_mkstemp(out_path);
  if (fd < 0)
    return -1;
#ifdef WAMBLE_PLATFORM_WINDOWS
  _close(fd);
#else
  close(fd);
#endif
  if (state_save_to_file(out_path) != 0)
    return -1;
  return 0;
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

static int perform_server_exec_reload(wamble_socket_t sockfd, char *argv[]) {
  if (sockfd == WAMBLE_INVALID_SOCKET) {
    LOG_WARN("Hot reload requested but no active socket");
    return -1;
  }
  if (make_socket_inheritable(sockfd) != 0) {
    LOG_WARN("Failed to mark socket inheritable for hot reload");
    return -1;
  }

  char state_path[512];
  int have_state =
      (save_process_state_snapshot(state_path, sizeof(state_path)) == 0);
  if (have_state) {
    wamble_set_env("WAMBLE_STATE_FILE", state_path);
  } else {
    LOG_WARN("Failed to save state before hot reload");
  }

  char fdstr[32];
  unsigned long long sock_val = (unsigned long long)sockfd;
  snprintf(fdstr, sizeof(fdstr), "%llu", sock_val);
  wamble_set_env("WAMBLE_HOT_RELOAD", "1");
  wamble_set_env("WAMBLE_INHERITED_SOCKFD", fdstr);
  LOG_INFO("Exec-based hot reload starting (socket=%s)", fdstr);
  int err = exec_self(argv);
  LOG_ERROR("execvp failed: %s", wamble_strerror(err));
  if (have_state) {
    wamble_unlink(state_path);
  }
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

static PersistenceStatus flush_intents_status_main(int *out_failures) {
  int failures = 0;
  PersistenceStatus st = wamble_apply_intents_with_db_checked(
      wamble_get_intent_buffer(), &failures);
  if (out_failures)
    *out_failures = failures;
  wamble_persistence_clear_status();
  return st;
}

static void handle_persistence_status_main(const char *phase,
                                           PersistenceStatus st, int failures) {
  switch (st) {
  case PERSISTENCE_STATUS_OK:
  case PERSISTENCE_STATUS_EMPTY:
    return;
  case PERSISTENCE_STATUS_NO_BUFFER:
    LOG_FATAL("Persistence intents missing buffer (%s)", phase);
    break;
  case PERSISTENCE_STATUS_ALLOC_FAIL:
    LOG_FATAL("Persistence intents OOM (%s)", phase);
    break;
  case PERSISTENCE_STATUS_APPLY_FAIL:
    LOG_FATAL("Persistence intents apply failures=%d (%s)", failures, phase);
    break;
  default:
    LOG_FATAL("Persistence intents unknown status=%d failures=%d (%s)", (int)st,
              failures, phase);
    break;
  }
}

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

  int has_profiles = config_profile_count();

  {
    SpectatorInitStatus sst = spectator_manager_init();
    if (sst != SPECTATOR_INIT_OK) {
      LOG_WARN("Spectator manager init failed status=%d", (int)sst);
    } else {
      LOG_INFO("Spectator manager initialized");
    }
  }

  if (has_profiles > 0) {
    int started = 0;
    ProfileStartStatus pst = start_profile_listeners(&started);
    if (pst != PROFILE_START_OK || started <= 0) {
      LOG_WARN("No profile listeners started (status=%d); falling back to "
               "default port",
               (int)pst);
    } else {
      LOG_INFO("Started %d profile listener(s)", started);
    }
  }

  wamble_socket_t sockfd = WAMBLE_INVALID_SOCKET;
  wamble_socket_t inherited_sockfd = WAMBLE_INVALID_SOCKET;
#if defined(WAMBLE_PLATFORM_POSIX) || defined(WAMBLE_PLATFORM_WINDOWS)
  const char *env_reload = getenv("WAMBLE_HOT_RELOAD");
  const char *env_fd = getenv("WAMBLE_INHERITED_SOCKFD");
  const char *env_state = getenv("WAMBLE_STATE_FILE");
  if (env_reload && strcmp(env_reload, "1") == 0 && env_fd && *env_fd) {
    char *endptr = NULL;
    unsigned long long fd_val = strtoull(env_fd, &endptr, 10);
    if (endptr && *endptr == '\0') {
      inherited_sockfd = (wamble_socket_t)fd_val;
      if (inherited_sockfd != WAMBLE_INVALID_SOCKET) {
        LOG_INFO("Hot reload: adopting inherited socket handle=%llu",
                 (unsigned long long)inherited_sockfd);
      }
    }
  }
#else
  const char *env_state = NULL;
#endif
  if (has_profiles == 0) {

    player_manager_init();
    LOG_INFO("Player manager initialized");
    board_manager_init();
    LOG_INFO("Board manager initialized");
    {
      int init_failures = 0;
      PersistenceStatus init_st = flush_intents_status_main(&init_failures);
      handle_persistence_status_main("init", init_st, init_failures);
    }
    if (inherited_sockfd != WAMBLE_INVALID_SOCKET) {
      sockfd = inherited_sockfd;
      configure_inherited_socket(sockfd);
      LOG_INFO("Server adopted existing listening socket (id=%llu)",
               (unsigned long long)sockfd);
    } else {
      sockfd = create_and_bind_socket(get_config()->port);
      if (sockfd == WAMBLE_INVALID_SOCKET) {
        LOG_FATAL("Failed to create and bind socket");
        return 1;
      }
      LOG_INFO("Server listening on port %d", get_config()->port);
    }
  }

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
  time_t last_tick = wamble_now_wall();

  LOG_INFO("Server main loop starting");
  while (!g_shutdown_requested) {
    LOG_DEBUG("Main loop iteration start");
    if (sockfd != WAMBLE_INVALID_SOCKET) {
      fd_set rfds;
      struct timeval tv;
      FD_ZERO(&rfds);
      FD_SET(sockfd, &rfds);
      tv.tv_sec = 0;
      tv.tv_usec = get_config()->select_timeout_usec;

      int ready =
#ifdef WAMBLE_PLATFORM_WINDOWS
          select(0, &rfds, NULL, NULL, &tv);
#else
          select(sockfd + 1, &rfds, NULL, NULL, &tv);
#endif
      if (ready == -1) {
        LOG_ERROR("select failed: %s", strerror(errno));
      } else if (ready == 0) {
        LOG_DEBUG("select timed out, no activity");
      } else if (FD_ISSET(sockfd, &rfds)) {
        for (int drained = 0; drained < 64; drained++) {
          struct WambleMsg msg;
          struct sockaddr_in cliaddr;
          int n = receive_message(sockfd, &msg, &cliaddr);
          if (n > 0) {
            int trust_tier = 0;
            if (qs && qs->get_trust_tier_by_token) {
              qs->get_trust_tier_by_token(msg.token, &trust_tier);
            }
            ServerStatus st =
                handle_message(sockfd, &msg, &cliaddr, trust_tier);
            log_server_status(st, &msg);
            continue;
          }
          break;
        }
      }
    } else {
#ifdef WAMBLE_PLATFORM_POSIX
      struct timespec ts = {.tv_sec = 0, .tv_nsec = 10000000};
      nanosleep(&ts, NULL);
#else
      Sleep(10);
#endif
    }

    time_t now = wamble_now_wall();
    if (now - last_cleanup > get_config()->cleanup_interval_sec) {
      LOG_INFO("Cleaning up expired client sessions");
      cleanup_expired_sessions();
      last_cleanup = now;
      LOG_INFO("Finished cleaning up expired client sessions");
    }

    if (has_profiles == 0) {

      if (now - last_tick > 1) {
        board_manager_tick();
        {
          int loop_failures = 0;
          PersistenceStatus loop_st = flush_intents_status_main(&loop_failures);
          handle_persistence_status_main("loop", loop_st, loop_failures);
        }
        spectator_manager_tick();
        db_tick();
        last_tick = now;
      }

      int cap = get_config()->max_client_sessions;
      if (cap < 1)
        cap = 1;
      SpectatorUpdate *events =
          (SpectatorUpdate *)malloc(sizeof(SpectatorUpdate) * (size_t)cap);
      if (events) {
        int nupd = spectator_collect_updates(events, cap);
        for (int i = 0; i < nupd; i++) {
          struct WambleMsg out = {0};
          out.ctrl = WAMBLE_CTRL_SPECTATE_UPDATE;
          memcpy(out.token, events[i].token, TOKEN_LENGTH);
          out.board_id = events[i].board_id;
          out.seq_num = 0;
          out.flags = WAMBLE_FLAG_UNRELIABLE;
          {
            size_t __len = strnlen(events[i].fen, FEN_MAX_LENGTH - 1);
            memcpy(out.fen, events[i].fen, __len);
            out.fen[__len] = '\0';
          }
          if (send_unreliable_packet(sockfd, &out, &events[i].addr) != 0) {
            LOG_WARN("Failed to send spectator update for board %lu",
                     out.board_id);
          }
        }
        int nnot = spectator_collect_notifications(events, cap);
        for (int i = 0; i < nnot; i++) {
          struct WambleMsg out = {0};
          out.ctrl = WAMBLE_CTRL_SERVER_NOTIFICATION;
          memcpy(out.token, events[i].token, TOKEN_LENGTH);
          out.board_id = events[i].board_id;
          out.seq_num = 0;
          out.flags = WAMBLE_FLAG_UNRELIABLE;
          {
            size_t __len = strnlen(events[i].fen, FEN_MAX_LENGTH - 1);
            memcpy(out.fen, events[i].fen, __len);
            out.fen[__len] = '\0';
          }
          if (send_unreliable_packet(sockfd, &out, &events[i].addr) != 0) {
            LOG_WARN("Failed to send spectator notice for board %lu",
                     out.board_id);
          }
        }
        free(events);
      }
    }
    if (g_reload_requested) {
      LOG_INFO("Reload requested; reloading config and reconciling listeners");
      ConfigLoadStatus rcfg =
          config_load(config_file, profile, cfg_status, sizeof(cfg_status));
      if (rcfg != CONFIG_LOAD_OK) {
        LOG_WARN("Config reload status=%d", (int)rcfg);
      }
      if (config_profile_count() > 0) {
        ProfileStartStatus rst = reconcile_profile_listeners();
        if (rst == PROFILE_START_THREAD_ERROR) {
          LOG_FATAL("Failed to start thread for one or more profiles");
        }
        if (rst != PROFILE_START_OK && rst != PROFILE_START_NONE) {
          LOG_WARN("Listener reconcile failed (status=%d)", (int)rst);
        }
      }
      g_reload_requested = 0;
    }

    if (g_exec_reload_requested) {
      int exec_rc;
      if (config_profile_count() > 0) {
        exec_rc = perform_profile_exec_reload(argv);
      } else {
        exec_rc = perform_server_exec_reload(sockfd, argv);
      }
      if (exec_rc != 0)
        g_exec_reload_requested = 0;
    }

    LOG_DEBUG("Main loop iteration end");
  }
  LOG_INFO("Server main loop ending");

  if (config_profile_count() > 0) {
    stop_profile_listeners();
  }
  if (sockfd != WAMBLE_INVALID_SOCKET) {
    wamble_close_socket(sockfd);
  }
  spectator_manager_shutdown();
  db_cleanup();

  wamble_net_cleanup();
  return 0;
}
