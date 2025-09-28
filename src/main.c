#include "../include/wamble/wamble.h"
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

static void configure_inherited_socket(wamble_socket_t sockfd) {
  if (sockfd == WAMBLE_INVALID_SOCKET)
    return;
  (void)wamble_set_nonblocking(sockfd);
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
        struct WambleMsg msg;
        struct sockaddr_in cliaddr;
        int n = receive_message(sockfd, &msg, &cliaddr);
        if (n > 0) {
          handle_message(sockfd, &msg, &cliaddr);
        } else if (n == 0) {
          LOG_WARN("Received 0 bytes from socket, client disconnected?");
        } else {
          LOG_ERROR("receive_message failed: %s", strerror(errno));
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

static void handle_client_hello(int sockfd, const struct WambleMsg *msg,
                                const struct sockaddr_in *cliaddr) {
  char token_str[TOKEN_LENGTH * 2 + 1];
  format_token_for_url(msg->token, token_str);
  LOG_DEBUG("Received Client Hello from token: %s", token_str);

  uint32_t client_version = msg->seq_num;
  if (client_version < WAMBLE_MIN_CLIENT_VERSION)
    client_version = WAMBLE_MIN_CLIENT_VERSION;

  if (client_version > WAMBLE_PROTO_VERSION) {
    struct WambleMsg err = {0};
    err.ctrl = WAMBLE_CTRL_ERROR;
    memcpy(err.token, msg->token, TOKEN_LENGTH);
    err.error_code = WAMBLE_ERR_UNSUPPORTED_VERSION;
    snprintf(err.error_reason, sizeof(err.error_reason),
             "upgrade required (client=%u server=%u)", client_version,
             WAMBLE_PROTO_VERSION);
    (void)send_reliable_message(sockfd, &err, cliaddr, get_config()->timeout_ms,
                                get_config()->max_retries);
    LOG_WARN("Rejected client %s: protocol version %u unsupported", token_str,
             client_version);
    return;
  }

  const uint8_t supported_caps =
      (uint8_t)(WAMBLE_CAP_HOT_RELOAD | WAMBLE_CAP_PROFILE_STATE);
  uint8_t requested_caps = (uint8_t)(msg->flags & WAMBLE_CAPABILITY_MASK);
  uint8_t negotiated_caps = requested_caps
                                ? (uint8_t)(requested_caps & supported_caps)
                                : supported_caps;

  WamblePlayer *player = get_player_by_token(msg->token);
  if (!player) {
    LOG_DEBUG("Player not found for token %s, creating new player", token_str);
    player = create_new_player();
    if (!player) {
      LOG_ERROR("Failed to create new player");
      return;
    }
    char new_token_str[TOKEN_LENGTH * 2 + 1];
    format_token_for_url(player->token, new_token_str);
    LOG_DEBUG("Created new player with token: %s", new_token_str);
  }

  WambleBoard *board = find_board_for_player(player);
  if (!board) {
    LOG_ERROR("Failed to find board for player %s", token_str);
    return;
  }
  LOG_DEBUG("Found board %lu for player %s", board->id, token_str);

  struct WambleMsg response = {0};
  response.ctrl = WAMBLE_CTRL_SERVER_HELLO;
  response.flags = negotiated_caps;
  response.header_version = (uint8_t)client_version;
  memcpy(response.token, player->token, TOKEN_LENGTH);
  response.board_id = board->id;
  response.seq_num = WAMBLE_PROTO_VERSION;
  {
    size_t __len = strnlen(board->fen, FEN_MAX_LENGTH - 1);
    memcpy(response.fen, board->fen, __len);
    response.fen[__len] = '\0';
  }
  LOG_DEBUG("Sending Server Hello response (board_id: %lu, fen: %s)",
            response.board_id, response.fen);
  LOG_DEBUG("Negotiated protocol version %u with caps 0x%02x for %s",
            client_version, negotiated_caps, token_str);

  if (send_reliable_message(sockfd, &response, cliaddr,
                            get_config()->timeout_ms,
                            get_config()->max_retries) != 0) {
    LOG_WARN("Failed to send reliable response to client hello for player %s",
             token_str);
  }
}

static void handle_player_move(int sockfd, const struct WambleMsg *msg,
                               const struct sockaddr_in *cliaddr) {
  char token_str[TOKEN_LENGTH * 2 + 1];
  format_token_for_url(msg->token, token_str);
  LOG_DEBUG("Received Player Move from token: %s for board %lu", token_str,
            msg->board_id);

  WamblePlayer *player = get_player_by_token(msg->token);
  if (!player) {
    LOG_WARN("Move from unknown player (token: %s)", token_str);
    return;
  }

  WambleBoard *board = get_board_by_id(msg->board_id);
  if (!board) {
    LOG_WARN("Move for unknown board: %lu from player %s", msg->board_id,
             token_str);
    return;
  }

  char uci_move[MAX_UCI_LENGTH + 1];
  uint8_t uci_len =
      msg->uci_len < MAX_UCI_LENGTH ? msg->uci_len : MAX_UCI_LENGTH;
  memcpy(uci_move, msg->uci, uci_len);
  uci_move[uci_len] = '\0';
  LOG_DEBUG("Player %s attempting move %s on board %lu", token_str, uci_move,
            board->id);

  MoveApplyStatus mv_status = MOVE_ERR_INVALID_ARGS;
  int mv_ok =
      validate_and_apply_move_status(board, player, uci_move, &mv_status);
  if (mv_ok == 0) {
    LOG_INFO("Move %s on board %lu by %s validated and applied", uci_move,
             board->id, token_str);

    uint64_t session_id = db_get_session_by_token(player->token);
    if (session_id > 0) {
      db_async_record_move(board->id, session_id, uci_move,
                           board->board.fullmove_number);
      LOG_DEBUG("Persisted move for session %lu on board %lu (move #%d)",
                session_id, board->id, board->board.fullmove_number);
    } else {
      LOG_WARN("No session found for player %s; skipping move persistence",
               token_str);
    }

    board_move_played(board->id);
    LOG_DEBUG("Recorded move played event for board %lu", board->id);

    LOG_DEBUG("Releasing board %lu after successful move", board->id);
    board_release_reservation(board->id);

    if (board->result != GAME_RESULT_IN_PROGRESS) {
      LOG_INFO("Game on board %lu has ended. Result: %d", board->id,
               board->result);
      board_game_completed(board->id, board->result);
    }

    WambleBoard *next_board = find_board_for_player(player);
    if (!next_board) {
      LOG_ERROR("Failed to find next board for player %s after move",
                token_str);
      return;
    }
    LOG_DEBUG("Found next board %lu for player %s", next_board->id, token_str);

    struct WambleMsg response;
    response.ctrl = WAMBLE_CTRL_BOARD_UPDATE;
    memcpy(response.token, player->token, TOKEN_LENGTH);
    response.board_id = next_board->id;
    response.seq_num = 0;
    response.uci_len = 0;
    {
      size_t __len = strnlen(next_board->fen, FEN_MAX_LENGTH - 1);
      memcpy(response.fen, next_board->fen, __len);
      response.fen[__len] = '\0';
    }
    LOG_DEBUG(
        "Sending Board Update response (board_id: %lu, fen: %s) to player %s",
        response.board_id, response.fen, token_str);

    if (send_reliable_message(sockfd, &response, cliaddr,
                              get_config()->timeout_ms,
                              get_config()->max_retries) != 0) {
      LOG_WARN("Failed to send reliable response to player move for player %s",
               token_str);
    } else {
      LOG_INFO("Player %s moved to new board %lu", token_str, next_board->id);
    }
  } else {
    switch (mv_status) {
    case MOVE_ERR_INVALID_ARGS:
      LOG_WARN("Move rejected: invalid arguments for player %s on board %lu",
               token_str, board->id);
      break;
    case MOVE_ERR_NOT_RESERVED:
      LOG_WARN("Move rejected: board %lu not reserved for player %s (uci %s)",
               board->id, token_str, uci_move);
      break;
    case MOVE_ERR_NOT_TURN:
      LOG_WARN(
          "Move rejected: not player's turn on board %lu (player %s, uci %s)",
          board->id, token_str, uci_move);
      break;
    case MOVE_ERR_BAD_UCI:
      LOG_WARN("Move rejected: invalid UCI '%s' (player %s, board %lu)",
               uci_move, token_str, board->id);
      break;
    case MOVE_ERR_ILLEGAL:
      LOG_WARN("Move rejected: illegal move %s on board %lu by player %s",
               uci_move, board->id, token_str);
      break;
    default:
      LOG_WARN("Move rejected: unknown reason for %s on board %lu by %s",
               uci_move, board->id, token_str);
      break;
    }
  }
}

void handle_message(int sockfd, const struct WambleMsg *msg,
                    const struct sockaddr_in *cliaddr) {
  switch (msg->ctrl) {
  case WAMBLE_CTRL_CLIENT_HELLO:
    LOG_DEBUG("Handling CLIENT_HELLO message (seq: %u)", msg->seq_num);
    handle_client_hello(sockfd, msg, cliaddr);
    break;
  case WAMBLE_CTRL_PLAYER_MOVE:
    LOG_DEBUG("Handling PLAYER_MOVE message (seq: %u)", msg->seq_num);
    if ((msg->flags & WAMBLE_FLAG_UNRELIABLE) == 0)
      send_ack(sockfd, msg, cliaddr);
    handle_player_move(sockfd, msg, cliaddr);
    break;
  case WAMBLE_CTRL_LIST_PROFILES: {
    LOG_DEBUG("Handling LIST_PROFILES message (seq: %u)", msg->seq_num);
    struct WambleMsg resp = {0};
    resp.ctrl = WAMBLE_CTRL_PROFILES_LIST;
    memcpy(resp.token, msg->token, TOKEN_LENGTH);

    int trust = db_get_trust_tier_by_token(msg->token);
    int count = config_profile_count();
    int written = 0;
    for (int i = 0; i < count; i++) {
      const WambleProfile *p = config_get_profile(i);
      if (!p || !p->advertise)
        continue;

      if (trust < p->visibility)
        continue;
      const char *name = p->name ? p->name : "";
      int need = (int)strlen(name);
      if (written + need + (written ? 1 : 0) >= FEN_MAX_LENGTH)
        break;
      if (written) {
        resp.fen[written++] = ',';
      }
      memcpy(&resp.fen[written], name, (size_t)need);
      written += need;
    }
    if (written < FEN_MAX_LENGTH)
      resp.fen[written] = '\0';
    (void)send_reliable_message(sockfd, &resp, cliaddr,
                                get_config()->timeout_ms,
                                get_config()->max_retries);
    break;
  }
  case WAMBLE_CTRL_GET_PROFILE_INFO: {
    LOG_DEBUG("Handling GET_PROFILE_INFO message (seq: %u)", msg->seq_num);
    char name[MAX_UCI_LENGTH + 1];
    int nlen = msg->uci_len < MAX_UCI_LENGTH ? msg->uci_len : MAX_UCI_LENGTH;
    memcpy(name, msg->uci, (size_t)nlen);
    name[nlen] = '\0';
    const WambleProfile *p = config_find_profile(name);
    struct WambleMsg resp = {0};
    resp.ctrl = WAMBLE_CTRL_PROFILE_INFO;
    memcpy(resp.token, msg->token, TOKEN_LENGTH);
    if (p) {
      snprintf(resp.fen, FEN_MAX_LENGTH, "%s;%d;%d;%d", p->name, p->config.port,
               p->advertise, p->visibility);
    } else {
      snprintf(resp.fen, FEN_MAX_LENGTH, "NOTFOUND;%s", name);
    }
    (void)send_reliable_message(sockfd, &resp, cliaddr,
                                get_config()->timeout_ms,
                                get_config()->max_retries);
    break;
  }
  case WAMBLE_CTRL_LOGIN_REQUEST: {
    LOG_DEBUG("Handling LOGIN_REQUEST message (seq: %u)", msg->seq_num);
    WamblePlayer *player = NULL;
    if (msg->login_pubkey[0] || msg->login_pubkey[31]) {
      player = login_player(msg->login_pubkey);
    }
    struct WambleMsg response = {0};
    if (player) {
      response.ctrl = WAMBLE_CTRL_LOGIN_SUCCESS;
      memcpy(response.token, player->token, TOKEN_LENGTH);
      char token_str[TOKEN_LENGTH * 2 + 1];
      format_token_for_url(player->token, token_str);
      LOG_INFO("Login success: player %s", token_str);
    } else {
      response.ctrl = WAMBLE_CTRL_LOGIN_FAILED;
      response.error_code = 1;
      snprintf(response.error_reason, sizeof(response.error_reason),
               "invalid or missing public key");
      LOG_WARN("Login failed: invalid or missing public key");
    }
    send_reliable_message(sockfd, &response, cliaddr, get_config()->timeout_ms,
                          get_config()->max_retries);
    break;
  }
  case WAMBLE_CTRL_SPECTATE_GAME: {
    LOG_DEBUG("Handling SPECTATE_GAME message (seq: %u, board=%lu)",
              msg->seq_num, msg->board_id);
    if ((msg->flags & WAMBLE_FLAG_UNRELIABLE) == 0)
      send_ack(sockfd, msg, cliaddr);
    SpectatorState new_state = SPECTATOR_STATE_IDLE;
    uint64_t focus_id = 0;
    SpectatorRequestStatus res =
        spectator_handle_request(msg, cliaddr, &new_state, &focus_id);
    if (!(res == SPECTATOR_OK_FOCUS || res == SPECTATOR_OK_SUMMARY ||
          res == SPECTATOR_OK_STOP)) {
      struct WambleMsg out = {0};
      out.ctrl = WAMBLE_CTRL_ERROR;
      memcpy(out.token, msg->token, TOKEN_LENGTH);
      out.error_code = (uint16_t)(-res);
      out.error_reason[0] = '\0';
      (void)send_reliable_message(sockfd, &out, cliaddr,
                                  get_config()->timeout_ms,
                                  get_config()->max_retries);
    } else {
      if (res == SPECTATOR_OK_FOCUS) {
        LOG_INFO("Spectator focus set to board %lu", focus_id);
      } else if (res == SPECTATOR_OK_SUMMARY) {
        LOG_INFO("Spectator summary mode enabled");
      }
    }
    break;
  }
  case WAMBLE_CTRL_SPECTATE_STOP: {
    LOG_DEBUG("Handling SPECTATE_STOP message (seq: %u)", msg->seq_num);
    if ((msg->flags & WAMBLE_FLAG_UNRELIABLE) == 0)
      send_ack(sockfd, msg, cliaddr);
    SpectatorState new_state = SPECTATOR_STATE_IDLE;
    uint64_t focus_id = 0;
    (void)spectator_handle_request(msg, cliaddr, &new_state, &focus_id);
    LOG_INFO("Spectator stopped; state now IDLE");
    break;
  }
  case WAMBLE_CTRL_GET_PLAYER_STATS: {
    LOG_DEBUG("Handling GET_PLAYER_STATS message (seq: %u)", msg->seq_num);
    WamblePlayer *player = get_player_by_token(msg->token);
    if (player) {
      struct WambleMsg response;
      response.ctrl = WAMBLE_CTRL_PLAYER_STATS_DATA;
      memcpy(response.token, player->token, TOKEN_LENGTH);
      send_reliable_message(sockfd, &response, cliaddr,
                            get_config()->timeout_ms,
                            get_config()->max_retries);
    }
    break;
  }
  case WAMBLE_CTRL_GET_LEGAL_MOVES: {
    LOG_DEBUG(
        "Handling GET_LEGAL_MOVES message (seq: %u, board=%lu, square=%u)",
        msg->seq_num, msg->board_id, (unsigned)msg->move_square);
    WamblePlayer *player = get_player_by_token(msg->token);
    if (!player) {
      LOG_WARN("Legal move request from unknown player token");
      break;
    }

    WambleBoard *board = get_board_by_id(msg->board_id);
    if (!board) {
      LOG_WARN("Legal move request for unknown board: %lu", msg->board_id);
      break;
    }

    struct WambleMsg response = {0};
    response.ctrl = WAMBLE_CTRL_LEGAL_MOVES;
    memcpy(response.token, msg->token, TOKEN_LENGTH);
    response.board_id = msg->board_id;
    response.move_square = msg->move_square;

    if (!tokens_equal(board->reservation_player_token, player->token)) {
      LOG_DEBUG(
          "Player token mismatch for board %lu when requesting legal moves",
          board->id);
      response.move_count = 0;
    } else if (msg->move_square >= 64) {
      LOG_WARN("Invalid square %u in legal move request for board %lu",
               (unsigned)msg->move_square, board->id);
      response.move_count = 0;
    } else {
      Move moves[WAMBLE_MAX_LEGAL_MOVES];
      int count = get_legal_moves_for_square(&board->board, msg->move_square,
                                             moves, WAMBLE_MAX_LEGAL_MOVES);
      if (count < 0) {
        LOG_WARN("Failed to compute legal moves for board %lu square %u",
                 board->id, (unsigned)msg->move_square);
        response.move_count = 0;
      } else {
        if (count > WAMBLE_MAX_LEGAL_MOVES)
          count = WAMBLE_MAX_LEGAL_MOVES;
        response.move_count = (uint8_t)count;
        for (int i = 0; i < count; i++) {
          response.moves[i].from = (uint8_t)moves[i].from;
          response.moves[i].to = (uint8_t)moves[i].to;
          response.moves[i].promotion = (int8_t)moves[i].promotion;
        }
      }
    }

    (void)send_reliable_message(sockfd, &response, cliaddr,
                                get_config()->timeout_ms,
                                get_config()->max_retries);
    break;
  }
  case WAMBLE_CTRL_ACK:
    LOG_DEBUG("Handling ACK message (seq: %u)", msg->seq_num);
    break;
  default:
    if ((msg->flags & WAMBLE_FLAG_UNRELIABLE) == 0)
      send_ack(sockfd, msg, cliaddr);
    LOG_WARN("Unknown message type: 0x%02x", msg->ctrl);
    break;
  }
}
