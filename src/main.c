#define _POSIX_C_SOURCE 200809L
#include "../include/wamble/wamble.h"
#include <signal.h>
#include <string.h>

void handle_message(int sockfd, const struct WambleMsg *msg,
                    const struct sockaddr_in *cliaddr);
WamblePlayer *login_player(const uint8_t *public_key);

static volatile sig_atomic_t g_reload_requested = 0;
static volatile sig_atomic_t g_shutdown_requested = 0;

static void handle_sighup(int signo) {
  (void)signo;
  g_reload_requested = 1;
}

static void handle_sigterm(int signo) {
  (void)signo;
  g_shutdown_requested = 1;
}

int main(int argc, char *argv[]) {
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

  config_load(config_file, profile);

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_sighup;
  sigaction(SIGHUP, &sa, NULL);

  struct sigaction sb;
  memset(&sb, 0, sizeof(sb));
  sb.sa_handler = handle_sigterm;
  sigaction(SIGINT, &sb, NULL);
  sigaction(SIGTERM, &sb, NULL);

  char db_conn_str[256];
  snprintf(db_conn_str, sizeof(db_conn_str),
           "dbname=%s user=%s password=%s host=%s", get_config()->db_name,
           get_config()->db_user, get_config()->db_pass, get_config()->db_host);

  if (db_init(db_conn_str) != 0) {
    LOG_FATAL("Failed to initialize database");
    return 1;
  }
  LOG_INFO("Database initialized successfully");

  start_network_listener();
  LOG_INFO("Network listener started");

  int has_profiles = config_profile_count();
  if (has_profiles > 0) {

    int started = start_profile_listeners();
    if (started <= 0) {
      LOG_WARN("No profile listeners started; falling back to default port");
    } else {
      LOG_INFO("Started %d profile listener(s)", started);
    }
  }

  int sockfd = -1;
  if (has_profiles == 0) {

    player_manager_init();
    LOG_INFO("Player manager initialized");
    board_manager_init();
    LOG_INFO("Board manager initialized");
    sockfd = create_and_bind_socket(get_config()->port);
    if (sockfd < 0) {
      LOG_FATAL("Failed to create and bind socket");
      return 1;
    }
    LOG_INFO("Server listening on port %d", get_config()->port);
  }

  time_t last_cleanup = time(NULL);
  time_t last_tick = time(NULL);

  LOG_INFO("Server main loop starting");
  while (!g_shutdown_requested) {
    LOG_DEBUG("Main loop iteration start");
    if (sockfd >= 0) {
      fd_set rfds;
      struct timeval tv;
      FD_ZERO(&rfds);
      FD_SET(sockfd, &rfds);
      tv.tv_sec = 0;
      tv.tv_usec = get_config()->select_timeout_usec;

      int ready = select(sockfd + 1, &rfds, NULL, NULL, &tv);
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

      struct timespec ts = {.tv_sec = 0, .tv_nsec = 10000000};
      nanosleep(&ts, NULL);
    }

    time_t now = time(NULL);
    if (now - last_cleanup > get_config()->cleanup_interval_sec) {
      LOG_INFO("Cleaning up expired client sessions");
      cleanup_expired_sessions();
      last_cleanup = now;
      LOG_INFO("Finished cleaning up expired client sessions");
    }

    if (has_profiles == 0) {
      if (now - last_tick > 1) {
        board_manager_tick();
        db_tick();
        last_tick = now;
      }
    }
    if (g_reload_requested) {
      LOG_INFO("Reload requested; reloading config and reconciling listeners");
      config_load(config_file, profile);
      if (config_profile_count() > 0) {
        reconcile_profile_listeners();
      }
      g_reload_requested = 0;
    }

    LOG_DEBUG("Main loop iteration end");
  }
  LOG_INFO("Server main loop ending");

  if (config_profile_count() > 0) {
    stop_profile_listeners();
  }
  if (sockfd >= 0) {
    close(sockfd);
  }
  db_cleanup();

  return 0;
}

static void handle_client_hello(int sockfd, const struct WambleMsg *msg,
                                const struct sockaddr_in *cliaddr) {
  char token_str[TOKEN_LENGTH * 2 + 1];
  format_token_for_url(msg->token, token_str);
  LOG_INFO("Received Client Hello from token: %s", token_str);

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

  struct WambleMsg response;
  response.ctrl = WAMBLE_CTRL_SERVER_HELLO;
  memcpy(response.token, player->token, TOKEN_LENGTH);
  response.board_id = board->id;
  response.seq_num = 0;
  response.uci_len = 0;
  strncpy(response.fen, board->fen, FEN_MAX_LENGTH);
  LOG_DEBUG("Sending Server Hello response (board_id: %lu, fen: %s)",
            response.board_id, response.fen);

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
  LOG_INFO("Received Player Move from token: %s for board %lu", token_str,
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

  if (validate_and_apply_move(board, player, uci_move) == 0) {
    LOG_INFO("Move %s on board %lu validated and applied", uci_move, board->id);

    LOG_DEBUG("Releasing board %lu after successful move", board->id);
    release_board(board->id);

    if (board->result != GAME_RESULT_IN_PROGRESS) {
      LOG_INFO("Game on board %lu has ended. Result: %d", board->id,
               board->result);
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
    strncpy(response.fen, next_board->fen, FEN_MAX_LENGTH);
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
    LOG_WARN("Invalid move %s on board %lu by player %s", uci_move, board->id,
             token_str);
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
    } else {
      response.ctrl = WAMBLE_CTRL_LOGIN_FAILED;
      response.error_code = 1;
      snprintf(response.error_reason, sizeof(response.error_reason),
               "invalid or missing public key");
    }
    send_reliable_message(sockfd, &response, cliaddr, get_config()->timeout_ms,
                          get_config()->max_retries);
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
