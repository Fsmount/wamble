#include "../include/wamble/wamble.h"
#include <string.h>

void handle_message(int sockfd, const struct WambleMsg *msg,
                    const struct sockaddr_in *cliaddr);

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

  char db_conn_str[256];
  snprintf(db_conn_str, sizeof(db_conn_str),
           "dbname=%s user=%s password=%s host=%s", get_config()->db_name,
           get_config()->db_user, get_config()->db_pass, get_config()->db_host);

  if (db_init(db_conn_str) != 0) {
    LOG_FATAL("Failed to initialize database");
    return 1;
  }
  LOG_INFO("Database initialized successfully");

  player_manager_init();
  LOG_INFO("Player manager initialized");
  board_manager_init();
  LOG_INFO("Board manager initialized");

  if (start_board_manager_thread() != 0) {
    LOG_FATAL("Failed to start board manager thread");
    return 1;
  }
  LOG_INFO("Board manager thread started");

  start_network_listener();
  LOG_INFO("Network listener started");

  int sockfd = create_and_bind_socket(get_config()->port);
  if (sockfd < 0) {
    LOG_FATAL("Failed to create and bind socket");
    return 1;
  }

  LOG_INFO("Server listening on port %d", get_config()->port);

  time_t last_cleanup = time(NULL);
  time_t last_tick = time(NULL);

  LOG_INFO("Server main loop starting");
  while (1) {
    LOG_DEBUG("Main loop iteration start");
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

    time_t now = time(NULL);
    if (now - last_cleanup > get_config()->cleanup_interval_sec) {
      LOG_INFO("Cleaning up expired client sessions");
      cleanup_expired_sessions();
      last_cleanup = now;
      LOG_INFO("Finished cleaning up expired client sessions");
    }

#ifdef WAMBLE_SINGLE_THREADED
    if (now - last_tick > 1) {
      board_manager_tick();
      db_tick();
      last_tick = now;
    }
#endif
    LOG_DEBUG("Main loop iteration end");
  }
  LOG_INFO("Server main loop ending");

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

  if (msg->ctrl != WAMBLE_CTRL_ACK) {
    send_ack(sockfd, msg, cliaddr);
    LOG_DEBUG("Sent ACK for message type 0x%02x (seq: %u)", msg->ctrl,
              msg->seq_num);
  }

  switch (msg->ctrl) {
  case WAMBLE_CTRL_CLIENT_HELLO:
    LOG_DEBUG("Handling CLIENT_HELLO message (seq: %u)", msg->seq_num);
    handle_client_hello(sockfd, msg, cliaddr);
    break;
  case WAMBLE_CTRL_PLAYER_MOVE:
    LOG_DEBUG("Handling PLAYER_MOVE message (seq: %u)", msg->seq_num);
    handle_player_move(sockfd, msg, cliaddr);
    break;
  case WAMBLE_CTRL_ACK:
    LOG_DEBUG("Handling ACK message (seq: %u)", msg->seq_num);
    break;
  default:
    LOG_WARN("Unknown message type: 0x%02x", msg->ctrl);
    break;
  }
}
