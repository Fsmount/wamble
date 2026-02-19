#include "../include/wamble/wamble.h"

static ServerStatus handle_client_hello(wamble_socket_t sockfd,
                                        const struct WambleMsg *msg,
                                        const struct sockaddr_in *cliaddr) {
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
    return SERVER_ERR_UNSUPPORTED_VERSION;
  }

  const uint8_t supported_caps =
      (uint8_t)(WAMBLE_CAP_HOT_RELOAD | WAMBLE_CAP_PROFILE_STATE);
  uint8_t requested_caps = (uint8_t)(msg->flags & WAMBLE_CAPABILITY_MASK);
  uint8_t negotiated_caps = requested_caps
                                ? (uint8_t)(requested_caps & supported_caps)
                                : supported_caps;

  WamblePlayer *player = get_player_by_token(msg->token);
  if (!player) {
    player = create_new_player();
    if (!player) {
      return SERVER_ERR_INTERNAL;
    }
  }

  WambleBoard *board = find_board_for_player(player);
  if (!board) {
    return SERVER_ERR_UNKNOWN_BOARD;
  }

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

  if (send_reliable_message(sockfd, &response, cliaddr,
                            get_config()->timeout_ms,
                            get_config()->max_retries) != 0) {
    return SERVER_ERR_SEND_FAILED;
  }

  return SERVER_OK;
}

static ServerStatus handle_player_move(wamble_socket_t sockfd,
                                       const struct WambleMsg *msg,
                                       const struct sockaddr_in *cliaddr) {
  WamblePlayer *player = get_player_by_token(msg->token);
  if (!player) {
    return SERVER_ERR_UNKNOWN_PLAYER;
  }

  WambleBoard *board = get_board_by_id(msg->board_id);
  if (!board) {
    return SERVER_ERR_UNKNOWN_BOARD;
  }

  char uci_move[MAX_UCI_LENGTH + 1];
  uint8_t uci_len =
      msg->uci_len < MAX_UCI_LENGTH ? msg->uci_len : MAX_UCI_LENGTH;
  memcpy(uci_move, msg->uci, uci_len);
  uci_move[uci_len] = '\0';

  MoveApplyStatus mv_status = MOVE_ERR_INVALID_ARGS;
  int mv_ok =
      validate_and_apply_move_status(board, player, uci_move, &mv_status);
  if (mv_ok != 0) {
    return SERVER_ERR_MOVE_REJECTED;
  }

  wamble_emit_record_move(board->id, player->token, uci_move,
                          board->board.fullmove_number);

  board_move_played(board->id);
  board_release_reservation(board->id);

  if (board->result != GAME_RESULT_IN_PROGRESS) {
    board_game_completed(board->id, board->result);
  }

  WambleBoard *next_board = find_board_for_player(player);
  if (!next_board) {
    return SERVER_ERR_INTERNAL;
  }

  struct WambleMsg response;
  memset(&response, 0, sizeof(response));
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

  if (send_reliable_message(sockfd, &response, cliaddr,
                            get_config()->timeout_ms,
                            get_config()->max_retries) != 0) {
    return SERVER_ERR_SEND_FAILED;
  }

  return SERVER_OK;
}

ServerStatus handle_message(wamble_socket_t sockfd, const struct WambleMsg *msg,
                            const struct sockaddr_in *cliaddr, int trust_tier) {
  switch (msg->ctrl) {
  case WAMBLE_CTRL_CLIENT_HELLO:
    return handle_client_hello(sockfd, msg, cliaddr);
  case WAMBLE_CTRL_PLAYER_MOVE:
    if ((msg->flags & WAMBLE_FLAG_UNRELIABLE) == 0)
      send_ack(sockfd, msg, cliaddr);
    return handle_player_move(sockfd, msg, cliaddr);
  case WAMBLE_CTRL_LIST_PROFILES: {
    struct WambleMsg resp = {0};
    resp.ctrl = WAMBLE_CTRL_PROFILES_LIST;
    memcpy(resp.token, msg->token, TOKEN_LENGTH);

    int count = config_profile_count();
    int written = 0;
    for (int i = 0; i < count; i++) {
      const WambleProfile *p = config_get_profile(i);
      if (!p || !p->advertise)
        continue;

      if (trust_tier < p->visibility)
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
    if (send_reliable_message(sockfd, &resp, cliaddr, get_config()->timeout_ms,
                              get_config()->max_retries) != 0) {
      return SERVER_ERR_SEND_FAILED;
    }
    return SERVER_OK;
  }
  case WAMBLE_CTRL_GET_PROFILE_INFO: {
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
    if (send_reliable_message(sockfd, &resp, cliaddr, get_config()->timeout_ms,
                              get_config()->max_retries) != 0) {
      return SERVER_ERR_SEND_FAILED;
    }
    return SERVER_OK;
  }
  case WAMBLE_CTRL_LOGIN_REQUEST: {
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
    if (send_reliable_message(sockfd, &response, cliaddr,
                              get_config()->timeout_ms,
                              get_config()->max_retries) != 0) {
      return SERVER_ERR_SEND_FAILED;
    }
    return player ? SERVER_OK : SERVER_ERR_LOGIN_FAILED;
  }
  case WAMBLE_CTRL_SPECTATE_GAME: {
    if ((msg->flags & WAMBLE_FLAG_UNRELIABLE) == 0)
      send_ack(sockfd, msg, cliaddr);
    SpectatorState new_state = SPECTATOR_STATE_IDLE;
    uint64_t focus_id = 0;
    SpectatorRequestStatus res = spectator_handle_request(
        msg, cliaddr, trust_tier, &new_state, &focus_id);
    if (!(res == SPECTATOR_OK_FOCUS || res == SPECTATOR_OK_SUMMARY ||
          res == SPECTATOR_OK_STOP)) {
      struct WambleMsg out = {0};
      out.ctrl = WAMBLE_CTRL_ERROR;
      memcpy(out.token, msg->token, TOKEN_LENGTH);
      out.error_code = (uint16_t)(-res);
      out.error_reason[0] = '\0';
      if (send_reliable_message(sockfd, &out, cliaddr, get_config()->timeout_ms,
                                get_config()->max_retries) != 0) {
        return SERVER_ERR_SEND_FAILED;
      }
      return SERVER_ERR_SPECTATOR;
    }
    return SERVER_OK;
  }
  case WAMBLE_CTRL_SPECTATE_STOP: {
    if ((msg->flags & WAMBLE_FLAG_UNRELIABLE) == 0)
      send_ack(sockfd, msg, cliaddr);
    SpectatorState new_state = SPECTATOR_STATE_IDLE;
    uint64_t focus_id = 0;
    (void)spectator_handle_request(msg, cliaddr, trust_tier, &new_state,
                                   &focus_id);
    return SERVER_OK;
  }
  case WAMBLE_CTRL_GET_PLAYER_STATS: {
    WamblePlayer *player = get_player_by_token(msg->token);
    if (player) {
      struct WambleMsg response;
      memset(&response, 0, sizeof(response));
      response.ctrl = WAMBLE_CTRL_PLAYER_STATS_DATA;
      memcpy(response.token, player->token, TOKEN_LENGTH);
      if (send_reliable_message(sockfd, &response, cliaddr,
                                get_config()->timeout_ms,
                                get_config()->max_retries) != 0) {
        return SERVER_ERR_SEND_FAILED;
      }
      return SERVER_OK;
    }
    return SERVER_ERR_UNKNOWN_PLAYER;
  }
  case WAMBLE_CTRL_GET_LEADERBOARD: {
    uint8_t lb_type = msg->leaderboard_type;
    if (lb_type != WAMBLE_LEADERBOARD_RATING)
      lb_type = WAMBLE_LEADERBOARD_SCORE;
    uint64_t requester_session_id = 0;
    if (wamble_query_get_session_by_token(msg->token, &requester_session_id) !=
        DB_OK) {
      requester_session_id = 0;
    }
    int limit = msg->leaderboard_limit ? (int)msg->leaderboard_limit : 10;
    DbLeaderboardResult lb =
        wamble_query_get_leaderboard(requester_session_id, lb_type, limit);
    if (lb.status != DB_OK) {
      return SERVER_ERR_INTERNAL;
    }
    struct WambleMsg response = {0};
    response.ctrl = WAMBLE_CTRL_LEADERBOARD_DATA;
    memcpy(response.token, msg->token, TOKEN_LENGTH);
    response.leaderboard_type = lb_type;
    response.leaderboard_self_rank = lb.self_rank;
    int count = lb.count;
    if (count < 0)
      count = 0;
    if (count > WAMBLE_MAX_LEADERBOARD_ENTRIES)
      count = WAMBLE_MAX_LEADERBOARD_ENTRIES;
    response.leaderboard_count = (uint8_t)count;
    for (int i = 0; i < count; i++) {
      response.leaderboard[i].rank = lb.rows[i].rank;
      response.leaderboard[i].session_id = lb.rows[i].session_id;
      response.leaderboard[i].score = lb.rows[i].score;
      response.leaderboard[i].rating = lb.rows[i].rating;
      response.leaderboard[i].games_played = lb.rows[i].games_played;
    }
    if (send_reliable_message(sockfd, &response, cliaddr,
                              get_config()->timeout_ms,
                              get_config()->max_retries) != 0) {
      return SERVER_ERR_SEND_FAILED;
    }
    return SERVER_OK;
  }
  case WAMBLE_CTRL_GET_LEGAL_MOVES: {
    WamblePlayer *player = get_player_by_token(msg->token);
    if (!player) {
      return SERVER_ERR_UNKNOWN_PLAYER;
    }

    WambleBoard *board = get_board_by_id(msg->board_id);
    if (!board) {
      return SERVER_ERR_UNKNOWN_BOARD;
    }

    struct WambleMsg response = {0};
    response.ctrl = WAMBLE_CTRL_LEGAL_MOVES;
    memcpy(response.token, msg->token, TOKEN_LENGTH);
    response.board_id = msg->board_id;
    response.move_square = msg->move_square;

    if (!tokens_equal(board->reservation_player_token, player->token)) {
      response.move_count = 0;
    } else if (msg->move_square >= 64) {
      response.move_count = 0;
      return SERVER_ERR_LEGAL_MOVES;
    } else {
      Move moves[WAMBLE_MAX_LEGAL_MOVES];
      int count = get_legal_moves_for_square(&board->board, msg->move_square,
                                             moves, WAMBLE_MAX_LEGAL_MOVES);
      if (count < 0) {
        response.move_count = 0;
        return SERVER_ERR_LEGAL_MOVES;
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

    if (send_reliable_message(sockfd, &response, cliaddr,
                              get_config()->timeout_ms,
                              get_config()->max_retries) != 0) {
      return SERVER_ERR_SEND_FAILED;
    }
    return SERVER_OK;
  }
  case WAMBLE_CTRL_ACK:
    return SERVER_OK;
  default:
    if ((msg->flags & WAMBLE_FLAG_UNRELIABLE) == 0)
      send_ack(sockfd, msg, cliaddr);
    return SERVER_ERR_UNKNOWN_CTRL;
  }
}
