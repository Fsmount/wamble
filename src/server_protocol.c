#include "../include/wamble/wamble.h"
#include "../include/wamble/wamble_db.h"

typedef struct {
  int used;
  uint8_t token[TOKEN_LENGTH];
  uint64_t window_start_ms;
  int count;
} RequestRateLimitEntry;

static WAMBLE_THREAD_LOCAL RequestRateLimitEntry g_rate_limit_entries[1024];

static int policy_check(const uint8_t *token, const char *profile_name,
                        const char *action, const char *resource,
                        const char *context_key, const char *context_value,
                        WamblePolicyDecision *out_decision) {
  const WambleQueryService *qs = wamble_get_query_service();
  if (!qs || !qs->resolve_policy_decision)
    return 0;
  WamblePolicyDecision decision;
  DbStatus st =
      qs->resolve_policy_decision(token, profile_name, action, resource,
                                  context_key, context_value, &decision);
  if (st != DB_OK)
    return 0;
  if (out_decision)
    *out_decision = decision;
  return decision.allowed ? 1 : 0;
}

static int resolve_profile_trust_tier(const uint8_t *token,
                                      const char *profile_name) {
  const WambleQueryService *qs = wamble_get_query_service();
  if (!qs || !qs->resolve_policy_decision)
    return 0;
  WamblePolicyDecision trust_decision;
  DbStatus st = qs->resolve_policy_decision(
      token, profile_name, "trust.tier", "tier", NULL, NULL, &trust_decision);
  return (st == DB_OK && trust_decision.allowed)
             ? trust_decision.permission_level
             : 0;
}

typedef enum {
  DISCOVER_POLICY_NO_RULE = 0,
  DISCOVER_POLICY_ALLOW = 1,
  DISCOVER_POLICY_DENY = -1,
} DiscoverPolicyDecision;

static DiscoverPolicyDecision resolve_discovery_policy_for_action(
    const uint8_t *token, const WambleProfile *p, const char *action) {
  if (!token || !p || !p->name)
    return DISCOVER_POLICY_NO_RULE;
  const WambleQueryService *qs = wamble_get_query_service();
  if (!qs || !qs->resolve_policy_decision)
    return DISCOVER_POLICY_NO_RULE;

  WamblePolicyDecision decision;
  char resource[256];
  DbStatus st;

  snprintf(resource, sizeof(resource), "profile:%s", p->name);
  st = qs->resolve_policy_decision(token, p->name, action, resource, NULL, NULL,
                                   &decision);
  if (st == DB_OK && decision.rule_id > 0)
    return decision.allowed ? DISCOVER_POLICY_ALLOW : DISCOVER_POLICY_DENY;

  if (p->group && p->group[0]) {
    snprintf(resource, sizeof(resource), "profile_selector:%s", p->group);
    st = qs->resolve_policy_decision(token, p->name, action, resource, NULL,
                                     NULL, &decision);
    if (st == DB_OK && decision.rule_id > 0)
      return decision.allowed ? DISCOVER_POLICY_ALLOW : DISCOVER_POLICY_DENY;
  }

  st = qs->resolve_policy_decision(token, p->name, action, "*", NULL, NULL,
                                   &decision);
  if (st == DB_OK && decision.rule_id > 0)
    return decision.allowed ? DISCOVER_POLICY_ALLOW : DISCOVER_POLICY_DENY;
  return DISCOVER_POLICY_NO_RULE;
}

static int rate_limit_allowed(const uint8_t *token, int max_per_sec) {
  if (!token || max_per_sec <= 0)
    return 1;
  uint64_t now = wamble_now_mono_millis();
  int match_idx = -1;
  int free_idx = -1;
  int oldest_idx = 0;
  uint64_t oldest_ms = UINT64_MAX;
  for (int i = 0; i < (int)(sizeof(g_rate_limit_entries) /
                            sizeof(g_rate_limit_entries[0]));
       i++) {
    RequestRateLimitEntry *e = &g_rate_limit_entries[i];
    if (!e->used) {
      if (free_idx < 0)
        free_idx = i;
      continue;
    }
    if (tokens_equal(e->token, token)) {
      match_idx = i;
      break;
    }
    if (e->window_start_ms < oldest_ms) {
      oldest_ms = e->window_start_ms;
      oldest_idx = i;
    }
  }

  RequestRateLimitEntry *entry = NULL;
  if (match_idx >= 0) {
    entry = &g_rate_limit_entries[match_idx];
    if (now >= entry->window_start_ms + 1000) {
      entry->window_start_ms = now;
      entry->count = 0;
    }
  } else {
    int idx = (free_idx >= 0) ? free_idx : oldest_idx;
    entry = &g_rate_limit_entries[idx];
    entry->used = 1;
    memcpy(entry->token, token, TOKEN_LENGTH);
    entry->window_start_ms = now;
    entry->count = 0;
  }
  if (entry->count >= max_per_sec)
    return 0;
  entry->count++;
  return 1;
}

static int profile_discovery_allowed(const uint8_t *token,
                                     const WambleProfile *p, int trust_tier) {
  if (!token || !p)
    return 0;
  (void)trust_tier;
  DiscoverPolicyDecision override = resolve_discovery_policy_for_action(
      token, p, "profile.discover.override");
  if (override == DISCOVER_POLICY_DENY)
    return 0;
  if (override == DISCOVER_POLICY_ALLOW)
    return 1;
  int effective_trust = resolve_profile_trust_tier(token, p->name);
  int default_visible =
      (p->advertise && effective_trust >= p->visibility) ? 1 : 0;
  DiscoverPolicyDecision policy =
      resolve_discovery_policy_for_action(token, p, "profile.discover");
  if (policy == DISCOVER_POLICY_DENY)
    return 0;
  if (policy == DISCOVER_POLICY_ALLOW)
    return 1;
  return default_visible;
}

static ServerStatus send_policy_denied(wamble_socket_t sockfd,
                                       const struct sockaddr_in *cliaddr,
                                       const uint8_t *token, const char *action,
                                       const char *resource,
                                       const WamblePolicyDecision *decision) {
  struct WambleMsg err = {0};
  err.ctrl = WAMBLE_CTRL_ERROR;
  memcpy(err.token, token, TOKEN_LENGTH);
  err.error_code = WAMBLE_ERR_ACCESS_DENIED;
  if (decision && decision->reason[0]) {
    snprintf(err.error_reason, sizeof(err.error_reason),
             "denied %.24s/%.24s: %.30s", action ? action : "",
             resource ? resource : "", decision->reason);
  } else {
    snprintf(err.error_reason, sizeof(err.error_reason), "denied %.24s/%.24s",
             action ? action : "", resource ? resource : "");
  }
  if (send_reliable_message(sockfd, &err, cliaddr, get_config()->timeout_ms,
                            get_config()->max_retries) != 0) {
    return SERVER_ERR_SEND_FAILED;
  }
  return SERVER_ERR_FORBIDDEN;
}

static const char *ctrl_policy_resource(uint8_t ctrl) {
  switch (ctrl) {
  case WAMBLE_CTRL_CLIENT_HELLO:
    return "client_hello";
  case WAMBLE_CTRL_SERVER_HELLO:
    return "server_hello";
  case WAMBLE_CTRL_PLAYER_MOVE:
    return "player_move";
  case WAMBLE_CTRL_BOARD_UPDATE:
    return "board_update";
  case WAMBLE_CTRL_ACK:
    return "ack";
  case WAMBLE_CTRL_LIST_PROFILES:
    return "list_profiles";
  case WAMBLE_CTRL_PROFILE_INFO:
    return "profile_info";
  case WAMBLE_CTRL_ERROR:
    return "error";
  case WAMBLE_CTRL_SERVER_NOTIFICATION:
    return "server_notification";
  case WAMBLE_CTRL_CLIENT_GOODBYE:
    return "client_goodbye";
  case WAMBLE_CTRL_SPECTATE_GAME:
    return "spectate_game";
  case WAMBLE_CTRL_SPECTATE_UPDATE:
    return "spectate_update";
  case WAMBLE_CTRL_LOGIN_REQUEST:
    return "login_request";
  case WAMBLE_CTRL_LOGOUT:
    return "logout";
  case WAMBLE_CTRL_LOGIN_SUCCESS:
    return "login_success";
  case WAMBLE_CTRL_LOGIN_FAILED:
    return "login_failed";
  case WAMBLE_CTRL_GET_PLAYER_STATS:
    return "get_player_stats";
  case WAMBLE_CTRL_PLAYER_STATS_DATA:
    return "player_stats_data";
  case WAMBLE_CTRL_GET_PROFILE_INFO:
    return "get_profile_info";
  case WAMBLE_CTRL_PROFILES_LIST:
    return "profiles_list";
  case WAMBLE_CTRL_SPECTATE_STOP:
    return "spectate_stop";
  case WAMBLE_CTRL_GET_LEGAL_MOVES:
    return "get_legal_moves";
  case WAMBLE_CTRL_LEGAL_MOVES:
    return "legal_moves";
  case WAMBLE_CTRL_GET_LEADERBOARD:
    return "get_leaderboard";
  case WAMBLE_CTRL_LEADERBOARD_DATA:
    return "leaderboard_data";
  default:
    return "unknown";
  }
}

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
                                       const struct sockaddr_in *cliaddr,
                                       const char *profile_name) {
  WamblePolicyDecision decision;
  memset(&decision, 0, sizeof(decision));
  if (!policy_check(msg->token, profile_name, "game.move", "play", NULL, NULL,
                    &decision)) {
    return send_policy_denied(sockfd, cliaddr, msg->token, "game.move", "play",
                              &decision);
  }
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
                            const struct sockaddr_in *cliaddr, int trust_tier,
                            const char *profile_name) {
  if (msg->ctrl != WAMBLE_CTRL_CLIENT_HELLO && msg->ctrl != WAMBLE_CTRL_ACK) {
    WamblePolicyDecision bypass = {0};
    const char *ctrl_res = ctrl_policy_resource(msg->ctrl);
    int bypass_rate_limit =
        policy_check(msg->token, profile_name, "rate_limit.bypass", "request",
                     "ctrl", ctrl_res, &bypass);
    int max_per_sec = get_config()->rate_limit_requests_per_sec;
    if (!bypass_rate_limit && !rate_limit_allowed(msg->token, max_per_sec)) {
      struct WambleMsg out = {0};
      out.ctrl = WAMBLE_CTRL_ERROR;
      memcpy(out.token, msg->token, TOKEN_LENGTH);
      out.error_code = WAMBLE_ERR_ACCESS_DENIED;
      snprintf(out.error_reason, sizeof(out.error_reason), "rate_limited");
      if (send_reliable_message(sockfd, &out, cliaddr, get_config()->timeout_ms,
                                get_config()->max_retries) != 0) {
        return SERVER_ERR_SEND_FAILED;
      }
      return SERVER_ERR_FORBIDDEN;
    }
  }
  if (msg->ctrl != WAMBLE_CTRL_CLIENT_HELLO && msg->ctrl != WAMBLE_CTRL_ACK &&
      msg->ctrl != WAMBLE_CTRL_LOGIN_REQUEST) {
    WamblePolicyDecision decision;
    memset(&decision, 0, sizeof(decision));
    const char *ctrl_res = ctrl_policy_resource(msg->ctrl);
    if (!policy_check(msg->token, profile_name, "protocol.ctrl", ctrl_res, NULL,
                      NULL, &decision)) {
      return send_policy_denied(sockfd, cliaddr, msg->token, "protocol.ctrl",
                                ctrl_res, &decision);
    }
  }
  switch (msg->ctrl) {
  case WAMBLE_CTRL_CLIENT_HELLO:
    return handle_client_hello(sockfd, msg, cliaddr);
  case WAMBLE_CTRL_PLAYER_MOVE:
    if ((msg->flags & WAMBLE_FLAG_UNRELIABLE) == 0)
      send_ack(sockfd, msg, cliaddr);
    return handle_player_move(sockfd, msg, cliaddr, profile_name);
  case WAMBLE_CTRL_LIST_PROFILES: {
    struct WambleMsg resp = {0};
    resp.ctrl = WAMBLE_CTRL_PROFILES_LIST;
    memcpy(resp.token, msg->token, TOKEN_LENGTH);

    int count = config_profile_count();
    int written = 0;
    for (int i = 0; i < count; i++) {
      const WambleProfile *p = config_get_profile(i);
      if (!p)
        continue;
      if (!profile_discovery_allowed(msg->token, p, trust_tier))
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
    if (p && profile_discovery_allowed(msg->token, p, trust_tier)) {
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
    int has_key = 0;
    for (int i = 0; i < 32; i++) {
      if (msg->login_pubkey[i] != 0) {
        has_key = 1;
        break;
      }
    }
    if (has_key) {
      player = attach_persistent_identity(msg->token, msg->login_pubkey);
    }
    struct WambleMsg response = {0};
    if (player) {
      response.ctrl = WAMBLE_CTRL_LOGIN_SUCCESS;
      memcpy(response.token, player->token, TOKEN_LENGTH);
    } else {
      response.ctrl = WAMBLE_CTRL_LOGIN_FAILED;
      response.error_code = 1;
      if (!has_key) {
        snprintf(response.error_reason, sizeof(response.error_reason),
                 "missing public key");
      } else {
        snprintf(response.error_reason, sizeof(response.error_reason),
                 "unknown session token; call CLIENT_HELLO first");
      }
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
    const char *spectate_mode = (msg->board_id == 0) ? "summary" : "focus";
    WamblePolicyDecision decision;
    memset(&decision, 0, sizeof(decision));
    if (!policy_check(msg->token, profile_name, "spectate.access", "view",
                      "mode", spectate_mode, &decision)) {
      struct WambleMsg out = {0};
      out.ctrl = WAMBLE_CTRL_ERROR;
      memcpy(out.token, msg->token, TOKEN_LENGTH);
      out.error_code = WAMBLE_ERR_ACCESS_DENIED;
      snprintf(out.error_reason, sizeof(out.error_reason),
               "denied spectate: %.48s",
               decision.reason[0] ? decision.reason : "policy");
      if (send_reliable_message(sockfd, &out, cliaddr, get_config()->timeout_ms,
                                get_config()->max_retries) != 0) {
        return SERVER_ERR_SEND_FAILED;
      }
      return SERVER_ERR_FORBIDDEN;
    }
    SpectatorState new_state = SPECTATOR_STATE_IDLE;
    uint64_t focus_id = 0;
    int capacity_bypass =
        policy_check(msg->token, profile_name, "spectate.capacity_bypass",
                     "focus", NULL, NULL, NULL);
    SpectatorRequestStatus res = spectator_handle_request(
        msg, cliaddr, trust_tier, capacity_bypass, &new_state, &focus_id);
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
    (void)spectator_handle_request(msg, cliaddr, trust_tier, 0, &new_state,
                                   &focus_id);
    return SERVER_OK;
  }
  case WAMBLE_CTRL_GET_PLAYER_STATS: {
    WamblePolicyDecision decision;
    memset(&decision, 0, sizeof(decision));
    if (!policy_check(msg->token, profile_name, "stats.read", "player", NULL,
                      NULL, &decision)) {
      return send_policy_denied(sockfd, cliaddr, msg->token, "stats.read",
                                "player", &decision);
    }
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
    WamblePolicyDecision decision;
    memset(&decision, 0, sizeof(decision));
    if (!policy_check(msg->token, profile_name, "leaderboard.read", "global",
                      NULL, NULL, &decision)) {
      return send_policy_denied(sockfd, cliaddr, msg->token, "leaderboard.read",
                                "global", &decision);
    }
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
    WamblePolicyDecision decision;
    memset(&decision, 0, sizeof(decision));
    if (!policy_check(msg->token, profile_name, "game.move", "legal", NULL,
                      NULL, &decision)) {
      return send_policy_denied(sockfd, cliaddr, msg->token, "game.move",
                                "legal", &decision);
    }
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
