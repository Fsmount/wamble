#include "../include/wamble/wamble.h"
typedef struct {
  int used;
  uint8_t token[TOKEN_LENGTH];
  uint64_t window_start_ms;
  int count;
} RequestRateLimitEntry;

static WAMBLE_THREAD_LOCAL RequestRateLimitEntry *g_rate_limit_entries = NULL;
static WAMBLE_THREAD_LOCAL int g_rate_limit_capacity = 0;

static int ensure_rate_limit_entries(void) {
  int desired = get_config()->max_client_sessions;
  if (desired <= 0)
    desired = 1;
  if (g_rate_limit_entries && g_rate_limit_capacity == desired)
    return 0;

  RequestRateLimitEntry *next = calloc((size_t)desired, sizeof(*next));
  if (!next)
    return -1;
  free(g_rate_limit_entries);
  g_rate_limit_entries = next;
  g_rate_limit_capacity = desired;
  return 0;
}

static int send_reliable_default(wamble_socket_t sockfd,
                                 const struct WambleMsg *msg,
                                 const struct sockaddr_in *cliaddr) {
  const WambleConfig *cfg = get_config();
  return send_reliable_message(sockfd, msg, cliaddr, cfg->timeout_ms,
                               cfg->max_retries);
}

static int policy_check(const uint8_t *token, const char *profile_name,
                        const char *action, const char *resource,
                        const char *context_key, const char *context_value,
                        WamblePolicyDecision *out_decision) {
  WamblePolicyDecision decision;
  DbStatus st = wamble_query_resolve_policy_decision(
      token, profile_name, action, resource, context_key, context_value,
      &decision);
  if (st != DB_OK)
    return 0;
  if (out_decision)
    *out_decision = decision;
  return decision.allowed ? 1 : 0;
}

static int resolve_profile_trust_tier(const uint8_t *token,
                                      const char *profile_name) {
  WamblePolicyDecision trust_decision;
  DbStatus st = wamble_query_resolve_policy_decision(
      token, profile_name, "trust.tier", "tier", NULL, NULL, &trust_decision);
  int trust_event = PROFILE_TRUST_DECISION_UNRESOLVED;
  int trust_tier = 0;
  if (st == DB_OK) {
    if (trust_decision.allowed) {
      trust_tier = trust_decision.permission_level;
      trust_event = PROFILE_TRUST_DECISION_ALLOWED;
    } else {
      trust_event = PROFILE_TRUST_DECISION_DENIED;
    }
  }
  wamble_runtime_event_publish(WAMBLE_RUNTIME_EVENT_TRUST_DECISION, trust_event,
                               profile_name);

  WambleFact facts[2];
  int fact_count = 0;
  memset(facts, 0, sizeof(facts));
  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "trust.tier");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_INT;
  facts[fact_count].int_value = trust_tier;
  fact_count++;
  if (profile_name && profile_name[0]) {
    snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
             "profile.name");
    facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_STRING;
    snprintf(facts[fact_count].string_value,
             sizeof(facts[fact_count].string_value), "%s", profile_name);
    fact_count++;
  }

  WambleTreatmentAction actions[8];
  int action_count = 0;
  if (wamble_query_resolve_treatment_actions(
          token, profile_name ? profile_name : "", "trust.resolve", NULL, facts,
          fact_count, actions, 8, &action_count) == DB_OK) {
    for (int i = 0; i < action_count; i++) {
      if (strcmp(actions[i].output_kind, "behavior") != 0)
        continue;
      if (strcmp(actions[i].output_key, "trust.tier.set") == 0 &&
          actions[i].value_type == WAMBLE_TREATMENT_VALUE_INT) {
        trust_tier = (int)actions[i].int_value;
      } else if (strcmp(actions[i].output_key, "trust.tier.delta") == 0 &&
                 actions[i].value_type == WAMBLE_TREATMENT_VALUE_INT) {
        trust_tier += (int)actions[i].int_value;
      } else if (strcmp(actions[i].output_key, "trust.tier.min") == 0 &&
                 actions[i].value_type == WAMBLE_TREATMENT_VALUE_INT &&
                 trust_tier < (int)actions[i].int_value) {
        trust_tier = (int)actions[i].int_value;
      }
    }
  }
  if (trust_tier < 0)
    trust_tier = 0;
  return trust_tier;
}

static void write_visible_board_fen(const uint8_t *token,
                                    const char *profile_name,
                                    const WambleBoard *board, char *out_fen,
                                    size_t out_fen_size) {
  if (!out_fen || out_fen_size == 0)
    return;
  out_fen[0] = '\0';
  if (!board)
    return;
  wamble_strip_fen_history(board->fen, out_fen, out_fen_size);
  if (!token)
    return;

  WambleFact facts[3];
  memset(facts, 0, sizeof(facts));
  int fact_count = wamble_collect_board_treatment_facts(board, facts, 3);
  WambleTreatmentAction actions[8];
  int action_count = 0;
  if (wamble_query_resolve_treatment_actions(
          token, profile_name ? profile_name : "", "board.read",
          board->last_mover_treatment_group, facts, fact_count, actions, 8,
          &action_count) != DB_OK) {
    return;
  }
  for (int i = 0; i < action_count; i++) {
    if (strcmp(actions[i].output_kind, "view") != 0 ||
        strcmp(actions[i].output_key, "board.fen") != 0 ||
        actions[i].value_type != WAMBLE_TREATMENT_VALUE_STRING ||
        !actions[i].string_value[0]) {
      continue;
    }
    snprintf(out_fen, out_fen_size, "%s", actions[i].string_value);
  }
}

static int prediction_read_uses_move_projection(const uint8_t *token,
                                                const char *profile_name,
                                                const WambleBoard *board) {
  if (!token || !board)
    return 0;
  WambleFact facts[3];
  memset(facts, 0, sizeof(facts));
  int fact_count = wamble_collect_board_treatment_facts(board, facts, 3);
  WambleTreatmentAction actions[8];
  int action_count = 0;
  if (wamble_query_resolve_treatment_actions(
          token, profile_name ? profile_name : "", "prediction.read",
          board->last_mover_treatment_group, facts, fact_count, actions, 8,
          &action_count) != DB_OK) {
    return 0;
  }
  for (int i = 0; i < action_count; i++) {
    if (strcmp(actions[i].output_kind, "view") == 0 &&
        strcmp(actions[i].output_key, "prediction.source") == 0 &&
        actions[i].value_type == WAMBLE_TREATMENT_VALUE_STRING &&
        strcmp(actions[i].string_value, "moves") == 0) {
      return 1;
    }
  }
  return 0;
}

static PredictionStatus
prediction_collect_move_projection(uint64_t board_id, WamblePredictionView *out,
                                   int max_out, int *out_count) {
  if (out_count)
    *out_count = 0;
  if (!out || max_out <= 0)
    return PREDICTION_ERR_INVALID;
  DbMovesResult mres = wamble_query_get_moves_for_board(board_id);
  if (mres.status != DB_OK)
    return PREDICTION_ERR_NOT_FOUND;
  int count = mres.count;
  if (count < 0)
    count = 0;
  if (count > max_out)
    count = max_out;
  for (int i = 0; i < count; i++) {
    memset(&out[i], 0, sizeof(out[i]));
    out[i].id = mres.rows[i].id;
    out[i].parent_id = (i > 0) ? mres.rows[i - 1].id : 0;
    out[i].board_id = mres.rows[i].board_id;
    memcpy(out[i].player_token, mres.rows[i].player_token, TOKEN_LENGTH);
    snprintf(out[i].predicted_move_uci, sizeof(out[i].predicted_move_uci), "%s",
             mres.rows[i].uci_move);
    snprintf(out[i].status, sizeof(out[i].status), "%s", "CORRECT");
    out[i].target_ply = i + 1;
    out[i].depth = 0;
    out[i].points_awarded = 0.0;
    out[i].created_at = mres.rows[i].timestamp;
  }
  if (out_count)
    *out_count = count;
  return PREDICTION_OK;
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

  WamblePolicyDecision decision;
  char resource[256];
  DbStatus st;

  snprintf(resource, sizeof(resource), "profile:%s", p->name);
  st = wamble_query_resolve_policy_decision(token, p->name, action, resource,
                                            NULL, NULL, &decision);
  if (st == DB_OK && decision.rule_id > 0)
    return decision.allowed ? DISCOVER_POLICY_ALLOW : DISCOVER_POLICY_DENY;

  if (p->group && p->group[0]) {
    snprintf(resource, sizeof(resource), "profile_selector:%s", p->group);
    st = wamble_query_resolve_policy_decision(token, p->name, action, resource,
                                              NULL, NULL, &decision);
    if (st == DB_OK && decision.rule_id > 0)
      return decision.allowed ? DISCOVER_POLICY_ALLOW : DISCOVER_POLICY_DENY;
  }

  st = wamble_query_resolve_policy_decision(token, p->name, action, "*", NULL,
                                            NULL, &decision);
  if (st == DB_OK && decision.rule_id > 0)
    return decision.allowed ? DISCOVER_POLICY_ALLOW : DISCOVER_POLICY_DENY;
  return DISCOVER_POLICY_NO_RULE;
}

static int rate_limit_allowed(const uint8_t *token, int max_per_sec) {
  if (!token || max_per_sec <= 0)
    return 1;
  if (ensure_rate_limit_entries() != 0)
    return 0;
  uint64_t now = wamble_now_mono_millis();
  int match_idx = -1;
  int free_idx = -1;
  for (int i = 0; i < g_rate_limit_capacity; i++) {
    RequestRateLimitEntry *e = &g_rate_limit_entries[i];
    if (e->used && now >= e->window_start_ms + 1000) {
      memset(e, 0, sizeof(*e));
    }
    if (!e->used) {
      if (free_idx < 0)
        free_idx = i;
      continue;
    }
    if (tokens_equal(e->token, token)) {
      match_idx = i;
      break;
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
    if (free_idx < 0)
      return 0;
    entry = &g_rate_limit_entries[free_idx];
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

static const uint8_t *
rate_limit_key_for_message(const struct WambleMsg *msg,
                           const struct sockaddr_in *cliaddr,
                           uint8_t key_buf[TOKEN_LENGTH]) {
  if (!msg)
    return NULL;
  if (msg->ctrl != WAMBLE_CTRL_CLIENT_HELLO || !cliaddr)
    return msg->token;
  memset(key_buf, 0, TOKEN_LENGTH);
  key_buf[0] = WAMBLE_CTRL_CLIENT_HELLO;
  memcpy(&key_buf[1], &cliaddr->sin_addr.s_addr,
         sizeof(cliaddr->sin_addr.s_addr));
  return key_buf;
}

static int profile_discovery_allowed(const uint8_t *token,
                                     const WambleProfile *p, int trust_tier) {
  if (!token || !p)
    return 0;
  if (p->abstract)
    return 0;
  DiscoverPolicyDecision override = resolve_discovery_policy_for_action(
      token, p, "profile.discover.override");
  if (override == DISCOVER_POLICY_DENY)
    return 0;
  if (override == DISCOVER_POLICY_ALLOW) {
    if (!p->advertise || trust_tier < p->visibility) {
      wamble_runtime_event_publish(
          WAMBLE_RUNTIME_EVENT_PROFILE_ADMIN,
          PROFILE_ADMIN_STATUS_DISCOVERY_OVERRIDE_EXPOSED, p->name);
    }
    return 1;
  }
  int effective_trust = resolve_profile_trust_tier(token, p->name);
  return (p->advertise && effective_trust >= p->visibility) ? 1 : 0;
}

static ServerStatus send_policy_denied(wamble_socket_t sockfd,
                                       const struct sockaddr_in *cliaddr,
                                       const uint8_t *token) {
  struct WambleMsg err = {0};
  err.ctrl = WAMBLE_CTRL_ERROR;
  memcpy(err.token, token, TOKEN_LENGTH);
  err.error_code = WAMBLE_ERR_ACCESS_DENIED;
  if (send_reliable_default(sockfd, &err, cliaddr) != 0) {
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
  case WAMBLE_CTRL_SUBMIT_PREDICTION:
    return "submit_prediction";
  case WAMBLE_CTRL_GET_PREDICTIONS:
    return "get_predictions";
  case WAMBLE_CTRL_PREDICTION_DATA:
    return "prediction_data";
  case WAMBLE_CTRL_GET_PROFILE_TOS:
    return "get_profile_tos";
  case WAMBLE_CTRL_PROFILE_TOS_DATA:
    return "profile_tos_data";
  default:
    return "unknown";
  }
}

static uint8_t prediction_status_code(const char *status) {
  if (!status)
    return WAMBLE_PREDICTION_STATUS_PENDING;
  if (strcmp(status, "CORRECT") == 0)
    return WAMBLE_PREDICTION_STATUS_CORRECT;
  if (strcmp(status, "INCORRECT") == 0)
    return WAMBLE_PREDICTION_STATUS_INCORRECT;
  if (strcmp(status, "EXPIRED") == 0)
    return WAMBLE_PREDICTION_STATUS_EXPIRED;
  return WAMBLE_PREDICTION_STATUS_PENDING;
}

static void fill_prediction_entry(WamblePredictionEntry *dst,
                                  const WamblePredictionView *src) {
  if (!dst || !src)
    return;
  memset(dst, 0, sizeof(*dst));
  dst->id = src->id;
  dst->parent_id = src->parent_id;
  memcpy(dst->token, src->player_token, TOKEN_LENGTH);
  dst->points_awarded = src->points_awarded;
  dst->target_ply = (src->target_ply >= 0 && src->target_ply <= 65535)
                        ? (uint16_t)src->target_ply
                        : 0;
  dst->depth = (src->depth >= 0 && src->depth <= 255) ? (uint8_t)src->depth : 0;
  dst->status = prediction_status_code(src->status);
  dst->uci_len = (uint8_t)strnlen(src->predicted_move_uci, MAX_UCI_LENGTH);
  memcpy(dst->uci, src->predicted_move_uci, dst->uci_len);
}

static ServerStatus
send_prediction_rows(wamble_socket_t sockfd, const struct sockaddr_in *cliaddr,
                     const uint8_t *token, uint64_t board_id,
                     const WamblePredictionView *rows, int count) {
  struct WambleMsg response = {0};
  response.ctrl = WAMBLE_CTRL_PREDICTION_DATA;
  memcpy(response.token, token, TOKEN_LENGTH);
  response.board_id = board_id;
  if (count < 0)
    count = 0;
  if (count > WAMBLE_MAX_PREDICTION_ENTRIES)
    count = WAMBLE_MAX_PREDICTION_ENTRIES;
  response.prediction_count = (uint8_t)count;
  for (int i = 0; i < count; i++) {
    fill_prediction_entry(&response.predictions[i], &rows[i]);
  }
  if (send_reliable_default(sockfd, &response, cliaddr) != 0) {
    return SERVER_ERR_SEND_FAILED;
  }
  return SERVER_OK;
}

static ServerStatus handle_client_hello(wamble_socket_t sockfd,
                                        const struct WambleMsg *msg,
                                        const struct sockaddr_in *cliaddr,
                                        const char *profile_name) {
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
    (void)send_reliable_default(sockfd, &err, cliaddr);
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
  write_visible_board_fen(player->token, profile_name, board, response.fen,
                          sizeof(response.fen));

  if (send_reliable_default(sockfd, &response, cliaddr) != 0) {
    return SERVER_ERR_SEND_FAILED;
  }

  return SERVER_OK;
}

static ServerStatus handle_client_goodbye(const struct WambleMsg *msg) {
  WamblePlayer *player = get_player_by_token(msg->token);
  if (!player)
    return SERVER_ERR_UNKNOWN_PLAYER;
  spectator_discard_by_token(msg->token);
  discard_player_by_token(msg->token);
  return SERVER_OK;
}

static ServerStatus handle_logout(const struct WambleMsg *msg) {
  WamblePlayer *player = get_player_by_token(msg->token);
  if (!player)
    return SERVER_ERR_UNKNOWN_PLAYER;
  if (detach_persistent_identity(msg->token) != 0)
    return SERVER_ERR_INTERNAL;
  return SERVER_OK;
}

static ServerStatus handle_player_move(wamble_socket_t sockfd,
                                       const struct WambleMsg *msg,
                                       const struct sockaddr_in *cliaddr,
                                       const char *profile_name) {
  if (!policy_check(msg->token, profile_name, "game.move", "play", NULL, NULL,
                    NULL)) {
    return send_policy_denied(sockfd, cliaddr, msg->token);
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
  (void)prediction_resolve_move(board, uci_move);

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
  if (next_board->board.game_mode == GAME_MODE_CHESS960)
    response.flags |= WAMBLE_FLAG_BOARD_IS_960;
  write_visible_board_fen(msg->token, profile_name, next_board, response.fen,
                          sizeof(response.fen));

  if (send_reliable_default(sockfd, &response, cliaddr) != 0) {
    return SERVER_ERR_SEND_FAILED;
  }

  return SERVER_OK;
}

static ServerStatus
handle_submit_prediction(wamble_socket_t sockfd, const struct WambleMsg *msg,
                         const struct sockaddr_in *cliaddr) {
  WambleBoard *board = get_board_by_id(msg->board_id);
  if (!board)
    return SERVER_ERR_UNKNOWN_BOARD;

  char uci[MAX_UCI_LENGTH + 1];
  uint8_t uci_len =
      msg->uci_len < MAX_UCI_LENGTH ? msg->uci_len : MAX_UCI_LENGTH;
  memcpy(uci, msg->uci, uci_len);
  uci[uci_len] = '\0';

  uint64_t prediction_id = 0;
  PredictionStatus st = prediction_submit_with_parent(
      board, msg->token, uci, msg->prediction_parent_id, 0, &prediction_id);
  if (st != PREDICTION_OK) {
    struct WambleMsg out = {0};
    out.ctrl = WAMBLE_CTRL_ERROR;
    memcpy(out.token, msg->token, TOKEN_LENGTH);
    out.error_code = WAMBLE_ERR_ACCESS_DENIED;
    if (send_reliable_default(sockfd, &out, cliaddr) != 0) {
      return SERVER_ERR_SEND_FAILED;
    }
    return SERVER_ERR_FORBIDDEN;
  }

  WamblePredictionView rows[WAMBLE_MAX_PREDICTION_ENTRIES];
  int count = 0;
  if (prediction_collect_tree(
          board->id, msg->token, 0, get_config()->prediction_view_depth_limit,
          rows, WAMBLE_MAX_PREDICTION_ENTRIES, &count) != PREDICTION_OK) {
    count = 0;
  }
  for (int i = 0; i < count; i++) {
    if (rows[i].id == prediction_id) {
      return send_prediction_rows(sockfd, cliaddr, msg->token, board->id,
                                  &rows[i], 1);
    }
  }
  return send_prediction_rows(sockfd, cliaddr, msg->token, board->id, NULL, 0);
}

static ServerStatus handle_get_predictions(wamble_socket_t sockfd,
                                           const struct sockaddr_in *cliaddr,
                                           const struct WambleMsg *msg,
                                           const char *profile_name) {
  WamblePredictionView rows[WAMBLE_MAX_PREDICTION_ENTRIES];
  int count = 0;
  int depth = msg->prediction_depth;
  if (depth <= 0)
    depth = get_config()->prediction_view_depth_limit;
  int limit = msg->prediction_limit;
  if (limit <= 0 || limit > WAMBLE_MAX_PREDICTION_ENTRIES)
    limit = WAMBLE_MAX_PREDICTION_ENTRIES;

  WambleBoard *board = get_board_by_id(msg->board_id);
  PredictionStatus st =
      prediction_read_uses_move_projection(msg->token, profile_name, board)
          ? prediction_collect_move_projection(msg->board_id, rows, limit,
                                               &count)
          : prediction_collect_tree(msg->board_id, msg->token, 0, depth, rows,
                                    limit, &count);
  if (st != PREDICTION_OK) {
    struct WambleMsg out = {0};
    out.ctrl = WAMBLE_CTRL_ERROR;
    memcpy(out.token, msg->token, TOKEN_LENGTH);
    out.error_code = WAMBLE_ERR_ACCESS_DENIED;
    if (send_reliable_default(sockfd, &out, cliaddr) != 0) {
      return SERVER_ERR_SEND_FAILED;
    }
    return SERVER_ERR_FORBIDDEN;
  }
  return send_prediction_rows(sockfd, cliaddr, msg->token, msg->board_id, rows,
                              count);
}

static ServerStatus handle_list_profiles(wamble_socket_t sockfd,
                                         const struct sockaddr_in *cliaddr,
                                         const struct WambleMsg *msg,
                                         int effective_trust_tier) {
  struct WambleMsg resp = {0};
  resp.ctrl = WAMBLE_CTRL_PROFILES_LIST;
  memcpy(resp.token, msg->token, TOKEN_LENGTH);

  int count = config_profile_count();
  int written = 0;
  for (int i = 0; i < count; i++) {
    const WambleProfile *p = config_get_profile(i);
    if (!p)
      continue;
    if (!profile_discovery_allowed(msg->token, p, effective_trust_tier))
      continue;
    const char *name = p->name ? p->name : "";
    int need = (int)strlen(name);
    if (written + need + (written ? 1 : 0) >= FEN_MAX_LENGTH)
      break;
    if (written)
      resp.profiles_list[written++] = ',';
    memcpy(&resp.profiles_list[written], name, (size_t)need);
    written += need;
  }
  if (written < FEN_MAX_LENGTH)
    resp.profiles_list[written] = '\0';
  resp.profiles_list_len = (uint16_t)written;
  if (send_reliable_default(sockfd, &resp, cliaddr) != 0) {
    return SERVER_ERR_SEND_FAILED;
  }
  return SERVER_OK;
}

static ServerStatus handle_get_profile_info(wamble_socket_t sockfd,
                                            const struct sockaddr_in *cliaddr,
                                            const struct WambleMsg *msg,
                                            int effective_trust_tier) {
  char name[PROFILE_NAME_MAX_LENGTH];
  int nlen = 0;
  nlen = msg->profile_name_len < (PROFILE_NAME_MAX_LENGTH - 1)
             ? msg->profile_name_len
             : (PROFILE_NAME_MAX_LENGTH - 1);
  if (nlen > 0)
    memcpy(name, msg->profile_name, (size_t)nlen);
  name[nlen] = '\0';

  const WambleProfile *p = config_find_profile(name);
  struct WambleMsg resp = {0};
  resp.ctrl = WAMBLE_CTRL_PROFILE_INFO;
  memcpy(resp.token, msg->token, TOKEN_LENGTH);
  if (p && profile_discovery_allowed(msg->token, p, effective_trust_tier)) {
    int wrote = snprintf(resp.profile_info, FEN_MAX_LENGTH, "%s;%d;%d;%d",
                         p->name, p->config.port, p->advertise, p->visibility);
    if (wrote < 0)
      wrote = 0;
    if (wrote >= FEN_MAX_LENGTH)
      wrote = FEN_MAX_LENGTH - 1;
    resp.profile_info_len = (uint16_t)wrote;
  } else {
    wamble_runtime_event_publish(
        WAMBLE_RUNTIME_EVENT_PROFILE_ADMIN,
        p ? PROFILE_ADMIN_STATUS_PROFILE_INFO_HIDDEN
          : PROFILE_ADMIN_STATUS_PROFILE_INFO_NOT_FOUND,
        name);
    int wrote =
        snprintf(resp.profile_info, FEN_MAX_LENGTH, "NOTFOUND;%.80s", name);
    if (wrote < 0)
      wrote = 0;
    if (wrote >= FEN_MAX_LENGTH)
      wrote = FEN_MAX_LENGTH - 1;
    resp.profile_info_len = (uint16_t)wrote;
  }
  if (send_reliable_default(sockfd, &resp, cliaddr) != 0) {
    return SERVER_ERR_SEND_FAILED;
  }
  return SERVER_OK;
}

static ServerStatus handle_get_profile_tos(wamble_socket_t sockfd,
                                           const struct sockaddr_in *cliaddr,
                                           const struct WambleMsg *msg,
                                           int effective_trust_tier) {
  char name[PROFILE_NAME_MAX_LENGTH];
  int nlen = msg->profile_name_len < (PROFILE_NAME_MAX_LENGTH - 1)
                 ? msg->profile_name_len
                 : (PROFILE_NAME_MAX_LENGTH - 1);
  if (nlen > 0)
    memcpy(name, msg->profile_name, (size_t)nlen);
  name[nlen] = '\0';

  const WambleProfile *p = config_find_profile(name);
  struct WambleMsg resp = {0};
  resp.ctrl = WAMBLE_CTRL_PROFILE_TOS_DATA;
  memcpy(resp.token, msg->token, TOKEN_LENGTH);
  if (p && profile_discovery_allowed(msg->token, p, effective_trust_tier)) {
    resp.tos_ptr = p->tos_text ? p->tos_text : "";
    resp.tos_len = p->tos_text ? strlen(p->tos_text) : 0;
  } else {
    wamble_runtime_event_publish(
        WAMBLE_RUNTIME_EVENT_PROFILE_ADMIN,
        p ? PROFILE_ADMIN_STATUS_PROFILE_INFO_HIDDEN
          : PROFILE_ADMIN_STATUS_PROFILE_INFO_NOT_FOUND,
        name);
    int wrote =
        snprintf(resp.profile_info, FEN_MAX_LENGTH, "NOTFOUND;%.80s", name);
    if (wrote < 0)
      wrote = 0;
    if (wrote >= FEN_MAX_LENGTH)
      wrote = FEN_MAX_LENGTH - 1;
    resp.tos_ptr = resp.profile_info;
    resp.tos_len = (size_t)wrote;
  }
  if (send_reliable_default(sockfd, &resp, cliaddr) != 0)
    return SERVER_ERR_SEND_FAILED;
  return SERVER_OK;
}

static int login_has_pubkey(const struct WambleMsg *msg) {
  if (!msg)
    return 0;
  for (int i = 0; i < 32; i++) {
    if (msg->login_pubkey[i] != 0)
      return 1;
  }
  return 0;
}

static ServerStatus handle_login_request(wamble_socket_t sockfd,
                                         const struct sockaddr_in *cliaddr,
                                         const struct WambleMsg *msg) {
  int has_key = login_has_pubkey(msg);
  WamblePlayer *player = NULL;
  if (has_key)
    player = attach_persistent_identity(msg->token, msg->login_pubkey);

  struct WambleMsg response = {0};
  if (player) {
    response.ctrl = WAMBLE_CTRL_LOGIN_SUCCESS;
    memcpy(response.token, player->token, TOKEN_LENGTH);
  } else {
    response.ctrl = WAMBLE_CTRL_LOGIN_FAILED;
    response.error_code = WAMBLE_ERR_ACCESS_DENIED;
  }
  if (send_reliable_default(sockfd, &response, cliaddr) != 0) {
    return SERVER_ERR_SEND_FAILED;
  }
  return player ? SERVER_OK : SERVER_ERR_LOGIN_FAILED;
}

static ServerStatus enforce_message_access_policies(
    wamble_socket_t sockfd, const struct WambleMsg *msg,
    const struct sockaddr_in *cliaddr, const char *profile_name) {
  if (msg->ctrl != WAMBLE_CTRL_ACK) {
    WamblePolicyDecision bypass = {0};
    const char *ctrl_res = ctrl_policy_resource(msg->ctrl);
    int bypass_rate_limit =
        policy_check(msg->token, profile_name, "rate_limit.bypass", "request",
                     "ctrl", ctrl_res, &bypass);
    int max_per_sec = get_config()->rate_limit_requests_per_sec;
    uint8_t rate_key[TOKEN_LENGTH];
    const uint8_t *limit_token =
        rate_limit_key_for_message(msg, cliaddr, rate_key);
    if (!bypass_rate_limit && !rate_limit_allowed(limit_token, max_per_sec)) {
      struct WambleMsg out = {0};
      out.ctrl = WAMBLE_CTRL_ERROR;
      memcpy(out.token, msg->token, TOKEN_LENGTH);
      out.error_code = WAMBLE_ERR_ACCESS_DENIED;
      if (send_reliable_default(sockfd, &out, cliaddr) != 0) {
        return SERVER_ERR_SEND_FAILED;
      }
      return SERVER_ERR_FORBIDDEN;
    }
  }

  if (msg->ctrl != WAMBLE_CTRL_ACK) {
    const char *ctrl_res = ctrl_policy_resource(msg->ctrl);
    if (!policy_check(msg->token, profile_name, "protocol.ctrl", ctrl_res, NULL,
                      NULL, NULL)) {
      return send_policy_denied(sockfd, cliaddr, msg->token);
    }
  }

  return SERVER_OK;
}

ServerStatus handle_message(wamble_socket_t sockfd, const struct WambleMsg *msg,
                            const struct sockaddr_in *cliaddr, int trust_tier,
                            const char *profile_name) {
  int effective_trust_tier = trust_tier;
  if (msg) {
    effective_trust_tier = resolve_profile_trust_tier(msg->token, profile_name);
  }
  ServerStatus access_status =
      enforce_message_access_policies(sockfd, msg, cliaddr, profile_name);
  if (access_status != SERVER_OK)
    return access_status;
  switch (msg->ctrl) {
  case WAMBLE_CTRL_CLIENT_HELLO:
    return handle_client_hello(sockfd, msg, cliaddr, profile_name);
  case WAMBLE_CTRL_CLIENT_GOODBYE:
    if ((msg->flags & WAMBLE_FLAG_UNRELIABLE) == 0)
      send_ack(sockfd, msg, cliaddr);
    return handle_client_goodbye(msg);
  case WAMBLE_CTRL_PLAYER_MOVE:
    if ((msg->flags & WAMBLE_FLAG_UNRELIABLE) == 0)
      send_ack(sockfd, msg, cliaddr);
    return handle_player_move(sockfd, msg, cliaddr, profile_name);
  case WAMBLE_CTRL_LIST_PROFILES:
    return handle_list_profiles(sockfd, cliaddr, msg, effective_trust_tier);
  case WAMBLE_CTRL_GET_PROFILE_INFO:
    return handle_get_profile_info(sockfd, cliaddr, msg, effective_trust_tier);
  case WAMBLE_CTRL_GET_PROFILE_TOS:
    return handle_get_profile_tos(sockfd, cliaddr, msg, effective_trust_tier);
  case WAMBLE_CTRL_LOGIN_REQUEST:
    return handle_login_request(sockfd, cliaddr, msg);
  case WAMBLE_CTRL_LOGOUT:
    if ((msg->flags & WAMBLE_FLAG_UNRELIABLE) == 0)
      send_ack(sockfd, msg, cliaddr);
    return handle_logout(msg);
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
      if (send_reliable_default(sockfd, &out, cliaddr) != 0) {
        return SERVER_ERR_SEND_FAILED;
      }
      return SERVER_ERR_FORBIDDEN;
    }
    SpectatorState new_state = SPECTATOR_STATE_IDLE;
    uint64_t focus_id = 0;
    int capacity_bypass =
        policy_check(msg->token, profile_name, "spectate.capacity_bypass",
                     "focus", NULL, NULL, NULL);
    SpectatorRequestStatus res =
        spectator_handle_request(msg, cliaddr, effective_trust_tier,
                                 capacity_bypass, &new_state, &focus_id);
    if (!(res == SPECTATOR_OK_FOCUS || res == SPECTATOR_OK_SUMMARY ||
          res == SPECTATOR_OK_STOP)) {
      struct WambleMsg out = {0};
      out.ctrl = WAMBLE_CTRL_ERROR;
      memcpy(out.token, msg->token, TOKEN_LENGTH);
      out.error_code = WAMBLE_ERR_ACCESS_DENIED;
      if (send_reliable_default(sockfd, &out, cliaddr) != 0) {
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
    (void)spectator_handle_request(msg, cliaddr, effective_trust_tier, 0,
                                   &new_state, &focus_id);
    return SERVER_OK;
  }
  case WAMBLE_CTRL_GET_PLAYER_STATS: {
    if (!policy_check(msg->token, profile_name, "stats.read", "player", NULL,
                      NULL, NULL)) {
      return send_policy_denied(sockfd, cliaddr, msg->token);
    }
    WamblePlayer *player = get_player_by_token(msg->token);
    if (player) {
      struct WambleMsg response;
      memset(&response, 0, sizeof(response));
      response.ctrl = WAMBLE_CTRL_PLAYER_STATS_DATA;
      memcpy(response.token, player->token, TOKEN_LENGTH);
      response.player_stats_score = player->score;
      response.player_stats_games_played =
          (player->games_played > 0) ? (uint32_t)player->games_played : 0;
      response.player_stats_chess960_games_played =
          (player->chess960_games_played > 0)
              ? (uint32_t)player->chess960_games_played
              : 0;
      if (send_reliable_default(sockfd, &response, cliaddr) != 0) {
        return SERVER_ERR_SEND_FAILED;
      }
      return SERVER_OK;
    }
    return SERVER_ERR_UNKNOWN_PLAYER;
  }
  case WAMBLE_CTRL_GET_LEADERBOARD: {
    if (!policy_check(msg->token, profile_name, "leaderboard.read", "global",
                      NULL, NULL, NULL)) {
      return send_policy_denied(sockfd, cliaddr, msg->token);
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
    if (send_reliable_default(sockfd, &response, cliaddr) != 0) {
      return SERVER_ERR_SEND_FAILED;
    }
    return SERVER_OK;
  }
  case WAMBLE_CTRL_SUBMIT_PREDICTION:
    return handle_submit_prediction(sockfd, msg, cliaddr);
  case WAMBLE_CTRL_GET_PREDICTIONS:
    return handle_get_predictions(sockfd, cliaddr, msg, profile_name);
  case WAMBLE_CTRL_GET_LEGAL_MOVES: {
    if (!policy_check(msg->token, profile_name, "game.move", "legal", NULL,
                      NULL, NULL)) {
      return send_policy_denied(sockfd, cliaddr, msg->token);
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

    if (send_reliable_default(sockfd, &response, cliaddr) != 0) {
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
