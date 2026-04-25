#include "../include/wamble/wamble.h"
void crypto_blake2b(uint8_t *hash, size_t hash_size, const uint8_t *msg,
                    size_t msg_size);
int crypto_eddsa_check(const uint8_t signature[64],
                       const uint8_t public_key[32], const uint8_t *message,
                       size_t message_size);

typedef struct {
  int used;
  uint8_t token[TOKEN_LENGTH];
  uint64_t window_start_ms;
  int count;
} RequestRateLimitEntry;

static WAMBLE_THREAD_LOCAL RequestRateLimitEntry *g_rate_limit_entries = NULL;
static WAMBLE_THREAD_LOCAL int g_rate_limit_capacity = 0;
static WAMBLE_THREAD_LOCAL uint32_t g_fragment_transfer_id_seq = 1;

#define LOGIN_CHALLENGE_TTL_MS 30000ULL

typedef struct {
  int used;
  uint8_t token[TOKEN_LENGTH];
  uint8_t public_key[WAMBLE_PUBLIC_KEY_LENGTH];
  uint8_t challenge[WAMBLE_LOGIN_CHALLENGE_LENGTH];
  uint64_t issued_at_ms;
} LoginChallengeEntry;

static WAMBLE_THREAD_LOCAL LoginChallengeEntry *g_login_challenge_entries =
    NULL;
static WAMBLE_THREAD_LOCAL int g_login_challenge_capacity = 0;

static void publish_server_protocol_status(int status_code,
                                           const char *profile_name);
static void publish_server_protocol_status_detail(int status_code,
                                                  const char *profile_name,
                                                  const char *detail);
static void publish_treatment_audit_status(int status_code,
                                           const char *profile_name);
static const char *ctrl_policy_resource(uint8_t ctrl);
static int compare_cstr_ptrs(const void *a, const void *b);
static int stats_read_allowed(const uint8_t *token, const char *profile_name,
                              uint64_t target_session_id,
                              uint64_t target_identity_id);
static void write_visible_board_fen(const uint8_t *token,
                                    const char *profile_name,
                                    const WambleBoard *board, char *out_fen,
                                    size_t out_fen_size);
static uint32_t append_session_capability_extensions(struct WambleMsg *msg,
                                                     const uint8_t *token,
                                                     const char *profile_name,
                                                     const WambleBoard *board);
static void append_last_move_extensions(struct WambleMsg *msg,
                                        const uint8_t *token,
                                        const char *profile_name,
                                        WambleBoard *board);

static int token_has_any_byte(const uint8_t *token) {
  if (!token)
    return 0;
  for (int i = 0; i < TOKEN_LENGTH; i++) {
    if (token[i] != 0)
      return 1;
  }
  return 0;
}

static int compare_cstr_ptrs(const void *a, const void *b) {
  const char *const *lhs = (const char *const *)a;
  const char *const *rhs = (const char *const *)b;
  const char *l = (lhs && *lhs) ? *lhs : "";
  const char *r = (rhs && *rhs) ? *rhs : "";
  return strcmp(l, r);
}

static int is_valid_stats_handle(const char *handle) {
  if (!handle || !handle[0])
    return 0;
  size_t len = strlen(handle);
  if (len < 4 || len > 63)
    return 0;
  for (size_t i = 0; i < len; i++) {
    char c = handle[i];
    int ok = ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_');
    if (!ok)
      return 0;
  }
  return 1;
}

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

static int ensure_login_challenge_entries(void) {
  int desired = get_config()->max_client_sessions;
  if (desired <= 0)
    desired = 1;
  if (g_login_challenge_entries && g_login_challenge_capacity == desired)
    return 0;
  LoginChallengeEntry *next = calloc((size_t)desired, sizeof(*next));
  if (!next)
    return -1;
  free(g_login_challenge_entries);
  g_login_challenge_entries = next;
  g_login_challenge_capacity = desired;
  return 0;
}

static int login_challenge_is_fresh(uint64_t issued_at_ms);

static LoginChallengeEntry *find_login_challenge_entry(const uint8_t *token,
                                                       int *out_free_index) {
  if (out_free_index)
    *out_free_index = -1;
  if (!token || !g_login_challenge_entries || g_login_challenge_capacity <= 0)
    return NULL;
  for (int i = 0; i < g_login_challenge_capacity; i++) {
    LoginChallengeEntry *entry = &g_login_challenge_entries[i];
    if (!entry->used) {
      if (out_free_index && *out_free_index < 0)
        *out_free_index = i;
      continue;
    }
    if (tokens_equal(entry->token, token))
      return entry;
  }
  return NULL;
}

static LoginChallengeEntry *
acquire_login_challenge_entry(const uint8_t *token) {
  int free_index = -1;
  LoginChallengeEntry *entry = find_login_challenge_entry(token, &free_index);
  if (entry)
    return entry;
  if (free_index >= 0)
    return &g_login_challenge_entries[free_index];
  int oldest_expired = -1;
  uint64_t oldest_expired_issued = UINT64_MAX;
  for (int i = 0; i < g_login_challenge_capacity; i++) {
    LoginChallengeEntry *slot = &g_login_challenge_entries[i];
    if (login_challenge_is_fresh(slot->issued_at_ms))
      continue;
    if (slot->issued_at_ms < oldest_expired_issued) {
      oldest_expired_issued = slot->issued_at_ms;
      oldest_expired = i;
    }
  }
  if (oldest_expired >= 0)
    return &g_login_challenge_entries[oldest_expired];
  return NULL;
}

static void clear_login_challenge(const uint8_t *token) {
  if (!token)
    return;
  LoginChallengeEntry *entry = find_login_challenge_entry(token, NULL);
  if (entry)
    memset(entry, 0, sizeof(*entry));
}

static int
issue_login_challenge(const uint8_t *token, const uint8_t *public_key,
                      uint8_t out_challenge[WAMBLE_LOGIN_CHALLENGE_LENGTH]) {
  if (!token || !public_key || !out_challenge)
    return -1;
  if (ensure_login_challenge_entries() != 0)
    return -1;
  LoginChallengeEntry *entry = acquire_login_challenge_entry(token);
  if (!entry)
    return -1;
  memset(entry, 0, sizeof(*entry));
  entry->used = 1;
  memcpy(entry->token, token, TOKEN_LENGTH);
  memcpy(entry->public_key, public_key, WAMBLE_PUBLIC_KEY_LENGTH);
  rng_bytes(entry->challenge, WAMBLE_LOGIN_CHALLENGE_LENGTH);
  entry->issued_at_ms = wamble_now_mono_millis();
  memcpy(out_challenge, entry->challenge, WAMBLE_LOGIN_CHALLENGE_LENGTH);
  return 0;
}

static int login_challenge_is_fresh(uint64_t issued_at_ms) {
  uint64_t now = wamble_now_mono_millis();
  if (now < issued_at_ms)
    return 0;
  return (now - issued_at_ms) <= LOGIN_CHALLENGE_TTL_MS;
}

static int verify_login_proof(const struct WambleMsg *msg) {
  if (!msg)
    return -1;
  LoginChallengeEntry *entry = find_login_challenge_entry(msg->token, NULL);
  if (!entry || !entry->used)
    return -1;
  int verified = 0;
  if (memcmp(entry->public_key, msg->login.public_key,
             WAMBLE_PUBLIC_KEY_LENGTH) != 0) {
    goto done;
  }
  if (!login_challenge_is_fresh(entry->issued_at_ms))
    goto done;

  uint8_t sign_message[128];
  size_t sign_message_len = wamble_build_login_signature_message(
      sign_message, sizeof(sign_message), msg->token, msg->login.public_key,
      entry->challenge);
  if (sign_message_len == 0)
    goto done;

  verified = (crypto_eddsa_check(msg->login.signature, msg->login.public_key,
                                 sign_message, sign_message_len) == 0)
                 ? 1
                 : 0;

done:
  if (!verified)
    memset(entry, 0, sizeof(*entry));
  return verified ? 0 : -1;
}

static int send_reliable_default(wamble_socket_t sockfd,
                                 const struct WambleMsg *msg,
                                 const struct sockaddr_in *cliaddr) {
  const WambleConfig *cfg = get_config();
  return send_reliable_message(sockfd, msg, cliaddr, cfg->timeout_ms,
                               cfg->max_retries);
}

static ServerStatus finish_request_after_terminal_send(
    wamble_socket_t sockfd, const struct WambleMsg *request,
    const struct sockaddr_in *cliaddr, ServerStatus status_if_sent) {
  if (status_if_sent == SERVER_ERR_SEND_FAILED)
    return status_if_sent;
  if (!request || !cliaddr)
    return status_if_sent;
  if ((request->flags & WAMBLE_FLAG_UNRELIABLE) == 0)
    send_ack(sockfd, request, cliaddr);
  return status_if_sent;
}

static void append_board_snapshot(struct WambleMsg *out, const uint8_t *token,
                                  const char *profile_name, WambleBoard *board,
                                  uint8_t ctrl) {
  uint32_t session_caps = 0;
  if (!out || !token || !profile_name || !profile_name[0] || !board)
    return;
  out->ctrl = ctrl;
  out->board_id = board->id;
  write_visible_board_fen(token, profile_name, board, out->view.fen,
                          sizeof(out->view.fen));
  session_caps =
      append_session_capability_extensions(out, token, profile_name, board);
  if ((session_caps & WAMBLE_SESSION_UI_CAP_GAME_MODE_VISIBLE) != 0 &&
      board->board.game_mode == GAME_MODE_CHESS960) {
    out->flags |= WAMBLE_FLAG_BOARD_IS_960;
  }
  append_last_move_extensions(out, token, profile_name, board);
}

static int build_board_state_sync_message(struct WambleMsg *out,
                                          const uint8_t *token,
                                          const char *profile_name) {
  WamblePlayer *player = NULL;
  WambleBoard *board = NULL;
  if (!out || !token || !profile_name || !profile_name[0])
    return -1;
  player = get_player_by_token(token);
  if (!player)
    return -1;
  board = find_board_for_player(player);
  if (!board)
    return -1;

  memset(out, 0, sizeof(*out));
  memcpy(out->token, player->token, TOKEN_LENGTH);
  append_board_snapshot(out, player->token, profile_name, board,
                        WAMBLE_CTRL_BOARD_UPDATE);
  return 0;
}

static int send_reliable_board_state_error(wamble_socket_t sockfd,
                                           const uint8_t *token,
                                           const struct sockaddr_in *cliaddr) {
  struct WambleMsg err = {0};
  WamblePlayer *player = get_player_by_token(token);
  err.ctrl = WAMBLE_CTRL_ERROR;
  memcpy(err.token, token, TOKEN_LENGTH);
  err.view.error_code =
      player ? WAMBLE_ERR_UNKNOWN_BOARD : WAMBLE_ERR_UNKNOWN_PLAYER;
  snprintf(err.view.error_reason, sizeof(err.view.error_reason), "%s",
           player ? "no board available for assignment" : "unknown player");
  return send_reliable_default(sockfd, &err, cliaddr);
}

int send_reliable_board_state_sync(wamble_socket_t sockfd, const uint8_t *token,
                                   const struct sockaddr_in *cliaddr) {
  struct WambleMsg out = {0};
  if (build_board_state_sync_message(&out, token,
                                     wamble_runtime_profile_key()) != 0) {
    return send_reliable_board_state_error(sockfd, token, cliaddr);
  }
  return send_reliable_default(sockfd, &out, cliaddr);
}

static int policy_check(const uint8_t *token, const char *profile_name,
                        const char *action, const char *resource,
                        const char *context_key, const char *context_value,
                        WamblePolicyDecision *out_decision) {
  int token_nonzero = 0;
  for (int i = 0; token && i < TOKEN_LENGTH; i++) {
    if (token[i] != 0) {
      token_nonzero = 1;
      break;
    }
  }
  WamblePolicyDecision decision;
  DbStatus st = wamble_query_resolve_policy_decision(
      token, profile_name, action, resource, context_key, context_value,
      &decision);
  if (st == DB_NOT_FOUND && token_nonzero) {
    (void)wamble_query_create_session(token, 0, NULL);
    st = wamble_query_resolve_policy_decision(token, profile_name, action,
                                              resource, context_key,
                                              context_value, &decision);
  }
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
  WambleRuntimeStatus runtime_status = {WAMBLE_RUNTIME_STATUS_TRUST_DECISION,
                                        trust_event};
  wamble_runtime_event_publish(runtime_status, profile_name, NULL);

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
  DbStatus treatment_status = wamble_query_resolve_treatment_actions(
      token, profile_name ? profile_name : "", "trust.resolve", NULL, facts,
      fact_count, actions, 8, &action_count);
  if (treatment_status == DB_OK) {
    publish_treatment_audit_status(action_count > 0
                                       ? TREATMENT_AUDIT_STATUS_TREATED
                                       : TREATMENT_AUDIT_STATUS_UNTREATED,
                                   profile_name);
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
  } else {
    publish_treatment_audit_status(TREATMENT_AUDIT_STATUS_QUERY_FAILED,
                                   profile_name);
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

  WambleFact facts[24];
  memset(facts, 0, sizeof(facts));
  int fact_count = wamble_collect_board_treatment_facts(board, facts, 24);
  if (token_has_any_byte(board->last_mover_token) && fact_count + 2 <= 24) {
    WamblePlayer *prev = get_player_by_token(board->last_mover_token);
    if (prev) {
      snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
               "previous_player.rating");
      facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_DOUBLE;
      facts[fact_count].double_value = prev->rating;
      fact_count++;

      snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
               "previous_player.score");
      facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_DOUBLE;
      facts[fact_count].double_value = prev->score;
      fact_count++;
    }
  }
  WambleTreatmentAction actions[8];
  int action_count = 0;
  DbStatus treatment_status = wamble_query_resolve_treatment_actions(
      token, profile_name ? profile_name : "", "board.read",
      board->last_mover_treatment_group, facts, fact_count, actions, 8,
      &action_count);
  if (treatment_status != DB_OK) {
    publish_treatment_audit_status(TREATMENT_AUDIT_STATUS_QUERY_FAILED,
                                   profile_name);
    return;
  }
  publish_treatment_audit_status(action_count > 0
                                     ? TREATMENT_AUDIT_STATUS_TREATED
                                     : TREATMENT_AUDIT_STATUS_UNTREATED,
                                 profile_name);
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
  WambleFact facts[24];
  memset(facts, 0, sizeof(facts));
  int fact_count = wamble_collect_board_treatment_facts(board, facts, 24);
  if (token_has_any_byte(board->last_mover_token) && fact_count + 2 <= 24) {
    WamblePlayer *prev = get_player_by_token(board->last_mover_token);
    if (prev) {
      snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
               "previous_player.rating");
      facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_DOUBLE;
      facts[fact_count].double_value = prev->rating;
      fact_count++;

      snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
               "previous_player.score");
      facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_DOUBLE;
      facts[fact_count].double_value = prev->score;
      fact_count++;
    }
  }
  WambleTreatmentAction actions[8];
  int action_count = 0;
  DbStatus treatment_status = wamble_query_resolve_treatment_actions(
      token, profile_name ? profile_name : "", "prediction.read",
      board->last_mover_treatment_group, facts, fact_count, actions, 8,
      &action_count);
  if (treatment_status != DB_OK) {
    publish_treatment_audit_status(TREATMENT_AUDIT_STATUS_QUERY_FAILED,
                                   profile_name);
    return 0;
  }
  publish_treatment_audit_status(action_count > 0
                                     ? TREATMENT_AUDIT_STATUS_TREATED
                                     : TREATMENT_AUDIT_STATUS_UNTREATED,
                                 profile_name);
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
      publish_server_protocol_status(
          SERVER_PROTOCOL_STATUS_PROFILE_DISCOVERY_OVERRIDE_EXPOSED, p->name);
    }
    return 1;
  }
  int effective_trust = resolve_profile_trust_tier(token, p->name);
  return (p->advertise && effective_trust >= p->visibility) ? 1 : 0;
}

static int profile_terms_route_allowed(const uint8_t *token,
                                       const WambleProfile *p,
                                       const char *requested_profile_name,
                                       const char *bound_profile_name,
                                       int trust_tier) {
  if (!p || !requested_profile_name || !requested_profile_name[0])
    return 0;
  if (p->abstract)
    return 0;
  if (bound_profile_name && bound_profile_name[0] &&
      strcmp(requested_profile_name, bound_profile_name) == 0) {
    return 1;
  }
  return profile_discovery_allowed(token, p, trust_tier);
}

static ServerStatus send_policy_denied(wamble_socket_t sockfd,
                                       const struct sockaddr_in *cliaddr,
                                       const uint8_t *token,
                                       const char *profile_name) {
  publish_server_protocol_status(SERVER_PROTOCOL_STATUS_POLICY_DENIED,
                                 profile_name);
  struct WambleMsg err = {0};
  err.ctrl = WAMBLE_CTRL_ERROR;
  memcpy(err.token, token, TOKEN_LENGTH);
  err.view.error_code = WAMBLE_ERR_ACCESS_DENIED;
  if (send_reliable_default(sockfd, &err, cliaddr) != 0) {
    return SERVER_ERR_SEND_FAILED;
  }
  return SERVER_ERR_FORBIDDEN;
}

static ServerStatus send_terms_required(wamble_socket_t sockfd,
                                        const struct sockaddr_in *cliaddr,
                                        const uint8_t *token,
                                        const char *profile_name) {
  char detail[160];
  snprintf(detail, sizeof(detail), "profile=%s terms acceptance required",
           profile_name && profile_name[0] ? profile_name : "default");
  publish_server_protocol_status_detail(SERVER_PROTOCOL_STATUS_POLICY_DENIED,
                                        profile_name, detail);
  struct WambleMsg err = {0};
  err.ctrl = WAMBLE_CTRL_ERROR;
  memcpy(err.token, token, TOKEN_LENGTH);
  err.view.error_code = WAMBLE_ERR_ACCESS_DENIED;
  snprintf(err.view.error_reason, sizeof(err.view.error_reason),
           "terms acceptance required");
  if (send_reliable_default(sockfd, &err, cliaddr) != 0)
    return SERVER_ERR_SEND_FAILED;
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
  case WAMBLE_CTRL_LOGIN_CHALLENGE:
    return "login_challenge";
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
  case WAMBLE_CTRL_ACCEPT_PROFILE_TOS:
    return "accept_profile_tos";
  case WAMBLE_CTRL_GET_ACTIVE_RESERVATIONS:
    return "get_active_reservations";
  case WAMBLE_CTRL_ACTIVE_RESERVATIONS_DATA:
    return "active_reservations_data";
  default:
    return "unknown";
  }
}

static int append_ext_int(struct WambleMsg *msg, const char *key,
                          int64_t value) {
  WambleMessageExtField *field = NULL;
  if (!msg || !key || !key[0] ||
      msg->extensions.count >= WAMBLE_MAX_MESSAGE_EXT_FIELDS) {
    return -1;
  }
  field = &msg->extensions.fields[msg->extensions.count++];
  memset(field, 0, sizeof(*field));
  snprintf(field->key, sizeof(field->key), "%s", key);
  field->value_type = WAMBLE_TREATMENT_VALUE_INT;
  field->int_value = value;
  return 0;
}

static int append_ext_double(struct WambleMsg *msg, const char *key,
                             double value) {
  WambleMessageExtField *field = NULL;
  if (!msg || !key || !key[0] ||
      msg->extensions.count >= WAMBLE_MAX_MESSAGE_EXT_FIELDS) {
    return -1;
  }
  field = &msg->extensions.fields[msg->extensions.count++];
  memset(field, 0, sizeof(*field));
  snprintf(field->key, sizeof(field->key), "%s", key);
  field->value_type = WAMBLE_TREATMENT_VALUE_DOUBLE;
  field->double_value = value;
  return 0;
}

static int append_ext_string(struct WambleMsg *msg, const char *key,
                             const char *value) {
  WambleMessageExtField *field = NULL;
  if (!msg || !key || !key[0] || !value ||
      msg->extensions.count >= WAMBLE_MAX_MESSAGE_EXT_FIELDS) {
    return -1;
  }
  field = &msg->extensions.fields[msg->extensions.count++];
  memset(field, 0, sizeof(*field));
  snprintf(field->key, sizeof(field->key), "%s", key);
  field->value_type = WAMBLE_TREATMENT_VALUE_STRING;
  snprintf(field->string_value, sizeof(field->string_value), "%s", value);
  return 0;
}

static int append_request_seq_ext(struct WambleMsg *msg, uint32_t request_seq) {
  if (!msg || request_seq == 0)
    return -1;
  return append_ext_int(msg, "request.seq_num", (int64_t)request_seq);
}

static int append_error_blocking_ext(struct WambleMsg *msg) {
  if (!msg)
    return -1;
  return append_ext_int(msg, "error.blocking", 1);
}

typedef enum {
  PREDICTION_RESPONSE_KIND_TREE = 0,
  PREDICTION_RESPONSE_KIND_SUBMIT = 1
} PredictionResponseKind;

typedef enum {
  PREDICTION_SUBMIT_STATUS_NONE = 0,
  PREDICTION_SUBMIT_STATUS_CREATED = 1,
  PREDICTION_SUBMIT_STATUS_DUPLICATE = 2,
  PREDICTION_SUBMIT_STATUS_DUPLICATE_MOVE = 3,
  PREDICTION_SUBMIT_STATUS_REJECTED_INVALID = 4,
  PREDICTION_SUBMIT_STATUS_REJECTED_LIMIT = 5,
  PREDICTION_SUBMIT_STATUS_REJECTED_NOT_ALLOWED = 6,
  PREDICTION_SUBMIT_STATUS_REJECTED_NOT_FOUND = 7,
  PREDICTION_SUBMIT_STATUS_REJECTED_DISABLED = 8
} PredictionSubmitStatusCode;

static int
append_prediction_response_metadata(struct WambleMsg *msg,
                                    PredictionResponseKind kind,
                                    PredictionSubmitStatusCode submit_status) {
  if (!msg)
    return -1;
  if (append_ext_string(
          msg, "prediction.request_kind",
          kind == PREDICTION_RESPONSE_KIND_SUBMIT ? "submit" : "tree") != 0) {
    return -1;
  }
  if (kind == PREDICTION_RESPONSE_KIND_SUBMIT) {
    return append_ext_int(msg, "prediction.submit_status",
                          (int64_t)submit_status);
  }
  return 0;
}

static PredictionSubmitStatusCode
prediction_submit_status_code(PredictionStatus st) {
  switch (st) {
  case PREDICTION_OK:
    return PREDICTION_SUBMIT_STATUS_CREATED;
  case PREDICTION_ERR_DUPLICATE:
    return PREDICTION_SUBMIT_STATUS_DUPLICATE;
  case PREDICTION_ERR_DUPLICATE_MOVE:
    return PREDICTION_SUBMIT_STATUS_DUPLICATE_MOVE;
  case PREDICTION_ERR_LIMIT:
    return PREDICTION_SUBMIT_STATUS_REJECTED_LIMIT;
  case PREDICTION_ERR_NOT_ALLOWED:
    return PREDICTION_SUBMIT_STATUS_REJECTED_NOT_ALLOWED;
  case PREDICTION_ERR_NOT_FOUND:
    return PREDICTION_SUBMIT_STATUS_REJECTED_NOT_FOUND;
  case PREDICTION_ERR_DISABLED:
    return PREDICTION_SUBMIT_STATUS_REJECTED_DISABLED;
  case PREDICTION_ERR_INVALID:
  default:
    return PREDICTION_SUBMIT_STATUS_REJECTED_INVALID;
  }
}

static ServerStatus
send_error_terminal_ex(wamble_socket_t sockfd,
                       const struct sockaddr_in *cliaddr, const uint8_t *token,
                       uint64_t board_id, uint16_t err_code, const char *reason,
                       const char *ext_key, int64_t ext_value, int blocking) {
  struct WambleMsg err = {0};
  err.ctrl = WAMBLE_CTRL_ERROR;
  memcpy(err.token, token, TOKEN_LENGTH);
  err.board_id = board_id;
  err.view.error_code = err_code;
  if (reason && reason[0])
    snprintf(err.view.error_reason, sizeof(err.view.error_reason), "%s",
             reason);
  if (ext_key && ext_key[0] && ext_value > 0)
    (void)append_ext_int(&err, ext_key, ext_value);
  if (blocking)
    (void)append_error_blocking_ext(&err);
  if (send_reliable_default(sockfd, &err, cliaddr) != 0)
    return SERVER_ERR_SEND_FAILED;
  return SERVER_ERR_INTERNAL;
}

static ServerStatus send_error_terminal_with_status(
    wamble_socket_t sockfd, const struct sockaddr_in *cliaddr,
    const uint8_t *token, uint64_t board_id, uint16_t err_code,
    const char *reason, const char *ext_key, int64_t ext_value, int blocking,
    ServerStatus status_if_sent) {
  ServerStatus st =
      send_error_terminal_ex(sockfd, cliaddr, token, board_id, err_code, reason,
                             ext_key, ext_value, blocking);
  if (st == SERVER_ERR_SEND_FAILED)
    return st;
  return status_if_sent;
}

static ServerStatus send_error_terminal(wamble_socket_t sockfd,
                                        const struct sockaddr_in *cliaddr,
                                        const uint8_t *token, uint16_t err_code,
                                        const char *reason, const char *ext_key,
                                        int64_t ext_value) {
  return send_error_terminal_ex(sockfd, cliaddr, token, 0, err_code, reason,
                                ext_key, ext_value, 0);
}

static ServerStatus
send_error_terminal_for_request(wamble_socket_t sockfd,
                                const struct sockaddr_in *cliaddr,
                                const uint8_t *token, uint32_t request_seq,
                                uint16_t err_code, const char *reason) {
  struct WambleMsg err = {0};
  err.ctrl = WAMBLE_CTRL_ERROR;
  memcpy(err.token, token, TOKEN_LENGTH);
  err.view.error_code = err_code;
  if (reason && reason[0])
    snprintf(err.view.error_reason, sizeof(err.view.error_reason), "%s",
             reason);
  (void)append_request_seq_ext(&err, request_seq);
  if (send_reliable_default(sockfd, &err, cliaddr) != 0)
    return SERVER_ERR_SEND_FAILED;
  return SERVER_ERR_INTERNAL;
}

static ServerStatus send_access_denied_for_request(
    wamble_socket_t sockfd, const struct sockaddr_in *cliaddr,
    const uint8_t *token, uint32_t request_seq, const char *reason) {
  struct WambleMsg err = {0};
  err.ctrl = WAMBLE_CTRL_ERROR;
  memcpy(err.token, token, TOKEN_LENGTH);
  err.view.error_code = WAMBLE_ERR_ACCESS_DENIED;
  if (reason && reason[0]) {
    snprintf(err.view.error_reason, sizeof(err.view.error_reason), "%s",
             reason);
  }
  if (request_seq > 0)
    (void)append_ext_int(&err, "stats.request_id", (int64_t)request_seq);
  if (send_reliable_default(sockfd, &err, cliaddr) != 0)
    return SERVER_ERR_SEND_FAILED;
  return SERVER_ERR_FORBIDDEN;
}

static const WambleMessageExtField *
find_ext_field_by_key(const struct WambleMsg *msg, const char *key) {
  if (!msg || !key || !key[0])
    return NULL;
  for (uint8_t i = 0; i < msg->extensions.count; i++) {
    if (strcmp(msg->extensions.fields[i].key, key) == 0)
      return &msg->extensions.fields[i];
  }
  return NULL;
}

static int effective_profile_websocket_port(const WambleProfile *profile);
static const char *
effective_profile_websocket_path(const WambleProfile *profile);
static int profile_terms_currently_accepted(const uint8_t *token,
                                            const char *profile_name);
static uint32_t compute_profile_ui_caps(const uint8_t *token,
                                        const WambleProfile *p);
static uint32_t append_session_capability_extensions(struct WambleMsg *msg,
                                                     const uint8_t *token,
                                                     const char *profile_name,
                                                     const WambleBoard *board);

static void fill_profile_info_response(struct WambleMsg *resp,
                                       const uint8_t *token, const char *name,
                                       const char *bound_profile_name,
                                       int effective_trust_tier) {
  const WambleProfile *p = NULL;
  int wrote = 0;
  if (!resp || !token || !name)
    return;
  resp->ctrl = WAMBLE_CTRL_PROFILE_INFO;
  memcpy(resp->token, token, TOKEN_LENGTH);
  p = config_find_profile(name);
  if (p && profile_terms_route_allowed(token, p, name, bound_profile_name,
                                       effective_trust_tier)) {
    int ws_port = effective_profile_websocket_port(p);
    const char *ws_path = effective_profile_websocket_path(p);
    wrote = snprintf(resp->text.profile_info, FEN_MAX_LENGTH, "%s;%d;%d;%d",
                     p->name, p->config.port, p->advertise, p->visibility);
    if (wrote < 0)
      wrote = 0;
    if (wrote >= FEN_MAX_LENGTH)
      wrote = FEN_MAX_LENGTH - 1;
    resp->text.profile_info_len = (uint16_t)wrote;
    (void)append_ext_int(resp, "profile.caps",
                         (int64_t)compute_profile_ui_caps(token, p));
    (void)append_ext_int(resp, "profile.tos_available",
                         (int64_t)((p->tos_text && p->tos_text[0]) ? 1 : 0));
    (void)append_ext_int(
        resp, "profile.tos_accepted",
        (int64_t)profile_terms_currently_accepted(token, p->name));
    (void)append_ext_int(resp, "profile.websocket_port", (int64_t)ws_port);
    if (ws_path)
      (void)append_ext_string(resp, "profile.websocket_path", ws_path);
    (void)append_ext_int(resp, "profile.reservation_timeout",
                         (int64_t)p->config.reservation_timeout);
  } else {
    publish_server_protocol_status(
        p ? SERVER_PROTOCOL_STATUS_PROFILE_INFO_HIDDEN
          : SERVER_PROTOCOL_STATUS_PROFILE_INFO_NOT_FOUND,
        name);
    wrote = snprintf(resp->text.profile_info, FEN_MAX_LENGTH, "NOTFOUND;%.80s",
                     name);
    if (wrote < 0)
      wrote = 0;
    if (wrote >= FEN_MAX_LENGTH)
      wrote = FEN_MAX_LENGTH - 1;
    resp->text.profile_info_len = (uint16_t)wrote;
  }
}

static void append_profile_session_snapshot(struct WambleMsg *resp,
                                            const uint8_t *token,
                                            const char *profile_name) {
  WamblePlayer *player = NULL;
  WambleBoard *board = NULL;
  uint32_t session_caps = 0;
  if (!resp || !token || !profile_name || !profile_name[0])
    return;
  player = get_player_by_token(token);
  if (!player)
    return;
  board = find_board_for_player(player);
  if (!board)
    return;
  session_caps =
      append_session_capability_extensions(resp, token, profile_name, board);
  resp->board_id = board->id;
  write_visible_board_fen(token, profile_name, board, resp->view.fen,
                          sizeof(resp->view.fen));
  if ((session_caps & WAMBLE_SESSION_UI_CAP_GAME_MODE_VISIBLE) != 0 &&
      board->board.game_mode == GAME_MODE_CHESS960) {
    resp->flags |= WAMBLE_FLAG_BOARD_IS_960;
  }
}

static int square_index_from_alg(const char *sq) {
  if (!sq || sq[0] < 'a' || sq[0] > 'h' || sq[1] < '1' || sq[1] > '8')
    return -1;
  return ((int)(sq[1] - '1') * 8) + (int)(sq[0] - 'a');
}

static int collect_board_read_treatment_facts(const WambleBoard *board,
                                              WambleFact *facts,
                                              int max_facts) {
  int fact_count = 0;
  if (!board || !facts || max_facts <= 0)
    return 0;
  memset(facts, 0, sizeof(*facts) * (size_t)max_facts);
  fact_count = wamble_collect_board_treatment_facts(board, facts, max_facts);
  if (token_has_any_byte(board->last_mover_token) &&
      fact_count + 2 <= max_facts) {
    WamblePlayer *prev = get_player_by_token(board->last_mover_token);
    if (prev) {
      snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
               "previous_player.rating");
      facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_DOUBLE;
      facts[fact_count].double_value = prev->rating;
      fact_count++;

      snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
               "previous_player.score");
      facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_DOUBLE;
      facts[fact_count].double_value = prev->score;
      fact_count++;
    }
  }
  return fact_count;
}

static int parse_move_path_indices(const char *path, int *from_idx,
                                   int *to_idx) {
  int from = -1;
  int to = -1;
  if (!path || !from_idx || !to_idx)
    return 0;
  if (strnlen(path, MAX_UCI_LENGTH) < 4)
    return 0;
  from = square_index_from_alg(path);
  to = square_index_from_alg(path + 2);
  if (from < 0 || to < 0 || from == to)
    return 0;
  *from_idx = from;
  *to_idx = to;
  return 1;
}

static void copy_move_path4(const char *path, char *out, size_t out_size) {
  if (!out || out_size == 0)
    return;
  out[0] = '\0';
  if (!path || strnlen(path, MAX_UCI_LENGTH) < 4)
    return;
  snprintf(out, out_size, "%c%c%c%c", path[0], path[1], path[2], path[3]);
}

static int display_path_is_board_consistent(const WambleBoard *board,
                                            int to_idx) {
  Bitboard occupied = 0ULL;
  if (!board || to_idx < 0 || to_idx >= 64)
    return 0;
  occupied = board->board.occupied[0] | board->board.occupied[1];
  return ((occupied & (1ULL << (uint64_t)to_idx)) != 0ULL) ? 1 : 0;
}

static const WambleFact *find_fact_by_key(const WambleFact *facts,
                                          int fact_count, const char *key) {
  if (!facts || fact_count <= 0 || !key || !key[0])
    return NULL;
  for (int i = 0; i < fact_count; i++) {
    if (strcmp(facts[i].key, key) == 0)
      return &facts[i];
  }
  return NULL;
}

static int resolve_last_move_indices(const uint8_t *token,
                                     const char *profile_name,
                                     WambleBoard *board, int *from_idx,
                                     int *to_idx, char *shown_uci,
                                     size_t shown_uci_size) {
  WambleFact facts[32];
  WambleTreatmentAction actions[16];
  int fact_count = 0;
  int action_count = 0;
  int max_age_ms = 0;
  char type[64] = "factual";
  char data_path[256] = {0};
  char data_fact_key[128] = {0};
  const char *candidate_path = NULL;
  int candidate_from = -1;
  int candidate_to = -1;
  int recognized_non_factual = 0;

  if (!token || !profile_name || !profile_name[0] || !board || !from_idx ||
      !to_idx || !shown_uci || shown_uci_size == 0) {
    return 0;
  }
  shown_uci[0] = '\0';

  fact_count = collect_board_read_treatment_facts(board, facts, 32);
  DbStatus treatment_status = wamble_query_resolve_treatment_actions(
      token, profile_name, "board.read", board->last_mover_treatment_group,
      facts, fact_count, actions, 16, &action_count);
  if (treatment_status != DB_OK) {
    publish_treatment_audit_status(TREATMENT_AUDIT_STATUS_QUERY_FAILED,
                                   profile_name);
    return 0;
  }
  publish_treatment_audit_status(action_count > 0
                                     ? TREATMENT_AUDIT_STATUS_TREATED
                                     : TREATMENT_AUDIT_STATUS_UNTREATED,
                                 profile_name);

  for (int i = 0; i < action_count; i++) {
    int ok_num = 0;
    if (strcmp(actions[i].output_kind, "view") != 0)
      continue;
    if (strcmp(actions[i].output_key, "last_move.type") == 0 &&
        actions[i].value_type == WAMBLE_TREATMENT_VALUE_STRING &&
        actions[i].string_value[0]) {
      snprintf(type, sizeof(type), "%s", actions[i].string_value);
    } else if (strcmp(actions[i].output_key, "last_move.mode") == 0 &&
               actions[i].value_type == WAMBLE_TREATMENT_VALUE_STRING &&
               actions[i].string_value[0]) {
      snprintf(type, sizeof(type), "%s",
               strcmp(actions[i].string_value, "off") == 0 ? "off" : "factual");
    } else if (strcmp(actions[i].output_key, "last_move.max_age_ms") == 0) {
      max_age_ms = (int)wamble_treatment_action_number(&actions[i], &ok_num);
      if (!ok_num)
        max_age_ms = 0;
    } else if ((strcmp(actions[i].output_key, "last_move.data.path") == 0 ||
                strcmp(actions[i].output_key, "last_move.path") == 0) &&
               actions[i].value_type == WAMBLE_TREATMENT_VALUE_STRING) {
      snprintf(data_path, sizeof(data_path), "%s", actions[i].string_value);
    } else if (strcmp(actions[i].output_key, "last_move.data.fact_key") == 0 &&
               actions[i].value_type == WAMBLE_TREATMENT_VALUE_STRING) {
      snprintf(data_fact_key, sizeof(data_fact_key), "%s",
               actions[i].string_value);
    }
  }

  if (max_age_ms > 0 && board->last_move_time > 0) {
    int64_t now_ms = (int64_t)wamble_now_wall() * 1000;
    int64_t move_ms = (int64_t)board->last_move_time * 1000;
    if (now_ms > move_ms && (now_ms - move_ms) > (int64_t)max_age_ms)
      return 0;
  }

  if (strcmp(type, "off") == 0)
    return 0;
  if (strcmp(type, "factual") == 0) {
    candidate_path = board->last_move_uci;
  } else if (strcmp(type, "literal") == 0) {
    candidate_path = data_path;
    recognized_non_factual = 1;
  } else if (strcmp(type, "fact") == 0) {
    const WambleFact *f = find_fact_by_key(facts, fact_count, data_fact_key);
    if (f && f->value_type == WAMBLE_TREATMENT_VALUE_STRING)
      candidate_path = f->string_value;
    recognized_non_factual = 1;
  } else {
    return 0;
  }

  if (candidate_path &&
      parse_move_path_indices(candidate_path, &candidate_from, &candidate_to) &&
      display_path_is_board_consistent(board, candidate_to)) {
    *from_idx = candidate_from;
    *to_idx = candidate_to;
    copy_move_path4(candidate_path, shown_uci, shown_uci_size);
    return 1;
  }

  if (recognized_non_factual &&
      parse_move_path_indices(board->last_move_uci, &candidate_from,
                              &candidate_to) &&
      display_path_is_board_consistent(board, candidate_to)) {
    *from_idx = candidate_from;
    *to_idx = candidate_to;
    copy_move_path4(board->last_move_uci, shown_uci, shown_uci_size);
    return 1;
  }
  return 0;
}

static int effective_profile_websocket_port(const WambleProfile *profile) {
  if (!profile || profile->config.websocket_enabled == 0)
    return 0;
  return (profile->config.websocket_port > 0) ? profile->config.websocket_port
                                              : profile->config.port;
}

static const char *
effective_profile_websocket_path(const WambleProfile *profile) {
  if (!profile || profile->config.websocket_enabled == 0)
    return NULL;
  if (!profile->config.websocket_path ||
      profile->config.websocket_path[0] == '\0')
    return "/ws";
  return profile->config.websocket_path;
}

static int protocol_ctrl_allowed(const uint8_t *token, const char *profile_name,
                                 uint8_t ctrl) {
  return policy_check(token, profile_name, "protocol.ctrl",
                      ctrl_policy_resource(ctrl), NULL, NULL, NULL);
}

static int profile_terms_required_for_profile(const WambleProfile *profile) {
  return (profile && profile->tos_text && profile->tos_text[0]) ? 1 : 0;
}

static int profile_terms_currently_accepted(const uint8_t *token,
                                            const char *profile_name) {
  const WambleProfile *profile = NULL;
  uint8_t tos_hash[WAMBLE_FRAGMENT_HASH_LENGTH] = {0};
  int accepted = 0;
  if (!token || !profile_name || !profile_name[0])
    return 1;
  profile = config_find_profile(profile_name);
  if (!profile_terms_required_for_profile(profile))
    return 1;
  crypto_blake2b(tos_hash, sizeof(tos_hash), (const uint8_t *)profile->tos_text,
                 strlen(profile->tos_text));
  if (wamble_query_has_profile_terms_acceptance(token, profile_name, tos_hash,
                                                &accepted) != DB_OK) {
    return 0;
  }
  return accepted ? 1 : 0;
}

typedef enum { CTRL_SCOPE_GLOBAL = 0, CTRL_SCOPE_PROFILE = 1 } CtrlScope;

static CtrlScope ctrl_scope(uint8_t ctrl) {
  switch (ctrl) {
  case WAMBLE_CTRL_ACK:
  case WAMBLE_CTRL_CLIENT_HELLO:
  case WAMBLE_CTRL_CLIENT_GOODBYE:
  case WAMBLE_CTRL_LIST_PROFILES:
  case WAMBLE_CTRL_GET_PROFILE_INFO:
  case WAMBLE_CTRL_GET_PROFILE_TOS:
  case WAMBLE_CTRL_ACCEPT_PROFILE_TOS:
  case WAMBLE_CTRL_GET_ACTIVE_RESERVATIONS:
  case WAMBLE_CTRL_LOGIN_REQUEST:
  case WAMBLE_CTRL_LOGOUT:
    return CTRL_SCOPE_GLOBAL;
  case WAMBLE_CTRL_PLAYER_MOVE:
  case WAMBLE_CTRL_SPECTATE_GAME:
  case WAMBLE_CTRL_SPECTATE_STOP:
  case WAMBLE_CTRL_GET_PLAYER_STATS:
  case WAMBLE_CTRL_GET_LEGAL_MOVES:
  case WAMBLE_CTRL_GET_LEADERBOARD:
  case WAMBLE_CTRL_SUBMIT_PREDICTION:
  case WAMBLE_CTRL_GET_PREDICTIONS:
    return CTRL_SCOPE_PROFILE;
  default:
    return CTRL_SCOPE_PROFILE;
  }
}

static int prediction_tree_read_allowed(uint64_t board_id,
                                        const uint8_t *token) {
  WamblePredictionView probe[1];
  int count = 0;
  return prediction_collect_tree(board_id, token, 0, 0, probe, 1, &count) ==
                 PREDICTION_OK
             ? 1
             : 0;
}

static uint32_t compute_profile_ui_caps(const uint8_t *token,
                                        const WambleProfile *p) {
  uint32_t caps = 0;
  if (!token || !p || !p->name || !p->name[0])
    return 0;
  int join_allowed =
      protocol_ctrl_allowed(token, p->name, WAMBLE_CTRL_CLIENT_HELLO);
  if (join_allowed)
    caps |= WAMBLE_PROFILE_UI_CAP_JOIN;
  if (p->tos_text && p->tos_text[0] &&
      protocol_ctrl_allowed(token, p->name, WAMBLE_CTRL_GET_PROFILE_TOS)) {
    caps |= WAMBLE_PROFILE_UI_CAP_TOS;
  }
  return caps;
}

static uint32_t compute_session_ui_caps(const uint8_t *token,
                                        const char *profile_name,
                                        const WambleBoard *board,
                                        const char **out_prediction_source) {
  uint32_t caps = 0;
  int spectate_proto = 0;
  int prediction_read_proto = 0;
  WamblePlayer *player = NULL;

  if (out_prediction_source)
    *out_prediction_source = "tree";
  if (!token || !profile_name || !profile_name[0] || !board)
    return 0;
  if (!profile_terms_currently_accepted(token, profile_name))
    return 0;

  player = get_player_by_token(token);
  if ((player && !player->has_persistent_identity) ||
      protocol_ctrl_allowed(token, profile_name, WAMBLE_CTRL_LOGIN_REQUEST))
    caps |= WAMBLE_SESSION_UI_CAP_ATTACH_IDENTITY;
  if (protocol_ctrl_allowed(token, profile_name, WAMBLE_CTRL_LOGOUT))
    caps |= WAMBLE_SESSION_UI_CAP_LOGOUT;

  if (board_is_reserved_for_player(board->id, token) &&
      protocol_ctrl_allowed(token, profile_name, WAMBLE_CTRL_GET_LEGAL_MOVES) &&
      protocol_ctrl_allowed(token, profile_name, WAMBLE_CTRL_PLAYER_MOVE) &&
      policy_check(token, profile_name, "game.move", "legal", NULL, NULL,
                   NULL) &&
      policy_check(token, profile_name, "game.move", "play", NULL, NULL,
                   NULL)) {
    caps |= WAMBLE_SESSION_UI_CAP_MOVE;
  }

  if (protocol_ctrl_allowed(token, profile_name,
                            WAMBLE_CTRL_GET_PLAYER_STATS)) {
    uint64_t session_id = 0;
    if (wamble_query_get_session_by_token(token, &session_id) != DB_OK)
      session_id = 0;
    if (stats_read_allowed(token, profile_name, session_id, 0)) {
      caps |= WAMBLE_SESSION_UI_CAP_STATS;
    }
  }

  if (protocol_ctrl_allowed(token, profile_name, WAMBLE_CTRL_GET_LEADERBOARD) &&
      policy_check(token, profile_name, "leaderboard.read", "global", NULL,
                   NULL, NULL)) {
    caps |= WAMBLE_SESSION_UI_CAP_LEADERBOARD;
  }

  spectate_proto =
      protocol_ctrl_allowed(token, profile_name, WAMBLE_CTRL_SPECTATE_GAME) &&
      protocol_ctrl_allowed(token, profile_name, WAMBLE_CTRL_SPECTATE_STOP);
  if (spectate_proto && policy_check(token, profile_name, "spectate.access",
                                     "view", "mode", "summary", NULL)) {
    caps |= WAMBLE_SESSION_UI_CAP_SPECTATE_SUMMARY;
  }
  if (spectate_proto && policy_check(token, profile_name, "spectate.access",
                                     "view", "mode", "focus", NULL)) {
    caps |= WAMBLE_SESSION_UI_CAP_SPECTATE_FOCUS;
  }

  if (protocol_ctrl_allowed(token, profile_name,
                            WAMBLE_CTRL_SUBMIT_PREDICTION) &&
      prediction_submit_allowed_for_player(board, token) == PREDICTION_OK) {
    caps |= WAMBLE_SESSION_UI_CAP_PREDICTION_SUBMIT;
  }

  prediction_read_proto =
      protocol_ctrl_allowed(token, profile_name, WAMBLE_CTRL_GET_PREDICTIONS);
  if (prediction_read_proto &&
      prediction_read_uses_move_projection(token, profile_name, board)) {
    caps |= WAMBLE_SESSION_UI_CAP_PREDICTION_READ;
    if (out_prediction_source)
      *out_prediction_source = "moves";
  } else if (prediction_read_proto &&
             prediction_tree_read_allowed(board->id, token)) {
    caps |= WAMBLE_SESSION_UI_CAP_PREDICTION_READ;
  }

  if (policy_check(token, profile_name, "game.mode", "view", NULL, NULL, NULL))
    caps |= WAMBLE_SESSION_UI_CAP_GAME_MODE_VISIBLE;

  return caps;
}

typedef enum {
  POLICY_CTX_NO_MATCH = -1,
  POLICY_CTX_DENY = 0,
  POLICY_CTX_ALLOW = 1
} PolicyContextResult;

static PolicyContextResult resolve_policy_context_result(
    const uint8_t *token, const char *profile_name, const char *action,
    const char *resource, const char *context_key, const char *context_value) {
  WamblePolicyDecision decision = {0};
  WamblePolicyDecision baseline = {0};
  DbStatus st = wamble_query_resolve_policy_decision(
      token, profile_name, action, resource, context_key, context_value,
      &decision);
  if (st != DB_OK)
    return POLICY_CTX_DENY;
  if (context_key && context_key[0]) {
    DbStatus base_st = wamble_query_resolve_policy_decision(
        token, profile_name, action, resource, NULL, NULL, &baseline);
    if (base_st == DB_OK && decision.rule_id == baseline.rule_id &&
        decision.allowed == baseline.allowed &&
        strcmp(decision.effect, baseline.effect) == 0 &&
        strcmp(decision.reason, baseline.reason) == 0) {
      return POLICY_CTX_NO_MATCH;
    }
  }
  if (!decision.rule_id && !decision.allowed &&
      strcmp(decision.reason, "default_deny_no_rule") == 0)
    return POLICY_CTX_NO_MATCH;
  return decision.allowed ? POLICY_CTX_ALLOW : POLICY_CTX_DENY;
}

static int stats_read_allowed(const uint8_t *token, const char *profile_name,
                              uint64_t target_session_id,
                              uint64_t target_identity_id) {
  PolicyContextResult res = POLICY_CTX_NO_MATCH;
  uint64_t identity_id = target_identity_id;
  if (identity_id == 0 && target_session_id > 0 &&
      wamble_query_get_session_global_identity_id(target_session_id,
                                                  &identity_id) != DB_OK) {
    identity_id = 0;
  }
  if (identity_id > 0) {
    char tags_csv[512] = {0};
    if (wamble_query_get_identity_tags_csv(identity_id, tags_csv,
                                           sizeof(tags_csv)) == DB_OK) {
      if (!tags_csv[0]) {
        res = resolve_policy_context_result(token, profile_name, "stats.read",
                                            "player", "target.identity_tag",
                                            "none");
        if (res != POLICY_CTX_NO_MATCH)
          return res == POLICY_CTX_ALLOW;
      } else {
        char tags_work[sizeof(tags_csv)] = {0};
        snprintf(tags_work, sizeof(tags_work), "%s", tags_csv);
        char *cursor = tags_work;
        while (cursor && cursor[0]) {
          char *sep = strchr(cursor, ',');
          if (sep)
            *sep = '\0';
          if (cursor[0]) {
            res = resolve_policy_context_result(token, profile_name,
                                                "stats.read", "player",
                                                "target.identity_tag", cursor);
            if (res != POLICY_CTX_NO_MATCH)
              return res == POLICY_CTX_ALLOW;
          }
          cursor = sep ? (sep + 1) : NULL;
        }
      }
    }
  }
  res = resolve_policy_context_result(token, profile_name, "stats.read",
                                      "player", NULL, NULL);
  return res == POLICY_CTX_ALLOW;
}

static uint32_t append_session_capability_extensions(struct WambleMsg *msg,
                                                     const uint8_t *token,
                                                     const char *profile_name,
                                                     const WambleBoard *board) {
  const char *prediction_source = "tree";
  uint32_t caps = 0;
  if (!msg || !token || !profile_name || !profile_name[0] || !board)
    return 0;
  caps =
      compute_session_ui_caps(token, profile_name, board, &prediction_source);
  (void)append_ext_int(msg, "session.caps", (int64_t)caps);
  if ((caps & WAMBLE_SESSION_UI_CAP_PREDICTION_READ) != 0) {
    (void)append_ext_string(msg, "prediction.source", prediction_source);
  }
  if ((caps & WAMBLE_SESSION_UI_CAP_PREDICTION_SUBMIT) != 0) {
    (void)append_ext_int(
        msg, "prediction.max_pending",
        (int64_t)prediction_max_pending_for_player(board, token));
  }
  if (board->reservation_time > 0) {
    (void)append_ext_int(msg, "reservation.reserved_at",
                         (int64_t)board->reservation_time);
  }
  return caps;
}

static void append_last_move_extensions(struct WambleMsg *msg,
                                        const uint8_t *token,
                                        const char *profile_name,
                                        WambleBoard *board) {
  int from_idx = -1;
  int to_idx = -1;
  char shown_uci[MAX_UCI_LENGTH] = {0};
  if (!msg || !token || !profile_name || !profile_name[0] || !board)
    return;
  if (!resolve_last_move_indices(token, profile_name, board, &from_idx, &to_idx,
                                 shown_uci, sizeof(shown_uci)))
    return;

  if (strncmp(board->last_move_shown_uci, shown_uci, MAX_UCI_LENGTH) != 0) {
    snprintf(board->last_move_shown_uci, sizeof(board->last_move_shown_uci),
             "%s", shown_uci);
  }

  (void)append_ext_int(msg, "last_move.from", (int64_t)from_idx);
  (void)append_ext_int(msg, "last_move.to", (int64_t)to_idx);
  wamble_emit_record_last_move_shown(board->id, token, shown_uci);
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
                     const WamblePredictionView *rows, int count,
                     PredictionResponseKind kind,
                     PredictionSubmitStatusCode submit_status) {
  struct WambleMsg response = {0};
  response.ctrl = WAMBLE_CTRL_PREDICTION_DATA;
  memcpy(response.token, token, TOKEN_LENGTH);
  response.board_id = board_id;
  if (count < 0)
    count = 0;
  if (count > WAMBLE_MAX_PREDICTION_ENTRIES)
    count = WAMBLE_MAX_PREDICTION_ENTRIES;
  response.prediction.count = (uint8_t)count;
  for (int i = 0; i < count; i++) {
    fill_prediction_entry(&response.prediction.entries[i], &rows[i]);
  }
  (void)append_prediction_response_metadata(&response, kind, submit_status);
  if (send_reliable_default(sockfd, &response, cliaddr) != 0) {
    return SERVER_ERR_SEND_FAILED;
  }
  return SERVER_OK;
}

static ServerStatus handle_client_hello(wamble_socket_t sockfd,
                                        const struct WambleMsg *msg,
                                        const struct sockaddr_in *cliaddr,
                                        const char *profile_name) {
  uint32_t client_version =
      (msg->header_version != 0) ? msg->header_version : msg->seq_num;
  if (client_version < WAMBLE_MIN_CLIENT_VERSION)
    client_version = WAMBLE_MIN_CLIENT_VERSION;

  if (client_version > WAMBLE_PROTO_VERSION) {
    publish_server_protocol_status(
        SERVER_PROTOCOL_STATUS_CLIENT_HELLO_UNSUPPORTED_VERSION, profile_name);
    struct WambleMsg err = {0};
    err.ctrl = WAMBLE_CTRL_ERROR;
    memcpy(err.token, msg->token, TOKEN_LENGTH);
    err.view.error_code = WAMBLE_ERR_UNSUPPORTED_VERSION;
    snprintf(err.view.error_reason, sizeof(err.view.error_reason),
             "upgrade required (client=%u server=%u)", client_version,
             WAMBLE_PROTO_VERSION);
    (void)append_error_blocking_ext(&err);
    (void)send_reliable_default(sockfd, &err, cliaddr);
    return SERVER_ERR_UNSUPPORTED_VERSION;
  }

  const uint8_t supported_caps =
      (uint8_t)(WAMBLE_CAP_HOT_RELOAD | WAMBLE_CAP_PROFILE_STATE);
  uint8_t requested_caps = (uint8_t)(msg->flags & WAMBLE_CAPABILITY_MASK);
  uint8_t negotiated_caps = requested_caps
                                ? (uint8_t)(requested_caps & supported_caps)
                                : supported_caps;

  WamblePlayer *player = NULL;
  if (token_has_any_byte(msg->token)) {
    player = get_player_by_token(msg->token);
  } else {
    uint8_t bound_token[TOKEN_LENGTH];
    if (network_get_bound_token_for_addr(cliaddr, bound_token) == 0)
      player = get_player_by_token(bound_token);
  }
  if (!player) {
    player = create_new_player();
    if (!player) {
      return send_error_terminal(sockfd, cliaddr, msg->token,
                                 WAMBLE_ERR_INTERNAL,
                                 "could not create player session", NULL, 0);
    }
  }

  WambleBoard *board = find_board_for_player(player);
  if (!board) {
    publish_server_protocol_status(SERVER_PROTOCOL_STATUS_UNKNOWN_BOARD,
                                   profile_name);
    return send_error_terminal_ex(
        sockfd, cliaddr, msg->token, 0, WAMBLE_ERR_UNKNOWN_BOARD,
        "no board available for assignment", NULL, 0, 1);
  }

  struct WambleMsg response = {0};
  response.flags = negotiated_caps;
  response.header_version = WAMBLE_PROTO_VERSION;
  memcpy(response.token, player->token, TOKEN_LENGTH);
  response.seq_num = WAMBLE_PROTO_VERSION;
  append_board_snapshot(&response, player->token, profile_name, board,
                        WAMBLE_CTRL_SERVER_HELLO);
  network_bind_client_token(cliaddr, player->token);

  if (send_reliable_default(sockfd, &response, cliaddr) != 0) {
    return SERVER_ERR_SEND_FAILED;
  }

  return SERVER_OK;
}

static ServerStatus handle_client_goodbye(const struct WambleMsg *msg,
                                          const char *profile_name) {
  WamblePlayer *player = get_player_by_token(msg->token);
  if (!player) {
    publish_server_protocol_status(SERVER_PROTOCOL_STATUS_UNKNOWN_PLAYER,
                                   profile_name);
    return SERVER_ERR_UNKNOWN_PLAYER;
  }
  clear_login_challenge(msg->token);
  spectator_discard_by_token(msg->token);
  discard_player_by_token(msg->token);
  return SERVER_OK;
}

static ServerStatus handle_logout(const struct WambleMsg *msg,
                                  const char *profile_name) {
  WamblePlayer *player = get_player_by_token(msg->token);
  if (!player) {
    publish_server_protocol_status(SERVER_PROTOCOL_STATUS_UNKNOWN_PLAYER,
                                   profile_name);
    return SERVER_ERR_UNKNOWN_PLAYER;
  }
  clear_login_challenge(msg->token);
  if (detach_persistent_identity(msg->token) != 0)
    return SERVER_ERR_INTERNAL;
  spectator_discard_by_token(msg->token);
  discard_player_by_token(msg->token);
  return SERVER_OK;
}

static ServerStatus handle_player_move(wamble_socket_t sockfd,
                                       const struct WambleMsg *msg,
                                       const struct sockaddr_in *cliaddr,
                                       const char *profile_name) {
  if (!policy_check(msg->token, profile_name, "game.move", "play", NULL, NULL,
                    NULL)) {
    return send_policy_denied(sockfd, cliaddr, msg->token, profile_name);
  }
  WamblePlayer *player = get_player_by_token(msg->token);
  if (!player) {
    publish_server_protocol_status(SERVER_PROTOCOL_STATUS_UNKNOWN_PLAYER,
                                   profile_name);
    return send_error_terminal_ex(sockfd, cliaddr, msg->token, msg->board_id,
                                  WAMBLE_ERR_UNKNOWN_PLAYER, "unknown player",
                                  NULL, 0, 1);
  }

  WambleBoard *board = get_board_by_id(msg->board_id);
  if (!board) {
    publish_server_protocol_status(SERVER_PROTOCOL_STATUS_UNKNOWN_BOARD,
                                   profile_name);
    return send_error_terminal_ex(sockfd, cliaddr, msg->token, msg->board_id,
                                  WAMBLE_ERR_UNKNOWN_BOARD, "unknown board",
                                  NULL, 0, 1);
  }

  char uci_move[MAX_UCI_LENGTH + 1];
  uint8_t uci_len =
      msg->text.uci_len < MAX_UCI_LENGTH ? msg->text.uci_len : MAX_UCI_LENGTH;
  memcpy(uci_move, msg->text.uci, uci_len);
  uci_move[uci_len] = '\0';

  MoveApplyStatus mv_status = MOVE_ERR_INVALID_ARGS;
  int mv_ok =
      validate_and_apply_move_status(board, player, uci_move, &mv_status);
  if (mv_ok != 0) {
    publish_server_protocol_status(SERVER_PROTOCOL_STATUS_MOVE_REJECTED,
                                   profile_name);
    char reason[64];
    snprintf(reason, sizeof(reason), "move rejected (status=%d)",
             (int)mv_status);
    return send_error_terminal(sockfd, cliaddr, msg->token,
                               WAMBLE_ERR_MOVE_REJECTED, reason, NULL, 0);
  }

  wamble_emit_record_move(board->id, player->token, uci_move,
                          board->board.fullmove_number);
  (void)prediction_resolve_move(board, uci_move);

  board_move_played(board->id, player->token, uci_move);
  board_release_reservation(board->id);

  if (board->result != GAME_RESULT_IN_PROGRESS) {
    board_game_completed(board->id, board->result);
  }

  if (!find_board_for_player(player)) {
    return send_error_terminal(sockfd, cliaddr, msg->token, WAMBLE_ERR_INTERNAL,
                               "no replacement board after move", NULL, 0);
  }
  if (send_reliable_board_state_sync(sockfd, player->token, cliaddr) != 0) {
    return SERVER_ERR_SEND_FAILED;
  }

  return SERVER_OK;
}

static ServerStatus handle_submit_prediction(wamble_socket_t sockfd,
                                             const struct WambleMsg *msg,
                                             const struct sockaddr_in *cliaddr,
                                             const char *profile_name) {
  WambleBoard *board = get_board_by_id(msg->board_id);
  if (!board) {
    publish_server_protocol_status(SERVER_PROTOCOL_STATUS_UNKNOWN_BOARD,
                                   profile_name);
    return SERVER_ERR_UNKNOWN_BOARD;
  }

  char uci[MAX_UCI_LENGTH + 1];
  uint8_t uci_len =
      msg->text.uci_len < MAX_UCI_LENGTH ? msg->text.uci_len : MAX_UCI_LENGTH;
  memcpy(uci, msg->text.uci, uci_len);
  uci[uci_len] = '\0';

  uint64_t prediction_id = 0;
  int can_read = prediction_tree_read_allowed(board->id, msg->token);
  int submit_flags = can_read ? 0 : WAMBLE_PREDICTION_SKIP_MOVE_DUP;
  PredictionStatus st = prediction_submit_with_parent(
      board, msg->token, uci, msg->prediction.parent_id, submit_flags,
      &prediction_id);
  if (st != PREDICTION_OK) {
    publish_server_protocol_status(SERVER_PROTOCOL_STATUS_PREDICTION_REJECTED,
                                   profile_name);
    if ((st == PREDICTION_ERR_DUPLICATE ||
         st == PREDICTION_ERR_DUPLICATE_MOVE) &&
        can_read && prediction_id != 0) {
      WamblePredictionView dup_view;
      if (prediction_get_view_by_id(prediction_id, &dup_view) ==
          PREDICTION_OK) {
        return send_prediction_rows(
            sockfd, cliaddr, msg->token, board->id, &dup_view, 1,
            PREDICTION_RESPONSE_KIND_SUBMIT, prediction_submit_status_code(st));
      }
    }
    return send_prediction_rows(sockfd, cliaddr, msg->token, board->id, NULL, 0,
                                PREDICTION_RESPONSE_KIND_SUBMIT,
                                prediction_submit_status_code(st));
  }

  WamblePredictionView created_view = {0};
  if (prediction_get_view_by_id(prediction_id, &created_view) !=
      PREDICTION_OK) {
    publish_server_protocol_status(SERVER_PROTOCOL_STATUS_PREDICTION_REJECTED,
                                   profile_name);
    return send_prediction_rows(sockfd, cliaddr, msg->token, board->id, NULL, 0,
                                PREDICTION_RESPONSE_KIND_SUBMIT,
                                PREDICTION_SUBMIT_STATUS_REJECTED_INVALID);
  }
  return send_prediction_rows(sockfd, cliaddr, msg->token, board->id,
                              &created_view, 1, PREDICTION_RESPONSE_KIND_SUBMIT,
                              PREDICTION_SUBMIT_STATUS_CREATED);
}

static ServerStatus handle_get_predictions(wamble_socket_t sockfd,
                                           const struct sockaddr_in *cliaddr,
                                           const struct WambleMsg *msg,
                                           const char *profile_name) {
  WamblePredictionView rows[WAMBLE_MAX_PREDICTION_ENTRIES];
  int count = 0;
  int depth = msg->prediction.depth;
  if (depth <= 0)
    depth = get_config()->prediction_view_depth_limit;
  int limit = msg->prediction.limit;
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
    publish_server_protocol_status(SERVER_PROTOCOL_STATUS_PREDICTION_REJECTED,
                                   profile_name);
    return send_error_terminal(sockfd, cliaddr, msg->token,
                               WAMBLE_ERR_PREDICTION_READ_FAILED,
                               "prediction read failed", NULL, 0);
  }
  return send_prediction_rows(sockfd, cliaddr, msg->token, msg->board_id, rows,
                              count, PREDICTION_RESPONSE_KIND_TREE,
                              PREDICTION_SUBMIT_STATUS_NONE);
}

static ServerStatus handle_list_profiles(wamble_socket_t sockfd,
                                         const struct sockaddr_in *cliaddr,
                                         const struct WambleMsg *msg,
                                         int effective_trust_tier) {
  const WambleConfig *cfg = get_config();
  char detail[96];
  snprintf(detail, sizeof(detail), "trust_tier=%d profile_count=%d",
           effective_trust_tier, config_profile_count());
  publish_server_protocol_status_detail(
      SERVER_PROTOCOL_STATUS_PROFILES_LIST_SERVED, wamble_runtime_profile_key(),
      detail);

  int count = config_profile_count();
  const char **names =
      count > 0 ? (const char **)calloc((size_t)count, sizeof(*names)) : NULL;
  int name_count = 0;
  size_t payload_len = 0;
  if (count > 0 && !names)
    return SERVER_ERR_SEND_FAILED;
  for (int i = 0; i < count; i++) {
    const WambleProfile *p = config_get_profile(i);
    if (!p)
      continue;
    if (!profile_discovery_allowed(msg->token, p, effective_trust_tier))
      continue;
    const char *name = p->name ? p->name : "";
    names[name_count++] = name;
    payload_len += strlen(name) + (payload_len ? 1u : 0u);
  }
  if (name_count > 1)
    qsort(names, (size_t)name_count, sizeof(*names), compare_cstr_ptrs);

  char *payload = payload_len > 0 ? (char *)malloc(payload_len + 1) : NULL;
  size_t written = 0;
  if (payload_len > 0 && !payload) {
    free(names);
    return SERVER_ERR_SEND_FAILED;
  }

  for (int i = 0; i < name_count; i++) {
    const char *name = names[i];
    size_t name_len = strlen(name);
    if (written > 0)
      payload[written++] = ',';
    if (name_len > 0) {
      memcpy(payload + written, name, name_len);
      written += name_len;
    }
  }
  if (payload)
    payload[written] = '\0';

  if (send_reliable_payload_bytes(
          sockfd, WAMBLE_CTRL_PROFILES_LIST, msg->token, 0,
          (const uint8_t *)payload, written, cliaddr, cfg->timeout_ms,
          cfg->max_retries, written > (size_t)(FEN_MAX_LENGTH - 1)) != 0) {
    free(payload);
    free(names);
    return SERVER_ERR_SEND_FAILED;
  }
  free(payload);
  free(names);
  return SERVER_OK;
}

static ServerStatus handle_get_profile_info(wamble_socket_t sockfd,
                                            const struct sockaddr_in *cliaddr,
                                            const struct WambleMsg *msg,
                                            int effective_trust_tier) {
  char name[PROFILE_NAME_MAX_LENGTH];
  int nlen = 0;
  nlen = msg->text.profile_name_len < (PROFILE_NAME_MAX_LENGTH - 1)
             ? msg->text.profile_name_len
             : (PROFILE_NAME_MAX_LENGTH - 1);
  if (nlen > 0)
    memcpy(name, msg->text.profile_name, (size_t)nlen);
  name[nlen] = '\0';

  struct WambleMsg resp = {0};
  fill_profile_info_response(&resp, msg->token, name, NULL,
                             effective_trust_tier);
  if (send_reliable_default(sockfd, &resp, cliaddr) != 0) {
    return SERVER_ERR_SEND_FAILED;
  }
  return SERVER_OK;
}

static uint32_t next_fragment_transfer_id(void) {
  uint32_t id = g_fragment_transfer_id_seq++;
  if (id == 0) {
    g_fragment_transfer_id_seq = 2;
    id = 1;
  }
  return id;
}

static void publish_server_protocol_status(int status_code,
                                           const char *profile_name) {
  publish_server_protocol_status_detail(status_code, profile_name, NULL);
}

static void publish_server_protocol_status_detail(int status_code,
                                                  const char *profile_name,
                                                  const char *detail) {
  WambleRuntimeStatus runtime_status = {WAMBLE_RUNTIME_STATUS_SERVER_PROTOCOL,
                                        status_code};
  wamble_runtime_event_publish(
      runtime_status,
      profile_name && profile_name[0] ? profile_name : "default", detail);
}

static void publish_treatment_audit_status(int status_code,
                                           const char *profile_name) {
  WambleRuntimeStatus runtime_status = {WAMBLE_RUNTIME_STATUS_TREATMENT_AUDIT,
                                        status_code};
  wamble_runtime_event_publish(
      runtime_status,
      profile_name && profile_name[0] ? profile_name : "default", NULL);
}

static ServerStatus send_fragmented_payload(
    wamble_socket_t sockfd, const struct sockaddr_in *cliaddr, uint8_t ctrl,
    const uint8_t token[TOKEN_LENGTH], const uint8_t *payload,
    size_t payload_len, const char *profile_name) {
  if (!cliaddr || !token || !payload || WAMBLE_FRAGMENT_DATA_MAX == 0) {
    publish_server_protocol_status(
        SERVER_PROTOCOL_STATUS_FRAGMENTATION_PREPARE_FAILED, profile_name);
    return SERVER_ERR_INTERNAL;
  }
  if (payload_len > UINT32_MAX) {
    publish_server_protocol_status(
        SERVER_PROTOCOL_STATUS_FRAGMENTATION_PREPARE_FAILED, profile_name);
    return SERVER_ERR_INTERNAL;
  }

  size_t max_fragment_size = (size_t)WAMBLE_FRAGMENT_DATA_MAX;
  size_t needed_chunks =
      (payload_len == 0)
          ? 1
          : ((payload_len + max_fragment_size - 1) / max_fragment_size);
  if (needed_chunks == 0 || needed_chunks > UINT16_MAX) {
    publish_server_protocol_status(
        SERVER_PROTOCOL_STATUS_FRAGMENTATION_PREPARE_FAILED, profile_name);
    return SERVER_ERR_INTERNAL;
  }

  if (needed_chunks > 1) {
    publish_server_protocol_status(
        SERVER_PROTOCOL_STATUS_FRAGMENTATION_MULTI_PACKET, profile_name);
  } else {
    publish_server_protocol_status(
        SERVER_PROTOCOL_STATUS_FRAGMENTATION_SINGLE_PACKET, profile_name);
  }

  uint16_t chunk_count = (uint16_t)needed_chunks;
  uint32_t transfer_id = next_fragment_transfer_id();
  uint8_t payload_hash[WAMBLE_FRAGMENT_HASH_LENGTH] = {0};
  crypto_blake2b(payload_hash, WAMBLE_FRAGMENT_HASH_LENGTH, payload,
                 payload_len);

  for (uint16_t chunk_index = 0; chunk_index < chunk_count; chunk_index++) {
    size_t offset = (size_t)chunk_index * max_fragment_size;
    size_t chunk_len = 0;
    if (offset < payload_len) {
      chunk_len = payload_len - offset;
      if (chunk_len > max_fragment_size)
        chunk_len = max_fragment_size;
    }

    struct WambleMsg resp = {0};
    resp.ctrl = ctrl;
    memcpy(resp.token, token, TOKEN_LENGTH);
    resp.fragment.fragment_version = WAMBLE_FRAGMENT_VERSION;
    resp.fragment.fragment_hash_algo = WAMBLE_FRAGMENT_HASH_BLAKE2B_256;
    resp.fragment.fragment_chunk_index = chunk_index;
    resp.fragment.fragment_chunk_count = chunk_count;
    resp.fragment.fragment_total_len = (uint32_t)payload_len;
    resp.fragment.fragment_transfer_id = transfer_id;
    memcpy(resp.fragment.fragment_hash, payload_hash,
           WAMBLE_FRAGMENT_HASH_LENGTH);
    resp.fragment.fragment_data_len = (uint16_t)chunk_len;
    if (chunk_len)
      memcpy(resp.fragment.fragment_data, payload + offset, chunk_len);
    if (send_reliable_default(sockfd, &resp, cliaddr) != 0) {
      publish_server_protocol_status(
          SERVER_PROTOCOL_STATUS_FRAGMENTATION_SEND_FAILED, profile_name);
      return SERVER_ERR_SEND_FAILED;
    }
  }
  return SERVER_OK;
}

static ServerStatus send_profile_tos_payload(
    wamble_socket_t sockfd, const struct sockaddr_in *cliaddr,
    const uint8_t token[TOKEN_LENGTH], const uint8_t *payload,
    size_t payload_len, const char *profile_name, uint32_t request_seq) {
  enum {
    WAMBLE_EXT_MAGIC_0_LOCAL = 0x57,
    WAMBLE_EXT_MAGIC_1_LOCAL = 0x58,
    WAMBLE_EXT_VERSION_LOCAL = 1
  };
  const char *ext_key = "profile.name";
  const char *request_key = "request.seq_num";
  size_t key_len = strnlen(ext_key, WAMBLE_MESSAGE_EXT_KEY_MAX);
  size_t request_key_len = strnlen(request_key, WAMBLE_MESSAGE_EXT_KEY_MAX);
  size_t value_len = strnlen(profile_name ? profile_name : "",
                             WAMBLE_MESSAGE_EXT_STRING_MAX - 1);
  size_t ext_body_len = 0;
  size_t total_len = 0;
  uint8_t *encoded = NULL;
  ServerStatus status = SERVER_ERR_INTERNAL;

  if (!cliaddr || !token || (!payload && payload_len > 0) || key_len == 0 ||
      key_len > 255 || request_key_len == 0 || request_key_len > 255) {
    publish_server_protocol_status(
        SERVER_PROTOCOL_STATUS_FRAGMENTATION_PREPARE_FAILED, profile_name);
    return SERVER_ERR_INTERNAL;
  }
  if (payload_len > SIZE_MAX - 2u - 1u - key_len - 1u - 2u - value_len - 1u -
                        request_key_len - 1u - 8u - 4u) {
    publish_server_protocol_status(
        SERVER_PROTOCOL_STATUS_FRAGMENTATION_PREPARE_FAILED, profile_name);
    return SERVER_ERR_INTERNAL;
  }

  ext_body_len =
      2u + 1u + key_len + 1u + 2u + value_len + 1u + request_key_len + 1u + 8u;
  total_len = payload_len + ext_body_len + 4u;
  encoded = (uint8_t *)malloc(total_len);
  if (!encoded) {
    publish_server_protocol_status(
        SERVER_PROTOCOL_STATUS_FRAGMENTATION_PREPARE_FAILED, profile_name);
    return SERVER_ERR_INTERNAL;
  }

  if (payload_len)
    memcpy(encoded, payload, payload_len);
  {
    size_t off = payload_len;
    uint16_t value_len_be = htons((uint16_t)value_len);
    uint16_t ext_body_len_be = htons((uint16_t)ext_body_len);
    encoded[off++] = WAMBLE_EXT_VERSION_LOCAL;
    encoded[off++] = 2;
    encoded[off++] = (uint8_t)key_len;
    memcpy(encoded + off, ext_key, key_len);
    off += key_len;
    encoded[off++] = (uint8_t)WAMBLE_TREATMENT_VALUE_STRING;
    memcpy(encoded + off, &value_len_be, sizeof(value_len_be));
    off += sizeof(value_len_be);
    if (value_len) {
      memcpy(encoded + off, profile_name, value_len);
      off += value_len;
    }
    encoded[off++] = (uint8_t)request_key_len;
    memcpy(encoded + off, request_key, request_key_len);
    off += request_key_len;
    encoded[off++] = (uint8_t)WAMBLE_TREATMENT_VALUE_INT;
    {
      uint64_t request_seq_be = wamble_host_to_net64((uint64_t)request_seq);
      memcpy(encoded + off, &request_seq_be, sizeof(request_seq_be));
      off += sizeof(request_seq_be);
    }
    encoded[off++] = WAMBLE_EXT_MAGIC_0_LOCAL;
    encoded[off++] = WAMBLE_EXT_MAGIC_1_LOCAL;
    memcpy(encoded + off, &ext_body_len_be, sizeof(ext_body_len_be));
  }

  status =
      send_fragmented_payload(sockfd, cliaddr, WAMBLE_CTRL_PROFILE_TOS_DATA,
                              token, encoded, total_len, profile_name);
  free(encoded);
  return status;
}

static size_t
encode_active_reservations_payload(const DbActiveReservationEntry *rows,
                                   int count, uint8_t *out, size_t out_cap) {
  size_t need = 2;
  if (count < 0)
    count = 0;
  if (count > 0 && !rows)
    return 0;
  if (count > (int)UINT16_MAX)
    count = (int)UINT16_MAX;
  for (int i = 0; i < count; i++) {
    size_t profile_len = strnlen(rows[i].profile_name, PROFILE_NAME_MAX_LENGTH);
    if (profile_len > UINT8_MAX)
      profile_len = UINT8_MAX;
    if (need > SIZE_MAX - (26u + profile_len))
      return 0;
    need += 26u + profile_len;
  }
  if (!out)
    return need;
  if (need > out_cap)
    return 0;
  uint16_t count_be = htons((uint16_t)count);
  memcpy(out, &count_be, 2);
  size_t off = 2;
  for (int i = 0; i < count; i++) {
    uint64_t board_be = wamble_host_to_net64(rows[i].board_id);
    uint64_t reserved_be = wamble_host_to_net64((uint64_t)rows[i].reserved_at);
    uint64_t expires_be = wamble_host_to_net64((uint64_t)rows[i].expires_at);
    size_t profile_len = strnlen(rows[i].profile_name, PROFILE_NAME_MAX_LENGTH);
    if (profile_len > UINT8_MAX)
      profile_len = UINT8_MAX;
    memcpy(out + off, &board_be, 8);
    off += 8;
    memcpy(out + off, &reserved_be, 8);
    off += 8;
    memcpy(out + off, &expires_be, 8);
    off += 8;
    out[off++] = rows[i].available ? 1u : 0u;
    out[off++] = (uint8_t)profile_len;
    if (profile_len > 0) {
      memcpy(out + off, rows[i].profile_name, profile_len);
      off += profile_len;
    }
  }
  return off;
}

static int reservation_rows_contain_board(const DbActiveReservationEntry *rows,
                                          int count, uint64_t board_id) {
  if (!rows || count <= 0 || board_id == 0)
    return 0;
  for (int i = 0; i < count; i++) {
    if (rows[i].board_id == board_id)
      return 1;
  }
  return 0;
}

static int merge_live_reservation_row(const uint8_t *token,
                                      const char *profile_name,
                                      const DbActiveReservationEntry *rows,
                                      int *inout_count,
                                      DbActiveReservationEntry **out_rows) {
  DbActiveReservationEntry live_row = {0};
  DbActiveReservationEntry *merged_rows = NULL;
  int merged_count = 0;

  if (!token || !inout_count || *inout_count < 0 || !out_rows)
    return -1;
  *out_rows = NULL;
  if (!board_fill_active_reservation_for_token(token, &live_row))
    return 0;
  if (reservation_rows_contain_board(rows, *inout_count, live_row.board_id))
    return 0;

  snprintf(live_row.profile_name, sizeof(live_row.profile_name), "%s",
           profile_name ? profile_name : "");
  merged_count = *inout_count > 0 ? (*inout_count + 1) : 1;
  merged_rows = (DbActiveReservationEntry *)malloc(sizeof(*merged_rows) *
                                                   (size_t)merged_count);
  if (!merged_rows)
    return -1;
  if (*inout_count > 0 && rows) {
    memcpy(merged_rows, rows, sizeof(*merged_rows) * (size_t)(*inout_count));
  }
  merged_rows[merged_count - 1] = live_row;
  *inout_count = merged_count;
  *out_rows = merged_rows;
  return 1;
}

static ServerStatus handle_get_active_reservations(
    wamble_socket_t sockfd, const struct sockaddr_in *cliaddr,
    const struct WambleMsg *msg, const char *profile_name) {
  if (!msg || !cliaddr)
    return SERVER_ERR_INTERNAL;
  uint8_t public_key[WAMBLE_PUBLIC_KEY_LENGTH] = {0};
  int has_identity = 0;
  WamblePlayer *player = NULL;
  uint64_t session_id = 0;
  DbStatus session_st =
      wamble_query_get_session_by_token(msg->token, &session_id);
  if (session_st != DB_OK && session_st != DB_NOT_FOUND) {
    return send_error_terminal(sockfd, cliaddr, msg->token,
                               WAMBLE_ERR_RESERVATIONS_FAILED,
                               "session lookup failed", NULL, 0);
  }
  if (session_st == DB_OK && session_id > 0) {
    DbStatus pubkey_st = wamble_query_get_session_public_key(
        session_id, public_key, &has_identity);
    if (pubkey_st != DB_OK && pubkey_st != DB_NOT_FOUND) {
      return send_error_terminal(sockfd, cliaddr, msg->token,
                                 WAMBLE_ERR_RESERVATIONS_FAILED,
                                 "identity lookup failed", NULL, 0);
    }
  }
  if (!has_identity) {
    player = get_player_by_token(msg->token);
    if (player && player->has_persistent_identity) {
      memcpy(public_key, player->public_key, WAMBLE_PUBLIC_KEY_LENGTH);
      has_identity = 1;
    }
  }

  DbActiveReservationsResult reservations = {0};
  int encode_count = 0;
  const DbActiveReservationEntry *encode_rows = NULL;
  DbActiveReservationEntry *merged_rows = NULL;
  if (has_identity) {
    reservations =
        wamble_query_get_active_reservations_by_public_key(public_key);
    if (reservations.status != DB_OK) {
      return send_error_terminal(sockfd, cliaddr, msg->token,
                                 WAMBLE_ERR_RESERVATIONS_FAILED,
                                 "reservations query failed", NULL, 0);
    }
    encode_count = reservations.count;
  } else {
    reservations.status = DB_OK;
    reservations.rows = NULL;
    reservations.count = 0;
    encode_count = 0;
  }

  encode_rows = reservations.rows;
  if (has_identity) {
    if (!player)
      player = get_player_by_token(msg->token);
    if (player && player->has_persistent_identity) {
      int merge_rc = merge_live_reservation_row(msg->token, profile_name,
                                                reservations.rows,
                                                &encode_count, &merged_rows);
      if (merge_rc < 0) {
        return send_error_terminal(sockfd, cliaddr, msg->token,
                                   WAMBLE_ERR_INTERNAL,
                                   "reservations alloc failed", NULL, 0);
      }
      if (merge_rc > 0) {
        encode_rows = merged_rows;
      }
    }
  }

  if (encode_count < 0)
    encode_count = 0;
  if (encode_count > (int)UINT16_MAX)
    encode_count = (int)UINT16_MAX;
  size_t payload_cap =
      encode_active_reservations_payload(encode_rows, encode_count, NULL, 0);
  if (payload_cap == 0) {
    free(merged_rows);
    return send_error_terminal(sockfd, cliaddr, msg->token,
                               WAMBLE_ERR_RESERVATIONS_FAILED,
                               "reservations payload overflow", NULL, 0);
  }
  uint8_t *payload = (uint8_t *)malloc(payload_cap);
  if (!payload) {
    free(merged_rows);
    return send_error_terminal(sockfd, cliaddr, msg->token, WAMBLE_ERR_INTERNAL,
                               "reservations alloc failed", NULL, 0);
  }
  size_t payload_len = encode_active_reservations_payload(
      encode_rows, encode_count, payload, payload_cap);
  if (payload_len == 0 && encode_count > 0) {
    free(merged_rows);
    free(payload);
    return send_error_terminal(sockfd, cliaddr, msg->token,
                               WAMBLE_ERR_RESERVATIONS_FAILED,
                               "reservations encode failed", NULL, 0);
  }
  ServerStatus st = send_fragmented_payload(
      sockfd, cliaddr, WAMBLE_CTRL_ACTIVE_RESERVATIONS_DATA, msg->token,
      payload, payload_len, profile_name);
  free(merged_rows);
  free(payload);
  return st;
}

static ServerStatus handle_get_profile_tos(wamble_socket_t sockfd,
                                           const struct sockaddr_in *cliaddr,
                                           const struct WambleMsg *msg,
                                           const char *profile_name,
                                           int effective_trust_tier) {
  if (!msg || !cliaddr)
    return SERVER_ERR_INTERNAL;
  char name[PROFILE_NAME_MAX_LENGTH];
  int nlen = msg->text.profile_name_len < (PROFILE_NAME_MAX_LENGTH - 1)
                 ? msg->text.profile_name_len
                 : (PROFILE_NAME_MAX_LENGTH - 1);
  if (nlen > 0)
    memcpy(name, msg->text.profile_name, (size_t)nlen);
  name[nlen] = '\0';
  if (!name[0] && profile_name && profile_name[0]) {
    snprintf(name, sizeof(name), "%s", profile_name);
  }

  const WambleProfile *p = config_find_profile(name);
  if (p && profile_terms_route_allowed(msg->token, p, name, profile_name,
                                       effective_trust_tier)) {
    const char *tos = p->tos_text ? p->tos_text : "";
    unsigned long long tos_len =
        (unsigned long long)(p->tos_text ? strlen(p->tos_text) : 0);
    char detail[128];
    snprintf(detail, sizeof(detail), "profile=%.48s trust_tier=%d tos_len=%llu",
             name, effective_trust_tier, tos_len);
    publish_server_protocol_status_detail(
        SERVER_PROTOCOL_STATUS_PROFILE_TOS_SERVED, name, detail);
    return send_profile_tos_payload(sockfd, cliaddr, msg->token,
                                    (const uint8_t *)tos, (size_t)tos_len, name,
                                    msg->seq_num);
  } else {
    publish_server_protocol_status(
        p ? SERVER_PROTOCOL_STATUS_PROFILE_INFO_HIDDEN
          : SERVER_PROTOCOL_STATUS_PROFILE_INFO_NOT_FOUND,
        name);
    char fallback[FEN_MAX_LENGTH];
    int wrote = snprintf(fallback, FEN_MAX_LENGTH, "NOTFOUND;%.80s", name);
    if (wrote < 0)
      wrote = 0;
    if (wrote >= FEN_MAX_LENGTH)
      wrote = FEN_MAX_LENGTH - 1;
    {
      char detail[128];
      snprintf(detail, sizeof(detail),
               "profile=%.48s found=%d trust_tier=%d fallback_len=%d", name,
               p ? 1 : 0, effective_trust_tier, wrote);
      publish_server_protocol_status_detail(
          SERVER_PROTOCOL_STATUS_PROFILE_TOS_FALLBACK, name, detail);
    }
    return send_profile_tos_payload(sockfd, cliaddr, msg->token,
                                    (const uint8_t *)fallback, (size_t)wrote,
                                    name, msg->seq_num);
  }
}

static ServerStatus handle_accept_profile_tos(wamble_socket_t sockfd,
                                              const struct sockaddr_in *cliaddr,
                                              const struct WambleMsg *msg,
                                              const char *profile_name,
                                              int effective_trust_tier) {
  if (!msg || !cliaddr)
    return SERVER_ERR_INTERNAL;

  char name[PROFILE_NAME_MAX_LENGTH];
  int nlen = msg->text.profile_name_len < (PROFILE_NAME_MAX_LENGTH - 1)
                 ? msg->text.profile_name_len
                 : (PROFILE_NAME_MAX_LENGTH - 1);
  if (nlen > 0)
    memcpy(name, msg->text.profile_name, (size_t)nlen);
  name[nlen] = '\0';
  if (!name[0] && profile_name && profile_name[0]) {
    snprintf(name, sizeof(name), "%s", profile_name);
  }

  if ((profile_name && profile_name[0] && strcmp(name, profile_name) != 0) ||
      !name[0]) {
    publish_server_protocol_status(
        SERVER_PROTOCOL_STATUS_PROFILE_TOS_ACCEPT_FAILED, profile_name);
    return send_error_terminal_for_request(
        sockfd, cliaddr, msg->token, msg->seq_num, WAMBLE_ERR_ACCESS_DENIED,
        "access denied");
  }

  const WambleProfile *p = config_find_profile(name);
  if (!p ||
      !profile_terms_route_allowed(msg->token, p, name, profile_name,
                                   effective_trust_tier) ||
      !p->tos_text || !p->tos_text[0]) {
    publish_server_protocol_status(
        SERVER_PROTOCOL_STATUS_PROFILE_TOS_ACCEPT_FAILED, name);
    return send_error_terminal_for_request(
        sockfd, cliaddr, msg->token, msg->seq_num, WAMBLE_ERR_ACCESS_DENIED,
        "access denied");
  }

  uint8_t tos_hash[WAMBLE_FRAGMENT_HASH_LENGTH] = {0};
  const char *tos = p->tos_text;
  uint64_t acceptance_id = 0;
  crypto_blake2b(tos_hash, sizeof(tos_hash), (const uint8_t *)tos, strlen(tos));
  DbStatus st = wamble_query_record_profile_terms_acceptance(
      msg->token, name, tos_hash, tos, &acceptance_id);
  if (st != DB_OK) {
    publish_server_protocol_status(
        SERVER_PROTOCOL_STATUS_PROFILE_TOS_ACCEPT_FAILED, name);
    struct WambleMsg out = {0};
    out.ctrl = WAMBLE_CTRL_ERROR;
    memcpy(out.token, msg->token, TOKEN_LENGTH);
    out.view.error_code = WAMBLE_ERR_ACCESS_DENIED;
    snprintf(out.view.error_reason, sizeof(out.view.error_reason),
             "failed to persist terms acceptance");
    (void)append_request_seq_ext(&out, msg->seq_num);
    if (send_reliable_default(sockfd, &out, cliaddr) != 0)
      return SERVER_ERR_SEND_FAILED;
    return SERVER_ERR_INTERNAL;
  }

  {
    char detail[160];
    snprintf(detail, sizeof(detail),
             "profile=%.48s trust_tier=%d acceptance_id=%llu", name,
             effective_trust_tier, (unsigned long long)acceptance_id);
    publish_server_protocol_status_detail(
        SERVER_PROTOCOL_STATUS_PROFILE_TOS_ACCEPTED, name, detail);
  }
  {
    struct WambleMsg response = {0};
    fill_profile_info_response(&response, msg->token, name, profile_name,
                               effective_trust_tier);
    (void)append_request_seq_ext(&response, msg->seq_num);
    if (profile_name && profile_name[0] && strcmp(name, profile_name) == 0) {
      append_profile_session_snapshot(&response, msg->token, profile_name);
    }
    if (send_reliable_default(sockfd, &response, cliaddr) != 0)
      return SERVER_ERR_SEND_FAILED;
  }
  return SERVER_OK;
}

static int login_has_pubkey(const struct WambleMsg *msg) {
  if (!msg)
    return 0;
  for (int i = 0; i < WAMBLE_PUBLIC_KEY_LENGTH; i++) {
    if (msg->login.public_key[i] != 0)
      return 1;
  }
  return 0;
}

static ServerStatus handle_login_request(wamble_socket_t sockfd,
                                         const struct sockaddr_in *cliaddr,
                                         const struct WambleMsg *msg,
                                         const char *profile_name) {
  struct WambleMsg response = {0};
  memcpy(response.token, msg->token, TOKEN_LENGTH);

  WamblePlayer *existing = get_player_by_token(msg->token);
  int has_key = login_has_pubkey(msg);
  if (!existing || !has_key) {
    publish_server_protocol_status(SERVER_PROTOCOL_STATUS_LOGIN_FAILED,
                                   profile_name);
    response.ctrl = WAMBLE_CTRL_LOGIN_FAILED;
    response.view.error_code = WAMBLE_ERR_ACCESS_DENIED;
    if (send_reliable_default(sockfd, &response, cliaddr) != 0)
      return SERVER_ERR_SEND_FAILED;
    return SERVER_ERR_LOGIN_FAILED;
  }

  if (!msg->login.has_signature) {
    response.ctrl = WAMBLE_CTRL_LOGIN_CHALLENGE;
    if (issue_login_challenge(msg->token, msg->login.public_key,
                              response.login.challenge) != 0) {
      publish_server_protocol_status(SERVER_PROTOCOL_STATUS_LOGIN_FAILED,
                                     profile_name);
      response.ctrl = WAMBLE_CTRL_LOGIN_FAILED;
      response.view.error_code = WAMBLE_ERR_ACCESS_DENIED;
      if (send_reliable_default(sockfd, &response, cliaddr) != 0)
        return SERVER_ERR_SEND_FAILED;
      return SERVER_ERR_LOGIN_FAILED;
    }
    publish_server_protocol_status(
        SERVER_PROTOCOL_STATUS_LOGIN_CHALLENGE_ISSUED, profile_name);
    if (send_reliable_default(sockfd, &response, cliaddr) != 0)
      return SERVER_ERR_SEND_FAILED;
    return SERVER_OK;
  }

  if (verify_login_proof(msg) != 0) {
    publish_server_protocol_status(SERVER_PROTOCOL_STATUS_LOGIN_FAILED,
                                   profile_name);
    response.ctrl = WAMBLE_CTRL_LOGIN_FAILED;
    response.view.error_code = WAMBLE_ERR_ACCESS_DENIED;
    if (send_reliable_default(sockfd, &response, cliaddr) != 0)
      return SERVER_ERR_SEND_FAILED;
    return SERVER_ERR_LOGIN_FAILED;
  }

  WamblePlayer *player =
      attach_persistent_identity(msg->token, msg->login.public_key);
  if (player) {
    publish_server_protocol_status(SERVER_PROTOCOL_STATUS_LOGIN_SUCCESS,
                                   profile_name);
    response.ctrl = WAMBLE_CTRL_LOGIN_SUCCESS;
    memcpy(response.token, player->token, TOKEN_LENGTH);
    append_profile_session_snapshot(&response, player->token, profile_name);
    {
      WambleBoard *board = find_board_for_player(player);
      if (board) {
        append_last_move_extensions(&response, player->token, profile_name,
                                    board);
      }
    }
  } else {
    publish_server_protocol_status(SERVER_PROTOCOL_STATUS_LOGIN_FAILED,
                                   profile_name);
    response.ctrl = WAMBLE_CTRL_LOGIN_FAILED;
    response.view.error_code = WAMBLE_ERR_ACCESS_DENIED;
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
      publish_server_protocol_status(SERVER_PROTOCOL_STATUS_RATE_LIMIT_DENIED,
                                     profile_name);
      struct WambleMsg out = {0};
      out.ctrl = WAMBLE_CTRL_ERROR;
      memcpy(out.token, msg->token, TOKEN_LENGTH);
      out.view.error_code = WAMBLE_ERR_ACCESS_DENIED;
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
      return send_policy_denied(sockfd, cliaddr, msg->token, profile_name);
    }
  }

  if (msg->ctrl != WAMBLE_CTRL_ACK &&
      msg->ctrl != WAMBLE_CTRL_GET_PROFILE_TOS &&
      msg->ctrl != WAMBLE_CTRL_ACCEPT_PROFILE_TOS && profile_name &&
      profile_name[0] && ctrl_scope(msg->ctrl) == CTRL_SCOPE_PROFILE &&
      !profile_terms_currently_accepted(msg->token, profile_name)) {
    return send_terms_required(sockfd, cliaddr, msg->token, profile_name);
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
    return finish_request_after_terminal_send(
        sockfd, msg, cliaddr, handle_client_goodbye(msg, profile_name));
  case WAMBLE_CTRL_PLAYER_MOVE:
    return finish_request_after_terminal_send(
        sockfd, msg, cliaddr,
        handle_player_move(sockfd, msg, cliaddr, profile_name));
  case WAMBLE_CTRL_LIST_PROFILES:
    return handle_list_profiles(sockfd, cliaddr, msg, effective_trust_tier);
  case WAMBLE_CTRL_GET_PROFILE_INFO:
    return handle_get_profile_info(sockfd, cliaddr, msg, effective_trust_tier);
  case WAMBLE_CTRL_GET_PROFILE_TOS:
    return handle_get_profile_tos(sockfd, cliaddr, msg, profile_name,
                                  effective_trust_tier);
  case WAMBLE_CTRL_ACCEPT_PROFILE_TOS:
    return handle_accept_profile_tos(sockfd, cliaddr, msg, profile_name,
                                     effective_trust_tier);
  case WAMBLE_CTRL_GET_ACTIVE_RESERVATIONS:
    return handle_get_active_reservations(sockfd, cliaddr, msg, profile_name);
  case WAMBLE_CTRL_LOGIN_REQUEST:
    return handle_login_request(sockfd, cliaddr, msg, profile_name);
  case WAMBLE_CTRL_LOGOUT:
    return finish_request_after_terminal_send(
        sockfd, msg, cliaddr, handle_logout(msg, profile_name));
  case WAMBLE_CTRL_SPECTATE_GAME: {
    const char *spectate_mode = (msg->board_id == 0) ? "summary" : "focus";
    WamblePolicyDecision decision;
    memset(&decision, 0, sizeof(decision));
    if (!policy_check(msg->token, profile_name, "spectate.access", "view",
                      "mode", spectate_mode, &decision)) {
      publish_server_protocol_status(SERVER_PROTOCOL_STATUS_SPECTATE_DENIED,
                                     profile_name);
      struct WambleMsg out = {0};
      out.ctrl = WAMBLE_CTRL_ERROR;
      memcpy(out.token, msg->token, TOKEN_LENGTH);
      out.view.error_code = WAMBLE_ERR_SPECTATE_VISIBILITY_DENIED;
      if (send_reliable_default(sockfd, &out, cliaddr) != 0) {
        return SERVER_ERR_SEND_FAILED;
      }
      return finish_request_after_terminal_send(sockfd, msg, cliaddr,
                                                SERVER_ERR_FORBIDDEN);
    }
    SpectatorState new_state = SPECTATOR_STATE_IDLE;
    uint64_t focus_id = 0;
    int capacity_bypass =
        policy_check(msg->token, profile_name, "spectate.capacity_bypass",
                     "focus", NULL, NULL, NULL);
    SpectatorRequestStatus res = spectator_handle_request(
        msg, cliaddr, effective_trust_tier, capacity_bypass,
        policy_check(msg->token, profile_name, "game.mode", "view", NULL, NULL,
                     NULL),
        &new_state, &focus_id);
    if (!(res == SPECTATOR_OK_FOCUS || res == SPECTATOR_OK_SUMMARY ||
          res == SPECTATOR_OK_STOP)) {
      uint16_t err_code = WAMBLE_ERR_ACCESS_DENIED;
      publish_server_protocol_status(SERVER_PROTOCOL_STATUS_SPECTATE_DENIED,
                                     profile_name);
      switch (res) {
      case SPECTATOR_ERR_VISIBILITY:
        err_code = WAMBLE_ERR_SPECTATE_VISIBILITY_DENIED;
        break;
      case SPECTATOR_ERR_BUSY:
        err_code = WAMBLE_ERR_SPECTATE_BUSY;
        break;
      case SPECTATOR_ERR_FULL:
        err_code = WAMBLE_ERR_SPECTATE_FULL;
        break;
      case SPECTATOR_ERR_FOCUS_DISABLED:
        err_code = WAMBLE_ERR_ACCESS_DENIED;
        break;
      case SPECTATOR_ERR_NOT_AVAILABLE:
        err_code = WAMBLE_ERR_SPECTATE_NOT_AVAILABLE;
        break;
      default:
        err_code = WAMBLE_ERR_ACCESS_DENIED;
        break;
      }
      struct WambleMsg out = {0};
      out.ctrl = WAMBLE_CTRL_ERROR;
      memcpy(out.token, msg->token, TOKEN_LENGTH);
      out.view.error_code = err_code;
      if (send_reliable_default(sockfd, &out, cliaddr) != 0) {
        return SERVER_ERR_SEND_FAILED;
      }
      return finish_request_after_terminal_send(sockfd, msg, cliaddr,
                                                SERVER_ERR_SPECTATOR);
    }
    if (send_reliable_spectate_state_sync(sockfd, msg->token, cliaddr) != 0) {
      return SERVER_ERR_SEND_FAILED;
    }
    return finish_request_after_terminal_send(sockfd, msg, cliaddr, SERVER_OK);
  }
  case WAMBLE_CTRL_SPECTATE_STOP: {
    SpectatorState new_state = SPECTATOR_STATE_IDLE;
    uint64_t focus_id = 0;
    (void)spectator_handle_request(msg, cliaddr, effective_trust_tier, 0, 0,
                                   &new_state, &focus_id);
    if (send_reliable_spectate_state_sync(sockfd, msg->token, cliaddr) != 0) {
      return SERVER_ERR_SEND_FAILED;
    }
    return finish_request_after_terminal_send(sockfd, msg, cliaddr, SERVER_OK);
  }
  case WAMBLE_CTRL_GET_PLAYER_STATS: {
    const WambleMessageExtField *target_sid_ext =
        find_ext_field_by_key(msg, "stats.target_session_id");
    const WambleMessageExtField *target_handle_ext =
        find_ext_field_by_key(msg, "stats.target_handle");
    const WambleMessageExtField *target_pub_ext =
        find_ext_field_by_key(msg, "stats.target_public_key");
    const WambleMessageExtField *request_id_ext =
        find_ext_field_by_key(msg, "stats.request_id");
    int has_explicit_target = 0;
    int requester_known = 0;
    int target_has_identity = 0;
    int64_t stats_request_id = 0;
    uint64_t target_session_id = 0;
    uint64_t target_identity_id = 0;
    uint64_t requester_session_id = 0;
    char target_handle[WAMBLE_MESSAGE_EXT_STRING_MAX] = {0};
    double score = 0.0;
    int games_played = 0;
    int chess960_games_played = 0;

    if (request_id_ext &&
        request_id_ext->value_type == WAMBLE_TREATMENT_VALUE_INT &&
        request_id_ext->int_value > 0) {
      stats_request_id = request_id_ext->int_value;
    }

    if (wamble_query_get_session_by_token(msg->token, &requester_session_id) ==
        DB_OK) {
      requester_known = 1;
    }

    target_session_id = requester_session_id;
    if (target_sid_ext &&
        target_sid_ext->value_type == WAMBLE_TREATMENT_VALUE_INT &&
        target_sid_ext->int_value > 0) {
      has_explicit_target = 1;
      target_session_id = (uint64_t)target_sid_ext->int_value;
    } else if (target_handle_ext &&
               target_handle_ext->value_type == WAMBLE_TREATMENT_VALUE_STRING &&
               target_handle_ext->string_value[0]) {
      has_explicit_target = 1;
      if (!is_valid_stats_handle(target_handle_ext->string_value))
        return send_access_denied_for_request(sockfd, cliaddr, msg->token,
                                              (uint32_t)stats_request_id,
                                              "invalid stats handle");
      if (wamble_query_get_global_identity_id_by_handle(
              target_handle_ext->string_value, &target_identity_id) != DB_OK ||
          target_identity_id == 0) {
        publish_server_protocol_status(SERVER_PROTOCOL_STATUS_UNKNOWN_PLAYER,
                                       profile_name);
        return send_error_terminal(
            sockfd, cliaddr, msg->token, WAMBLE_ERR_UNKNOWN_PLAYER,
            "unknown stats handle", "stats.request_id", stats_request_id);
      }
      if (wamble_query_get_latest_session_by_global_identity_id(
              target_identity_id, &target_session_id) != DB_OK ||
          target_session_id == 0) {
        publish_server_protocol_status(SERVER_PROTOCOL_STATUS_UNKNOWN_PLAYER,
                                       profile_name);
        return send_error_terminal(sockfd, cliaddr, msg->token,
                                   WAMBLE_ERR_UNKNOWN_PLAYER,
                                   "no session for stats target",
                                   "stats.request_id", stats_request_id);
      }
      snprintf(target_handle, sizeof(target_handle), "%s",
               target_handle_ext->string_value);
    } else if (target_pub_ext &&
               target_pub_ext->value_type == WAMBLE_TREATMENT_VALUE_STRING &&
               target_pub_ext->string_value[0]) {
      return send_access_denied_for_request(sockfd, cliaddr, msg->token,
                                            (uint32_t)stats_request_id,
                                            "stats public key target denied");
    }

    if (target_session_id > 0 &&
        wamble_query_get_session_global_identity_id(
            target_session_id, &target_identity_id) != DB_OK) {
      target_identity_id = 0;
    }

    if (!stats_read_allowed(msg->token, profile_name, target_session_id,
                            target_identity_id))
      return send_access_denied_for_request(sockfd, cliaddr, msg->token,
                                            (uint32_t)stats_request_id,
                                            "stats read denied");

    if (!requester_known) {
      WamblePlayer *requester = get_player_by_token(msg->token);
      if (requester && has_explicit_target) {
        requester_known = 1;
      } else if (requester && !has_explicit_target &&
                 !requester->has_persistent_identity) {
        struct WambleMsg fallback = {0};
        fallback.ctrl = WAMBLE_CTRL_PLAYER_STATS_DATA;
        memcpy(fallback.token, msg->token, TOKEN_LENGTH);
        fallback.stats.player_stats.score = requester->score;
        fallback.stats.player_stats.games_played =
            (requester->games_played > 0) ? (uint32_t)requester->games_played
                                          : 0;
        fallback.stats.player_stats.chess960_games_played =
            (requester->chess960_games_played > 0)
                ? (uint32_t)requester->chess960_games_played
                : 0;
        if (stats_request_id > 0)
          (void)append_ext_int(&fallback, "stats.request_id", stats_request_id);
        (void)append_ext_int(&fallback, "stats.target_session_id", 0);
        (void)append_ext_int(&fallback, "stats.target_has_identity", 0);
        (void)append_ext_string(&fallback, "stats.target_handle", "");
        if (send_reliable_default(sockfd, &fallback, cliaddr) != 0)
          return SERVER_ERR_SEND_FAILED;
        return SERVER_OK;
      } else {
        publish_server_protocol_status(SERVER_PROTOCOL_STATUS_UNKNOWN_PLAYER,
                                       profile_name);
        return send_error_terminal_ex(sockfd, cliaddr, msg->token, 0,
                                      WAMBLE_ERR_UNKNOWN_PLAYER,
                                      "requester session not found",
                                      "stats.request_id", stats_request_id, 1);
      }
    }

    {
      uint8_t target_public_key[32] = {0};
      DbStatus score_st = DB_ERR_EXEC;
      DbStatus games_st = DB_ERR_EXEC;
      DbStatus games960_st = DB_ERR_EXEC;
      if (wamble_query_get_session_public_key(target_session_id,
                                              target_public_key,
                                              &target_has_identity) != DB_OK) {
        target_has_identity = 0;
      }
      if (target_has_identity && target_identity_id > 0) {
        score_st =
            wamble_query_get_identity_total_score(target_identity_id, &score);
        games_st = wamble_query_get_identity_games_played(target_identity_id,
                                                          &games_played);
        games960_st = wamble_query_get_identity_chess960_games_played(
            target_identity_id, &chess960_games_played);
        if (target_handle[0] == '\0') {
          (void)wamble_query_get_identity_handle(
              target_identity_id, target_handle, sizeof(target_handle));
        }
      } else {
        score_st =
            wamble_query_get_player_total_score(target_session_id, &score);
        games_st = wamble_query_get_session_games_played(target_session_id,
                                                         &games_played);
        games960_st = wamble_query_get_session_chess960_games_played(
            target_session_id, &chess960_games_played);
      }
      if (target_session_id == requester_session_id) {
        if (score_st == DB_NOT_FOUND)
          score = 0.0;
        if (games_st == DB_NOT_FOUND)
          games_played = 0;
        if (games960_st == DB_NOT_FOUND)
          chess960_games_played = 0;
      }
      if (!((score_st == DB_OK || (target_session_id == requester_session_id &&
                                   score_st == DB_NOT_FOUND)) &&
            (games_st == DB_OK || (target_session_id == requester_session_id &&
                                   games_st == DB_NOT_FOUND)) &&
            (games960_st == DB_OK ||
             (target_session_id == requester_session_id &&
              games960_st == DB_NOT_FOUND)))) {
        publish_server_protocol_status(SERVER_PROTOCOL_STATUS_UNKNOWN_PLAYER,
                                       profile_name);
        return send_error_terminal(
            sockfd, cliaddr, msg->token, WAMBLE_ERR_STATS_FAILED,
            "stats lookup failed", "stats.request_id", stats_request_id);
      }

      struct WambleMsg response = {0};
      response.ctrl = WAMBLE_CTRL_PLAYER_STATS_DATA;
      memcpy(response.token, msg->token, TOKEN_LENGTH);
      response.stats.player_stats.score = score;
      response.stats.player_stats.games_played =
          (games_played > 0) ? (uint32_t)games_played : 0;
      response.stats.player_stats.chess960_games_played =
          (chess960_games_played > 0) ? (uint32_t)chess960_games_played : 0;
      if (stats_request_id > 0)
        (void)append_ext_int(&response, "stats.request_id", stats_request_id);
      (void)append_ext_int(&response, "stats.target_session_id",
                           (int64_t)target_session_id);
      (void)append_ext_int(&response, "stats.target_has_identity",
                           target_has_identity ? 1 : 0);
      (void)append_ext_string(&response, "stats.target_handle",
                              target_has_identity ? target_handle : "");
      if (send_reliable_default(sockfd, &response, cliaddr) != 0)
        return SERVER_ERR_SEND_FAILED;
      return SERVER_OK;
    }
  }
  case WAMBLE_CTRL_GET_LEADERBOARD: {
    int64_t page_index_ext = 0;
    const WambleMessageExtField *page_index_field = NULL;
    if (!policy_check(msg->token, profile_name, "leaderboard.read", "global",
                      NULL, NULL, NULL)) {
      return send_policy_denied(sockfd, cliaddr, msg->token, profile_name);
    }
    uint8_t lb_type = msg->leaderboard_payload.type;
    if (lb_type != WAMBLE_LEADERBOARD_RATING)
      lb_type = WAMBLE_LEADERBOARD_SCORE;
    uint64_t requester_session_id = 0;
    if (wamble_query_get_session_by_token(msg->token, &requester_session_id) !=
        DB_OK) {
      return send_error_terminal_ex(sockfd, cliaddr, msg->token, 0,
                                    WAMBLE_ERR_UNKNOWN_PLAYER,
                                    "requester session not found", NULL, 0, 1);
    }
    int limit = msg->leaderboard_payload.limit
                    ? (int)msg->leaderboard_payload.limit
                    : 10;
    page_index_field = find_ext_field_by_key(msg, "leaderboard.page_index");
    if (page_index_field &&
        page_index_field->value_type == WAMBLE_TREATMENT_VALUE_INT) {
      page_index_ext = page_index_field->int_value;
    }
    if (page_index_ext < 0)
      page_index_ext = 0;
    int offset = (int)page_index_ext * limit;
    DbLeaderboardResult lb = wamble_query_get_leaderboard(
        requester_session_id, lb_type, limit, offset);
    if (lb.status != DB_OK) {
      return send_error_terminal(sockfd, cliaddr, msg->token,
                                 WAMBLE_ERR_LEADERBOARD_FAILED,
                                 "leaderboard query failed", NULL, 0);
    }
    struct WambleMsg response = {0};
    response.ctrl = WAMBLE_CTRL_LEADERBOARD_DATA;
    memcpy(response.token, msg->token, TOKEN_LENGTH);
    response.leaderboard_payload.type = lb_type;
    response.leaderboard_payload.self_rank = lb.self_rank;
    int count = lb.count;
    if (count < 0)
      count = 0;
    if (count > WAMBLE_MAX_LEADERBOARD_ENTRIES)
      count = WAMBLE_MAX_LEADERBOARD_ENTRIES;
    response.leaderboard_payload.count = (uint8_t)count;
    for (int i = 0; i < count; i++) {
      response.leaderboard_payload.entries[i].rank = lb.rows[i].rank;
      response.leaderboard_payload.entries[i].session_id =
          lb.rows[i].session_id;
      response.leaderboard_payload.entries[i].score = lb.rows[i].score;
      response.leaderboard_payload.entries[i].rating = lb.rows[i].rating;
      response.leaderboard_payload.entries[i].games_played =
          lb.rows[i].games_played;
      response.leaderboard_payload.entries[i].has_identity =
          lb.rows[i].has_identity;
      memcpy(response.leaderboard_payload.entries[i].public_key,
             lb.rows[i].public_key, WAMBLE_PUBLIC_KEY_LENGTH);
      response.leaderboard_payload.entries[i].handle = lb.rows[i].handle;
    }
    (void)append_ext_int(&response, "leaderboard.total_count",
                         (int64_t)lb.total_count);
    (void)append_ext_int(&response, "leaderboard.page_index", page_index_ext);
    (void)append_ext_int(&response, "leaderboard.page_size", limit);
    if (!lb.self_in_rows && lb.self_rank > 0) {
      (void)append_ext_int(&response, "leaderboard.self.rank",
                           (int64_t)lb.self.rank);
      (void)append_ext_int(&response, "leaderboard.self.session_id",
                           (int64_t)lb.self.session_id);
      (void)append_ext_double(&response, "leaderboard.self.score",
                              lb.self.score);
      (void)append_ext_double(&response, "leaderboard.self.rating",
                              lb.self.rating);
      (void)append_ext_int(&response, "leaderboard.self.games_played",
                           (int64_t)lb.self.games_played);
      (void)append_ext_int(&response, "leaderboard.self.has_identity",
                           lb.self.has_identity ? 1 : 0);
      if (lb.self.has_identity) {
        char pub_hex[WAMBLE_PUBLIC_KEY_LENGTH * 2 + 1];
        static const char hex[] = "0123456789abcdef";
        for (int i = 0; i < WAMBLE_PUBLIC_KEY_LENGTH; i++) {
          pub_hex[i * 2] = hex[(lb.self.public_key[i] >> 4) & 0xF];
          pub_hex[i * 2 + 1] = hex[lb.self.public_key[i] & 0xF];
        }
        pub_hex[WAMBLE_PUBLIC_KEY_LENGTH * 2] = '\0';
        (void)append_ext_string(&response, "leaderboard.self.public_key",
                                pub_hex);
      }
    }
    if (send_reliable_default(sockfd, &response, cliaddr) != 0) {
      return SERVER_ERR_SEND_FAILED;
    }
    return SERVER_OK;
  }
  case WAMBLE_CTRL_SUBMIT_PREDICTION:
    return handle_submit_prediction(sockfd, msg, cliaddr, profile_name);
  case WAMBLE_CTRL_GET_PREDICTIONS:
    return handle_get_predictions(sockfd, cliaddr, msg, profile_name);
  case WAMBLE_CTRL_GET_LEGAL_MOVES: {
    if (!policy_check(msg->token, profile_name, "game.move", "legal", NULL,
                      NULL, NULL)) {
      return send_policy_denied(sockfd, cliaddr, msg->token, profile_name);
    }
    WamblePlayer *player = get_player_by_token(msg->token);
    if (!player) {
      publish_server_protocol_status(SERVER_PROTOCOL_STATUS_UNKNOWN_PLAYER,
                                     profile_name);
      return send_error_terminal_ex(sockfd, cliaddr, msg->token, msg->board_id,
                                    WAMBLE_ERR_UNKNOWN_PLAYER, "unknown player",
                                    NULL, 0, 1);
    }

    WambleBoard *board = get_board_by_id(msg->board_id);
    if (!board) {
      publish_server_protocol_status(SERVER_PROTOCOL_STATUS_UNKNOWN_BOARD,
                                     profile_name);
      return send_error_terminal_ex(sockfd, cliaddr, msg->token, msg->board_id,
                                    WAMBLE_ERR_UNKNOWN_BOARD, "unknown board",
                                    NULL, 0, 1);
    }

    struct WambleMsg response = {0};
    response.ctrl = WAMBLE_CTRL_LEGAL_MOVES;
    memcpy(response.token, msg->token, TOKEN_LENGTH);
    response.board_id = msg->board_id;
    response.stats.legal_moves.square = msg->stats.legal_moves.square;

    if (!tokens_equal(board->reservation_player_token, player->token) &&
        !((msg->flags & WAMBLE_FLAG_PREDICTION_CONTEXT) != 0 &&
          prediction_submit_allowed_for_player(board, player->token) ==
              PREDICTION_OK)) {
      response.stats.legal_moves.count = 0;
    } else if (msg->stats.legal_moves.square >= 64) {
      response.stats.legal_moves.count = 0;
      publish_server_protocol_status(
          SERVER_PROTOCOL_STATUS_LEGAL_MOVES_INVALID_REQUEST, profile_name);
      return send_error_terminal(sockfd, cliaddr, msg->token,
                                 WAMBLE_ERR_LEGAL_MOVES_INVALID,
                                 "invalid square index", NULL, 0);
    } else {
      Move moves[WAMBLE_MAX_LEGAL_MOVES];
      int count = get_legal_moves_for_square(&board->board,
                                             msg->stats.legal_moves.square,
                                             moves, WAMBLE_MAX_LEGAL_MOVES);
      if (count < 0) {
        response.stats.legal_moves.count = 0;
        publish_server_protocol_status(
            SERVER_PROTOCOL_STATUS_LEGAL_MOVES_INVALID_REQUEST, profile_name);
        return send_error_terminal(sockfd, cliaddr, msg->token,
                                   WAMBLE_ERR_LEGAL_MOVES_INVALID,
                                   "legal-moves enumeration failed", NULL, 0);
      } else {
        if (count > WAMBLE_MAX_LEGAL_MOVES)
          count = WAMBLE_MAX_LEGAL_MOVES;
        response.stats.legal_moves.count = (uint8_t)count;
        for (int i = 0; i < count; i++) {
          response.stats.legal_moves.entries[i].from = (uint8_t)moves[i].from;
          response.stats.legal_moves.entries[i].to = (uint8_t)moves[i].to;
          response.stats.legal_moves.entries[i].promotion =
              (int8_t)moves[i].promotion;
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
    publish_server_protocol_status(SERVER_PROTOCOL_STATUS_UNKNOWN_CTRL,
                                   profile_name);
    return SERVER_ERR_UNKNOWN_CTRL;
  }
}
