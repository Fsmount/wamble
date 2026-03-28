#include "../include/wamble/wamble.h"
#include <ctype.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  uint64_t board_id;
  uint8_t player_token[TOKEN_LENGTH];
  int correct_streak;
} PredictionStreak;

static void prediction_set_streak(uint64_t board_id, const uint8_t *token,
                                  int streak);
static int prediction_resolve_session_id(const uint8_t *player_token,
                                         uint64_t *out_session_id);
static void prediction_expire_invalid_descendants_locked(uint64_t board_id);
static PredictionStatus prediction_write_allowed_for_player_depth(
    const WambleBoard *board, const uint8_t *player_token, int depth);

static WAMBLE_THREAD_LOCAL WamblePrediction *g_predictions = NULL;
static WAMBLE_THREAD_LOCAL int g_prediction_count = 0;
static WAMBLE_THREAD_LOCAL int g_prediction_cap = 0;
static WAMBLE_THREAD_LOCAL PredictionStreak *g_streaks = NULL;
static WAMBLE_THREAD_LOCAL int g_streak_count = 0;
static WAMBLE_THREAD_LOCAL int g_streak_cap = 0;
static WAMBLE_THREAD_LOCAL wamble_mutex_t g_prediction_mutex;
static WAMBLE_THREAD_LOCAL int g_prediction_mutex_ready = 0;

static int prediction_ensure_streak_capacity_locked(int need) {
  if (need <= g_streak_cap)
    return 0;
  int new_cap = g_streak_cap > 0 ? g_streak_cap : 16;
  while (new_cap < need)
    new_cap *= 2;
  PredictionStreak *new_streaks = (PredictionStreak *)realloc(
      g_streaks, (size_t)new_cap * sizeof(*g_streaks));
  if (!new_streaks)
    return -1;
  memset(new_streaks + g_streak_cap, 0,
         (size_t)(new_cap - g_streak_cap) * sizeof(*new_streaks));
  g_streaks = new_streaks;
  g_streak_cap = new_cap;
  return 0;
}

static int prediction_ensure_capacity_locked(int need) {
  if (need <= g_prediction_cap)
    return 0;
  int new_cap = g_prediction_cap > 0 ? g_prediction_cap : 16;
  while (new_cap < need)
    new_cap *= 2;
  WamblePrediction *new_predictions = (WamblePrediction *)realloc(
      g_predictions, (size_t)new_cap * sizeof(*g_predictions));
  if (!new_predictions)
    return -1;
  memset(new_predictions + g_prediction_cap, 0,
         (size_t)(new_cap - g_prediction_cap) * sizeof(*new_predictions));
  g_predictions = new_predictions;
  g_prediction_cap = new_cap;
  return prediction_ensure_streak_capacity_locked(new_cap);
}

static void prediction_reset_locked(void) {
  free(g_predictions);
  free(g_streaks);
  g_predictions = NULL;
  g_prediction_count = 0;
  g_prediction_cap = 0;
  g_streaks = NULL;
  g_streak_count = 0;
  g_streak_cap = 0;
}

static void prediction_rebuild_streaks_locked(void) {
  g_streak_count = 0;
  for (int i = 0; i < g_prediction_count; i++) {
    const WamblePrediction *pred = &g_predictions[i];
    if (strcmp(pred->status, "PENDING") != 0)
      continue;
    prediction_set_streak(pred->board_id, pred->player_token,
                          pred->correct_streak);
  }
}

static PredictionManagerStatus prediction_load_active_locked(void) {
  DbPredictionsResult rows = wamble_query_get_pending_predictions();
  if (rows.status != DB_OK)
    return PREDICTION_MANAGER_ERR_DB_LOAD;
  if (!rows.rows || rows.count <= 0)
    return PREDICTION_MANAGER_OK;

  for (int i = 0; i < rows.count; i++) {
    const DbPredictionRow *src = &rows.rows[i];
    if (prediction_ensure_capacity_locked(g_prediction_count + 1) != 0)
      return PREDICTION_MANAGER_ERR_ALLOC;
    WamblePrediction *dst = &g_predictions[g_prediction_count++];
    memset(dst, 0, sizeof(*dst));
    dst->id = src->id;
    dst->board_id = src->board_id;
    dst->parent_id = src->parent_prediction_id;
    memcpy(dst->player_token, src->player_token, TOKEN_LENGTH);
    snprintf(dst->predicted_move_uci, sizeof(dst->predicted_move_uci), "%s",
             src->predicted_move_uci);
    snprintf(dst->status, sizeof(dst->status), "%s", src->status);
    dst->target_ply = src->move_number;
    dst->depth = src->depth;
    dst->correct_streak = src->correct_streak;
    dst->points_awarded = src->points_awarded;
    dst->created_at = src->created_at;
  }

  prediction_rebuild_streaks_locked();
  return PREDICTION_MANAGER_OK;
}

static int prediction_resolve_session_id(const uint8_t *player_token,
                                         uint64_t *out_session_id) {
  if (out_session_id)
    *out_session_id = 0;
  if (!player_token)
    return -1;

  uint64_t session_id = 0;
  if (wamble_query_get_session_by_token(player_token, &session_id) == DB_OK &&
      session_id > 0) {
    if (out_session_id)
      *out_session_id = session_id;
    return 0;
  }

  if (wamble_query_create_session(player_token, 0, &session_id) == DB_OK &&
      session_id > 0) {
    if (out_session_id)
      *out_session_id = session_id;
    return 0;
  }

  if (wamble_query_get_session_by_token(player_token, &session_id) == DB_OK &&
      session_id > 0) {
    if (out_session_id)
      *out_session_id = session_id;
    return 0;
  }
  return -1;
}

static int prediction_persist_new_locked(uint64_t board_id,
                                         const uint8_t *player_token,
                                         uint64_t parent_prediction_id,
                                         const char *predicted_move_uci,
                                         int target_ply, int correct_streak,
                                         uint64_t *out_prediction_id) {
  uint64_t session_id = 0;
  if (prediction_resolve_session_id(player_token, &session_id) == 0 &&
      session_id > 0 &&
      wamble_query_create_prediction(
          board_id, session_id, parent_prediction_id, predicted_move_uci,
          target_ply, correct_streak, out_prediction_id) == DB_OK &&
      (!out_prediction_id || *out_prediction_id > 0)) {
    return 0;
  }
  (void)board_id;
  (void)player_token;
  (void)parent_prediction_id;
  (void)predicted_move_uci;
  (void)target_ply;
  (void)correct_streak;
  (void)out_prediction_id;
  return -1;
}

PredictionManagerStatus prediction_manager_init(void) {
  if (g_prediction_mutex_ready) {
    wamble_mutex_lock(&g_prediction_mutex);
    prediction_reset_locked();
    wamble_mutex_unlock(&g_prediction_mutex);
    wamble_mutex_destroy(&g_prediction_mutex);
    g_prediction_mutex_ready = 0;
  }

  wamble_mutex_init(&g_prediction_mutex);
  g_prediction_mutex_ready = 1;

  int max_pending = get_config()->prediction_max_pending;
  if (max_pending < 1)
    max_pending = 1;
  g_prediction_cap =
      max_pending *
      ((get_config()->max_boards > 0) ? get_config()->max_boards : 1);
  if (g_prediction_cap < 16)
    g_prediction_cap = 16;
  g_streak_cap = g_prediction_cap;

  g_predictions = (WamblePrediction *)calloc((size_t)g_prediction_cap,
                                             sizeof(*g_predictions));
  g_streaks =
      (PredictionStreak *)calloc((size_t)g_streak_cap, sizeof(*g_streaks));
  if (!g_predictions || !g_streaks) {
    prediction_reset_locked();
    return PREDICTION_MANAGER_ERR_ALLOC;
  }

  PredictionManagerStatus status = PREDICTION_MANAGER_OK;
  wamble_mutex_lock(&g_prediction_mutex);
  status = prediction_load_active_locked();
  wamble_mutex_unlock(&g_prediction_mutex);
  return status;
}

static int prediction_current_ply(const WambleBoard *board) {
  if (!board)
    return 0;
  int ply = (board->board.fullmove_number - 1) * 2;
  if (board->board.turn == 'b')
    ply += 1;
  return (ply < 0) ? 0 : ply;
}

static int prediction_next_ply(const WambleBoard *board) {
  return prediction_current_ply(board) + 1;
}

static int prediction_valid_uci(const char *uci) {
  size_t len = strnlen(uci ? uci : "", MAX_UCI_LENGTH);
  if (len < 4 || len > 5)
    return 0;
  for (size_t i = 0; i < len; i++) {
    if (!isalnum((unsigned char)uci[i]))
      return 0;
  }
  return 1;
}

static uint64_t prediction_hash_token(const uint8_t *token) {
  uint64_t h = 1469598103934665603ULL;
  for (int i = 0; i < TOKEN_LENGTH; i++) {
    h ^= token[i];
    h *= 1099511628211ULL;
  }
  return h;
}

static int prediction_pending_count_locked(uint64_t board_id);
static int prediction_failed_count_for_locked(uint64_t board_id,
                                              const uint8_t *token);

static int prediction_treatment_feature_bool(const uint8_t *token,
                                             const WambleBoard *board,
                                             const char *key, int *out_value) {
  if (!token || !key || !out_value)
    return 0;
  WambleFact facts[32];
  int fact_count = 0;
  memset(facts, 0, sizeof(facts));
  if (board && board->id > 0) {
    fact_count = wamble_collect_board_treatment_facts(board, facts, 32);

    int have_prev = 0;
    for (int i = 0; i < TOKEN_LENGTH; i++) {
      if (board->last_mover_token[i] != 0) {
        have_prev = 1;
        break;
      }
    }
    if (have_prev && fact_count + 2 <= 32) {
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
  }
  if (fact_count + 5 <= 32) {
    WamblePlayer *self = get_player_by_token(token);
    if (self) {
      snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
               "player.rating");
      facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_DOUBLE;
      facts[fact_count].double_value = self->rating;
      fact_count++;
      snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
               "player.score");
      facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_DOUBLE;
      facts[fact_count].double_value = self->score;
      fact_count++;
      snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
               "player.prediction_score");
      facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_DOUBLE;
      facts[fact_count].double_value = self->prediction_score;
      fact_count++;
      snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
               "player.games_played");
      facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_INT;
      facts[fact_count].int_value = self->games_played;
      fact_count++;
      snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
               "player.chess960_games_played");
      facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_INT;
      facts[fact_count].int_value = self->chess960_games_played;
      fact_count++;
    }
  }
  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "failed_predictions.count");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_INT;
  facts[fact_count].int_value =
      board ? prediction_failed_count_for_locked(board->id, token) : 0;
  fact_count++;
  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "pending_predictions.count");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_INT;
  facts[fact_count].int_value =
      board ? prediction_pending_count_locked(board->id) : 0;
  fact_count++;

  WambleTreatmentAction actions[8];
  int action_count = 0;
  DbStatus treatment_status = wamble_query_resolve_treatment_actions(
      token, "", "prediction.submit",
      board ? board->last_mover_treatment_group : NULL, facts, fact_count,
      actions, 8, &action_count);
  if (treatment_status != DB_OK) {
    WambleRuntimeStatus runtime_status = {WAMBLE_RUNTIME_STATUS_TREATMENT_AUDIT,
                                          TREATMENT_AUDIT_STATUS_QUERY_FAILED};
    wamble_runtime_event_publish(runtime_status, wamble_runtime_profile_key(),
                                 NULL);
    return 0;
  }
  WambleRuntimeStatus runtime_status = {WAMBLE_RUNTIME_STATUS_TREATMENT_AUDIT,
                                        action_count > 0
                                            ? TREATMENT_AUDIT_STATUS_TREATED
                                            : TREATMENT_AUDIT_STATUS_UNTREATED};
  wamble_runtime_event_publish(runtime_status, wamble_runtime_profile_key(),
                               NULL);
  for (int i = 0; i < action_count; i++) {
    if (strcmp(actions[i].output_kind, "feature") != 0 ||
        strcmp(actions[i].output_key, key) != 0) {
      continue;
    }
    if (actions[i].value_type == WAMBLE_TREATMENT_VALUE_BOOL) {
      *out_value = actions[i].bool_value;
      return 1;
    }
    if (actions[i].value_type == WAMBLE_TREATMENT_VALUE_INT) {
      *out_value = actions[i].int_value ? 1 : 0;
      return 1;
    }
  }
  return 0;
}

static int prediction_failed_count_for_locked(uint64_t board_id,
                                              const uint8_t *token) {
  int count = 0;
  for (int i = 0; i < g_prediction_count; i++) {
    if (g_predictions[i].board_id == board_id &&
        tokens_equal(g_predictions[i].player_token, token) &&
        strcmp(g_predictions[i].status, "INCORRECT") == 0) {
      count++;
    }
  }
  return count;
}

static int prediction_collect_actions(const uint8_t *token,
                                      const WambleBoard *board,
                                      const char *hook_name,
                                      WambleTreatmentAction *actions,
                                      int max_actions, int *out_count) {
  if (out_count)
    *out_count = 0;
  if (!token || !hook_name || !actions || max_actions <= 0)
    return -1;
  WambleFact facts[32];
  int fact_count = 0;
  memset(facts, 0, sizeof(facts));
  if (board && board->id > 0) {
    fact_count = wamble_collect_board_treatment_facts(board, facts, 32);

    snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
             "board.last_move");
    facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_STRING;
    snprintf(facts[fact_count].string_value,
             sizeof(facts[fact_count].string_value), "%s", board->fen);
    fact_count++;

    int have_prev = 0;
    for (int i = 0; i < TOKEN_LENGTH; i++) {
      if (board->last_mover_token[i] != 0) {
        have_prev = 1;
        break;
      }
    }
    if (have_prev && fact_count + 2 <= 32) {
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
  }
  if (fact_count + 5 <= 32) {
    WamblePlayer *self = get_player_by_token(token);
    if (self) {
      snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
               "player.rating");
      facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_DOUBLE;
      facts[fact_count].double_value = self->rating;
      fact_count++;
      snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
               "player.score");
      facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_DOUBLE;
      facts[fact_count].double_value = self->score;
      fact_count++;
      snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
               "player.prediction_score");
      facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_DOUBLE;
      facts[fact_count].double_value = self->prediction_score;
      fact_count++;
      snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
               "player.games_played");
      facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_INT;
      facts[fact_count].int_value = self->games_played;
      fact_count++;
      snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
               "player.chess960_games_played");
      facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_INT;
      facts[fact_count].int_value = self->chess960_games_played;
      fact_count++;
    }
  }
  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "prediction.failed_count");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_INT;
  facts[fact_count].int_value =
      board ? prediction_failed_count_for_locked(board->id, token) : 0;
  fact_count++;
  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "failed_predictions.count");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_INT;
  facts[fact_count].int_value =
      board ? prediction_failed_count_for_locked(board->id, token) : 0;
  fact_count++;

  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "prediction.pending_count");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_INT;
  facts[fact_count].int_value =
      board ? prediction_pending_count_locked(board->id) : 0;
  fact_count++;
  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "pending_predictions.count");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_INT;
  facts[fact_count].int_value =
      board ? prediction_pending_count_locked(board->id) : 0;
  fact_count++;

  DbStatus treatment_status = wamble_query_resolve_treatment_actions(
      token, "", hook_name, board ? board->last_mover_treatment_group : NULL,
      facts, fact_count, actions, max_actions, out_count);
  if (treatment_status != DB_OK) {
    WambleRuntimeStatus runtime_status = {WAMBLE_RUNTIME_STATUS_TREATMENT_AUDIT,
                                          TREATMENT_AUDIT_STATUS_QUERY_FAILED};
    wamble_runtime_event_publish(runtime_status, wamble_runtime_profile_key(),
                                 NULL);
    return -1;
  }
  WambleRuntimeStatus runtime_status = {WAMBLE_RUNTIME_STATUS_TREATMENT_AUDIT,
                                        (out_count && *out_count > 0)
                                            ? TREATMENT_AUDIT_STATUS_TREATED
                                            : TREATMENT_AUDIT_STATUS_UNTREATED};
  wamble_runtime_event_publish(runtime_status, wamble_runtime_profile_key(),
                               NULL);
  return 0;
}

int prediction_get_runtime_counts(uint64_t board_id, const uint8_t *token,
                                  int *out_pending_count,
                                  int *out_failed_count) {
  if (out_pending_count)
    *out_pending_count = 0;
  if (out_failed_count)
    *out_failed_count = 0;
  if (board_id == 0 || !token)
    return -1;
  if (!g_prediction_mutex_ready)
    return -1;
  wamble_mutex_lock(&g_prediction_mutex);
  int pending = prediction_pending_count_locked(board_id);
  int failed = prediction_failed_count_for_locked(board_id, token);
  wamble_mutex_unlock(&g_prediction_mutex);
  if (out_pending_count)
    *out_pending_count = pending;
  if (out_failed_count)
    *out_failed_count = failed;
  return 0;
}

static int prediction_gated_allowed(const uint8_t *token,
                                    const WambleBoard *board) {
  int override = 0;
  if (prediction_treatment_feature_bool(token, board, "prediction.gated",
                                        &override)) {
    return override;
  }
  int percent = get_config()->prediction_gated_percent;
  if (percent <= 0)
    return 0;
  if (percent >= 100)
    return 1;
  uint64_t h = prediction_hash_token(token) ^
               (uint64_t)(unsigned int)get_config()->experiment_seed;
  return (int)(h % 100ULL) < percent;
}

static int prediction_match_moves(const char *predicted, const char *actual) {
  if (!predicted || !actual)
    return 0;
  if (get_config()->prediction_match_policy &&
      strcmp(get_config()->prediction_match_policy, "from-to-only") == 0) {
    return strncmp(predicted, actual, 4) == 0;
  }
  return strcmp(predicted, actual) == 0;
}

static int prediction_find_streak(uint64_t board_id, const uint8_t *token) {
  for (int i = 0; i < g_streak_count; i++) {
    if (g_streaks[i].board_id == board_id &&
        tokens_equal(g_streaks[i].player_token, token)) {
      return i;
    }
  }
  return -1;
}

static int prediction_streak_for(uint64_t board_id, const uint8_t *token) {
  int idx = prediction_find_streak(board_id, token);
  return (idx >= 0) ? g_streaks[idx].correct_streak : 0;
}

static int prediction_participated_in_ply_locked(uint64_t board_id,
                                                 int target_ply,
                                                 const uint8_t *token) {
  if (!token)
    return 0;
  for (int i = 0; i < g_prediction_count; i++) {
    const WamblePrediction *pred = &g_predictions[i];
    if (pred->board_id != board_id || pred->target_ply != target_ply)
      continue;
    if (tokens_equal(pred->player_token, token))
      return 1;
  }
  return 0;
}

static void prediction_set_streak(uint64_t board_id, const uint8_t *token,
                                  int streak) {
  int idx = prediction_find_streak(board_id, token);
  if (streak <= 0) {
    if (idx >= 0)
      g_streaks[idx] = g_streaks[--g_streak_count];
    return;
  }
  if (idx >= 0) {
    g_streaks[idx].correct_streak = streak;
    return;
  }
  if (!g_streaks || g_streak_count >= g_streak_cap)
    return;
  PredictionStreak *slot = &g_streaks[g_streak_count++];
  memset(slot, 0, sizeof(*slot));
  slot->board_id = board_id;
  memcpy(slot->player_token, token, TOKEN_LENGTH);
  slot->correct_streak = streak;
}

static int prediction_pending_count_locked(uint64_t board_id) {
  int count = 0;
  for (int i = 0; i < g_prediction_count; i++) {
    if (g_predictions[i].board_id == board_id &&
        strcmp(g_predictions[i].status, "PENDING") == 0) {
      count++;
    }
  }
  return count;
}

static int prediction_pending_count_scoped_locked(uint64_t board_id, int depth,
                                                  uint64_t parent_id) {
  int count = 0;
  for (int i = 0; i < g_prediction_count; i++) {
    const WamblePrediction *p = &g_predictions[i];
    if (p->board_id != board_id || strcmp(p->status, "PENDING") != 0)
      continue;
    if (p->depth != depth || p->parent_id != parent_id)
      continue;
    count++;
  }
  return count;
}

static int prediction_find_dup_locked(uint64_t board_id, const uint8_t *token,
                                      const char *move_uci, uint64_t parent_id,
                                      int check_move_dup, int max_per_parent,
                                      int *out_kind) {
  int self_idx = -1, move_idx = -1;
  int self_pending = 0;
  for (int i = 0; i < g_prediction_count; i++) {
    const WamblePrediction *p = &g_predictions[i];
    if (p->board_id != board_id || p->parent_id != parent_id ||
        strcmp(p->status, "PENDING") != 0)
      continue;
    if (tokens_equal(p->player_token, token)) {
      self_pending++;
      if (self_idx < 0)
        self_idx = i;
    }
    if (move_idx < 0 && check_move_dup &&
        strcmp(p->predicted_move_uci, move_uci) == 0)
      move_idx = i;
    if ((max_per_parent > 0 && self_pending >= max_per_parent) &&
        (!check_move_dup || move_idx >= 0)) {
      break;
    }
  }
  if (max_per_parent > 0 && self_pending >= max_per_parent && self_idx >= 0) {
    *out_kind = 1;
    return self_idx;
  }
  if (move_idx >= 0) {
    *out_kind = 2;
    return move_idx;
  }
  *out_kind = 0;
  return -1;
}

static void prediction_fill_view_locked(const WamblePrediction *pred,
                                        WamblePredictionView *dst) {
  memset(dst, 0, sizeof(*dst));
  dst->id = pred->id;
  dst->parent_id = pred->parent_id;
  dst->board_id = pred->board_id;
  memcpy(dst->player_token, pred->player_token, TOKEN_LENGTH);
  snprintf(dst->predicted_move_uci, sizeof(dst->predicted_move_uci), "%s",
           pred->predicted_move_uci);
  snprintf(dst->status, sizeof(dst->status), "%s", pred->status);
  dst->target_ply = pred->target_ply;
  dst->depth = pred->depth;
  dst->points_awarded = pred->points_awarded;
  dst->created_at = pred->created_at;
}

static int prediction_find_by_id_locked(uint64_t prediction_id) {
  if (prediction_id == 0)
    return -1;
  for (int i = 0; i < g_prediction_count; i++) {
    if (g_predictions[i].id == prediction_id)
      return i;
  }
  return -1;
}

static void prediction_expire_invalid_descendants_locked(uint64_t board_id) {
  int changed = 0;
  do {
    changed = 0;
    for (int i = 0; i < g_prediction_count; i++) {
      WamblePrediction *pred = &g_predictions[i];
      if (pred->board_id != board_id || pred->parent_id == 0 ||
          strcmp(pred->status, "PENDING") != 0) {
        continue;
      }
      int parent_idx = prediction_find_by_id_locked(pred->parent_id);
      if (parent_idx < 0 || g_predictions[parent_idx].board_id != board_id ||
          strcmp(g_predictions[parent_idx].status, "INCORRECT") == 0 ||
          strcmp(g_predictions[parent_idx].status, "EXPIRED") == 0) {
        pred->points_awarded = 0.0;
        snprintf(pred->status, sizeof(pred->status), "EXPIRED");
        wamble_emit_resolve_prediction(board_id, pred->player_token,
                                       pred->target_ply, pred->status, 0.0);
        changed = 1;
      }
    }
  } while (changed);
}

static int prediction_policy_allowed(const uint8_t *token, const char *action,
                                     const char *resource,
                                     const char *context_key,
                                     const char *context_value,
                                     WamblePolicyDecision *out) {
  const char *profile = wamble_runtime_profile_key();
  WamblePolicyDecision decision = {0};
  DbStatus st = wamble_query_resolve_policy_decision(
      token, profile ? profile : "", action, resource, context_key,
      context_value, &decision);
  if (st != DB_OK)
    return 0;
  if (out)
    *out = decision;
  return decision.allowed ? 1 : 0;
}

PredictionStatus
prediction_submit_allowed_for_player(const WambleBoard *board,
                                     const uint8_t *player_token) {
  return prediction_write_allowed_for_player_depth(board, player_token, 0);
}

static PredictionStatus prediction_write_allowed_for_player_depth(
    const WambleBoard *board, const uint8_t *player_token, int depth) {
  if (!board || !player_token)
    return PREDICTION_ERR_INVALID;
  if (get_config()->prediction_mode == PREDICTION_MODE_DISABLED)
    return PREDICTION_ERR_DISABLED;
  if (depth < 0)
    depth = 0;

  const char *resource = "streak";
  if (get_config()->prediction_mode == PREDICTION_MODE_NEXT_SELF_MOVE) {
    resource = "self";
    if (!board_is_reserved_for_player(board->id, player_token))
      return PREDICTION_ERR_NOT_ALLOWED;
  } else if (get_config()->prediction_mode == PREDICTION_MODE_GATED) {
    resource = "gated";
    if (!prediction_gated_allowed(player_token, board))
      return PREDICTION_ERR_NOT_ALLOWED;
  }

  char board_buf[32];
  WamblePolicyDecision decision = {0};
  snprintf(board_buf, sizeof(board_buf), "%llu", (unsigned long long)board->id);
  if (!prediction_policy_allowed(player_token, "prediction.write", resource,
                                 "board", board_buf, &decision)) {
    return PREDICTION_ERR_NOT_ALLOWED;
  }
  if (decision.permission_level < depth) {
    return PREDICTION_ERR_NOT_ALLOWED;
  }
  return PREDICTION_OK;
}

static int prediction_treatment_max_pending_locked(const uint8_t *token,
                                                   const WambleBoard *board,
                                                   int fallback) {
  WambleTreatmentAction actions[16];
  int action_count = 0;
  if (prediction_collect_actions(token, board, "prediction.submit", actions, 16,
                                 &action_count) != 0) {
    return fallback;
  }
  for (int i = 0; i < action_count; i++) {
    if (strcmp(actions[i].output_kind, "behavior") != 0 ||
        strcmp(actions[i].output_key, "prediction.max_pending") != 0) {
      continue;
    }
    if (actions[i].value_type == WAMBLE_TREATMENT_VALUE_INT &&
        actions[i].int_value > 0) {
      return (int)actions[i].int_value;
    }
  }
  return fallback;
}

static double
prediction_apply_resolution_adjustments_locked(const uint8_t *token,
                                               const WambleBoard *board,
                                               int is_correct, double points) {
  WambleTreatmentAction actions[16];
  int action_count = 0;
  const char *hook = is_correct ? "prediction.submit" : "prediction.submit";
  if (prediction_collect_actions(token, board, hook, actions, 16,
                                 &action_count) != 0) {
    return points;
  }
  for (int i = 0; i < action_count; i++) {
    if (strcmp(actions[i].output_kind, "behavior") != 0)
      continue;
    int ok = 0;
    double value = wamble_treatment_action_number(&actions[i], &ok);
    if (!ok)
      continue;
    if (strcmp(actions[i].output_key, "prediction.points.multiplier") == 0) {
      points *= value;
    } else if (strcmp(actions[i].output_key, "prediction.points.bonus") == 0) {
      points += value;
    } else if (!is_correct && strcmp(actions[i].output_key,
                                     "prediction.penalty.multiplier") == 0) {
      points *= value;
    }
  }
  return points;
}

static int prediction_treatment_view_depth_cap(const uint8_t *token,
                                               int fallback) {
  WambleTreatmentAction actions[16];
  int action_count = 0;
  if (prediction_collect_actions(token, NULL, "prediction.read", actions, 16,
                                 &action_count) != 0) {
    return fallback;
  }
  for (int i = 0; i < action_count; i++) {
    if (strcmp(actions[i].output_kind, "behavior") != 0 ||
        strcmp(actions[i].output_key, "prediction.view_depth_cap") != 0) {
      continue;
    }
    if (actions[i].value_type == WAMBLE_TREATMENT_VALUE_INT &&
        actions[i].int_value >= 0) {
      return (int)actions[i].int_value;
    }
  }
  return fallback;
}

static double prediction_points_for_streak(int streak_before) {
  int cap = get_config()->prediction_streak_cap;
  if (cap < 1)
    cap = 1;
  int exponent = streak_before;
  if (exponent < 0)
    exponent = 0;
  if (exponent >= cap)
    exponent = cap - 1;
  return get_config()->prediction_base_points *
         pow(get_config()->prediction_streak_multiplier, (double)exponent);
}

PredictionStatus prediction_submit(WambleBoard *board,
                                   const uint8_t *player_token,
                                   const char *predicted_move_uci,
                                   int trust_tier) {
  (void)trust_tier;
  return prediction_submit_with_parent(board, player_token, predicted_move_uci,
                                       0, 0, NULL);
}

PredictionStatus prediction_submit_with_parent(WambleBoard *board,
                                               const uint8_t *player_token,
                                               const char *predicted_move_uci,
                                               uint64_t parent_prediction_id,
                                               int flags,
                                               uint64_t *out_prediction_id) {
  PredictionStatus st =
      prediction_submit_allowed_for_player(board, player_token);
  if (st != PREDICTION_OK)
    return st;
  if (!prediction_valid_uci(predicted_move_uci))
    return PREDICTION_ERR_INVALID;
  if (!g_prediction_mutex_ready || !g_predictions)
    return PREDICTION_ERR_INVALID;

  int check_move_dup = !(flags & WAMBLE_PREDICTION_SKIP_MOVE_DUP);
  int max_per_parent = get_config()->prediction_max_per_parent;
  if (max_per_parent < 0)
    max_per_parent = 0;
  if (!get_config()->prediction_enforce_move_duplicate)
    check_move_dup = 0;
  wamble_mutex_lock(&g_prediction_mutex);

  int depth = 0;
  int target_ply = prediction_next_ply(board);
  int current_ply = prediction_current_ply(board);
  if (parent_prediction_id > 0) {
    int parent_idx = prediction_find_by_id_locked(parent_prediction_id);
    if (parent_idx < 0 || g_predictions[parent_idx].board_id != board->id) {
      wamble_mutex_unlock(&g_prediction_mutex);
      return PREDICTION_ERR_NOT_FOUND;
    }
    if (strcmp(g_predictions[parent_idx].status, "INCORRECT") == 0 ||
        strcmp(g_predictions[parent_idx].status, "EXPIRED") == 0) {
      wamble_mutex_unlock(&g_prediction_mutex);
      return PREDICTION_ERR_INVALID;
    }
    depth = g_predictions[parent_idx].depth + 1;
    target_ply = g_predictions[parent_idx].target_ply + 1;
    if (prediction_write_allowed_for_player_depth(board, player_token, depth) !=
        PREDICTION_OK) {
      wamble_mutex_unlock(&g_prediction_mutex);
      return PREDICTION_ERR_NOT_ALLOWED;
    }
  }

  {
    int max_pending = get_config()->prediction_max_pending;
    if (max_pending < 1)
      max_pending = 1;
    max_pending = prediction_treatment_max_pending_locked(player_token, board,
                                                          max_pending);
    if (prediction_pending_count_scoped_locked(
            board->id, depth, parent_prediction_id) >= max_pending) {
      wamble_mutex_unlock(&g_prediction_mutex);
      return PREDICTION_ERR_LIMIT;
    }
  }
  {
    int dup_kind = 0;
    int dup_idx = prediction_find_dup_locked(
        board->id, player_token, predicted_move_uci, parent_prediction_id,
        check_move_dup, max_per_parent, &dup_kind);
    if (dup_idx >= 0) {
      if (out_prediction_id)
        *out_prediction_id = g_predictions[dup_idx].id;
      wamble_mutex_unlock(&g_prediction_mutex);
      return dup_kind == 1 ? PREDICTION_ERR_DUPLICATE
                           : PREDICTION_ERR_DUPLICATE_MOVE;
    }
  }
  if (prediction_ensure_capacity_locked(g_prediction_count + 1) != 0) {
    wamble_mutex_unlock(&g_prediction_mutex);
    return PREDICTION_ERR_LIMIT;
  }

  if (target_ply <= current_ply) {
    wamble_mutex_unlock(&g_prediction_mutex);
    return PREDICTION_ERR_INVALID;
  }

  int streak_before = prediction_streak_for(board->id, player_token);
  uint64_t db_prediction_id = 0;
  if (prediction_persist_new_locked(
          board->id, player_token, parent_prediction_id, predicted_move_uci,
          target_ply, streak_before, &db_prediction_id) != 0 ||
      db_prediction_id == 0) {
    wamble_mutex_unlock(&g_prediction_mutex);
    return PREDICTION_ERR_INVALID;
  }

  WamblePrediction *slot = &g_predictions[g_prediction_count++];
  memset(slot, 0, sizeof(*slot));
  slot->id = db_prediction_id;
  slot->board_id = board->id;
  slot->parent_id = parent_prediction_id;
  memcpy(slot->player_token, player_token, TOKEN_LENGTH);
  snprintf(slot->predicted_move_uci, sizeof(slot->predicted_move_uci), "%s",
           predicted_move_uci);
  snprintf(slot->status, sizeof(slot->status), "PENDING");
  slot->target_ply = target_ply;
  slot->depth = depth;
  slot->correct_streak = streak_before;
  slot->points_awarded = 0.0;
  slot->created_at = wamble_now_wall();
  if (out_prediction_id)
    *out_prediction_id = slot->id;

  wamble_mutex_unlock(&g_prediction_mutex);
  return PREDICTION_OK;
}

PredictionStatus prediction_resolve_move(WambleBoard *board,
                                         const char *actual_move_uci) {
  if (!board || !actual_move_uci || !g_prediction_mutex_ready || !g_predictions)
    return PREDICTION_ERR_INVALID;

  int resolved_ply = prediction_current_ply(board);
  int resolved_any = 0;

  wamble_mutex_lock(&g_prediction_mutex);

  for (int i = g_prediction_count - 1; i >= 0; i--) {
    WamblePrediction *pred = &g_predictions[i];
    if (pred->board_id != board->id || pred->target_ply != resolved_ply ||
        strcmp(pred->status, "PENDING") != 0) {
      continue;
    }

    resolved_any = 1;
    if (prediction_match_moves(pred->predicted_move_uci, actual_move_uci)) {
      double points =
          (get_config()->prediction_mode == PREDICTION_MODE_NEXT_SELF_MOVE)
              ? get_config()->prediction_base_points
              : prediction_points_for_streak(pred->correct_streak);
      points = prediction_apply_resolution_adjustments_locked(
          pred->player_token, board, 1, points);
      pred->points_awarded = points;
      snprintf(pred->status, sizeof(pred->status), "CORRECT");
      if (points != 0.0)
        (void)scoring_apply_prediction_points(pred->player_token, points);
      prediction_set_streak(board->id, pred->player_token,
                            pred->correct_streak + 1);
      wamble_emit_resolve_prediction(board->id, pred->player_token,
                                     pred->target_ply, pred->status, points);
    } else {
      double penalty = -fabs(get_config()->prediction_penalty_incorrect);
      penalty = prediction_apply_resolution_adjustments_locked(
          pred->player_token, board, 0, penalty);
      pred->points_awarded = penalty;
      snprintf(pred->status, sizeof(pred->status), "INCORRECT");
      if (penalty != 0.0)
        (void)scoring_apply_prediction_points(pred->player_token, penalty);
      prediction_set_streak(board->id, pred->player_token, 0);
      wamble_emit_resolve_prediction(board->id, pred->player_token,
                                     pred->target_ply, pred->status, penalty);
    }
  }

  prediction_expire_invalid_descendants_locked(board->id);

  if (get_config()->prediction_mode != PREDICTION_MODE_NEXT_SELF_MOVE) {
    for (int i = g_streak_count - 1; i >= 0; i--) {
      if (g_streaks[i].board_id != board->id)
        continue;
      int participated = prediction_participated_in_ply_locked(
          board->id, resolved_ply, g_streaks[i].player_token);
      if (!participated)
        g_streaks[i] = g_streaks[--g_streak_count];
    }
  }

  wamble_mutex_unlock(&g_prediction_mutex);
  return resolved_any ? PREDICTION_OK : PREDICTION_NONE;
}

PredictionStatus prediction_collect_tree(uint64_t board_id,
                                         const uint8_t *requester_token,
                                         int trust_tier, int max_depth,
                                         WamblePredictionView *out, int max_out,
                                         int *out_count) {
  (void)trust_tier;
  if (out_count)
    *out_count = 0;
  if (!requester_token || !out || max_out <= 0)
    return PREDICTION_ERR_INVALID;

  WamblePolicyDecision decision = {0};
  char depth_buf[16];
  snprintf(depth_buf, sizeof(depth_buf), "%d", max_depth);
  if (!prediction_policy_allowed(requester_token, "prediction.read", "tree",
                                 "depth", depth_buf, &decision)) {
    return PREDICTION_ERR_NOT_ALLOWED;
  }

  int allowed_depth = get_config()->prediction_view_depth_limit;
  if (allowed_depth < 0)
    allowed_depth = 0;
  allowed_depth =
      prediction_treatment_view_depth_cap(requester_token, allowed_depth);
  if (decision.permission_level >= 0 &&
      decision.permission_level < allowed_depth)
    allowed_depth = decision.permission_level;
  if (max_depth >= 0 && max_depth < allowed_depth)
    allowed_depth = max_depth;

  wamble_mutex_lock(&g_prediction_mutex);
  int count = 0;
  for (int i = 0; i < g_prediction_count && count < max_out; i++) {
    const WamblePrediction *pred = &g_predictions[i];
    if (pred->board_id != board_id || pred->depth > allowed_depth)
      continue;
    prediction_fill_view_locked(pred, &out[count++]);
  }
  wamble_mutex_unlock(&g_prediction_mutex);

  if (out_count)
    *out_count = count;
  return PREDICTION_OK;
}

PredictionStatus prediction_get_view_by_id(uint64_t prediction_id,
                                           WamblePredictionView *out) {
  if (!out || prediction_id == 0)
    return PREDICTION_ERR_INVALID;
  if (!g_prediction_mutex_ready)
    return PREDICTION_ERR_INVALID;
  wamble_mutex_lock(&g_prediction_mutex);
  int idx = prediction_find_by_id_locked(prediction_id);
  if (idx < 0) {
    wamble_mutex_unlock(&g_prediction_mutex);
    return PREDICTION_ERR_NOT_FOUND;
  }
  prediction_fill_view_locked(&g_predictions[idx], out);
  wamble_mutex_unlock(&g_prediction_mutex);
  return PREDICTION_OK;
}

static void prediction_clear_board(uint64_t board_id) {
  if (!g_prediction_mutex_ready)
    return;
  wamble_mutex_lock(&g_prediction_mutex);
  for (int i = g_prediction_count - 1; i >= 0; i--) {
    if (g_predictions[i].board_id == board_id)
      g_predictions[i] = g_predictions[--g_prediction_count];
  }
  for (int i = g_streak_count - 1; i >= 0; i--) {
    if (g_streaks[i].board_id == board_id)
      g_streaks[i] = g_streaks[--g_streak_count];
  }
  wamble_mutex_unlock(&g_prediction_mutex);
}

void prediction_expire_board(uint64_t board_id) {
  if (!g_prediction_mutex_ready)
    return;

  wamble_mutex_lock(&g_prediction_mutex);
  for (int i = 0; i < g_prediction_count; i++) {
    WamblePrediction *pred = &g_predictions[i];
    if (pred->board_id != board_id || strcmp(pred->status, "PENDING") != 0)
      continue;
    pred->points_awarded = 0.0;
    snprintf(pred->status, sizeof(pred->status), "EXPIRED");
    wamble_emit_resolve_prediction(board_id, pred->player_token,
                                   pred->target_ply, pred->status, 0.0);
  }
  wamble_mutex_unlock(&g_prediction_mutex);

  prediction_clear_board(board_id);
}
