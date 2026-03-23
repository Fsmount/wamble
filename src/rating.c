#include "wamble/wamble.h"
#include <string.h>

static int rating_seen_map_index(const uint8_t *map_tokens,
                                 const int *map_slots, int map_size,
                                 const uint8_t *token) {
  if (!map_tokens || !map_slots || map_size <= 0 || !token)
    return -1;
  int idx = (int)(wamble_token_hash32(token) % (uint32_t)map_size);
  for (int n = 0; n < map_size; n++) {
    int slot = map_slots[idx];
    if (slot < 0)
      return -1;
    if (memcmp(&map_tokens[idx * TOKEN_LENGTH], token, TOKEN_LENGTH) == 0)
      return slot;
    idx++;
    if (idx == map_size)
      idx = 0;
  }
  return -1;
}

static int rating_seen_map_insert(uint8_t *map_tokens, int *map_slots,
                                  int map_size, const uint8_t *token,
                                  int seen_slot) {
  if (!map_tokens || !map_slots || map_size <= 0 || !token || seen_slot < 0)
    return -1;
  int idx = (int)(wamble_token_hash32(token) % (uint32_t)map_size);
  for (int n = 0; n < map_size; n++) {
    int slot = map_slots[idx];
    if (slot < 0) {
      memcpy(&map_tokens[idx * TOKEN_LENGTH], token, TOKEN_LENGTH);
      map_slots[idx] = seen_slot;
      return 0;
    }
    if (memcmp(&map_tokens[idx * TOKEN_LENGTH], token, TOKEN_LENGTH) == 0)
      return 0;
    idx++;
    if (idx == map_size)
      idx = 0;
  }
  return -1;
}

static void rating_apply_treatment_adjustments(const WambleBoard *board,
                                               WamblePlayer *player,
                                               double *delta) {
  if (!board || !player || !delta)
    return;
  WambleFact facts[24];
  int fact_count = 0;
  memset(facts, 0, sizeof(facts));
  fact_count = wamble_collect_board_treatment_facts(board, facts, 24);

  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "player.rating");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_DOUBLE;
  facts[fact_count].double_value = player->rating;
  fact_count++;
  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "player.score");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_DOUBLE;
  facts[fact_count].double_value = player->score;
  fact_count++;
  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "player.prediction_score");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_DOUBLE;
  facts[fact_count].double_value = player->prediction_score;
  fact_count++;
  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "player.games_played");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_INT;
  facts[fact_count].int_value = player->games_played;
  fact_count++;
  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "player.chess960_games_played");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_INT;
  facts[fact_count].int_value = player->chess960_games_played;
  fact_count++;

  int have_prev = 0;
  for (int i = 0; i < TOKEN_LENGTH; i++) {
    if (board->last_mover_token[i] != 0) {
      have_prev = 1;
      break;
    }
  }
  if (have_prev && fact_count + 2 <= 24) {
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

  WambleTreatmentAction actions[16];
  int action_count = 0;
  DbStatus treatment_status = wamble_query_resolve_treatment_actions(
      player->token, "", "rating.adjust", board->last_mover_treatment_group,
      facts, fact_count, actions, 16, &action_count);
  if (treatment_status != DB_OK) {
    WambleRuntimeStatus runtime_status = {WAMBLE_RUNTIME_STATUS_TREATMENT_AUDIT,
                                          TREATMENT_AUDIT_STATUS_QUERY_FAILED};
    wamble_runtime_event_publish(runtime_status, wamble_runtime_profile_key(),
                                 NULL);
    return;
  }
  WambleRuntimeStatus runtime_status = {WAMBLE_RUNTIME_STATUS_TREATMENT_AUDIT,
                                        action_count > 0
                                            ? TREATMENT_AUDIT_STATUS_TREATED
                                            : TREATMENT_AUDIT_STATUS_UNTREATED};
  wamble_runtime_event_publish(runtime_status, wamble_runtime_profile_key(),
                               NULL);

  for (int i = 0; i < action_count; i++) {
    const WambleTreatmentAction *action = &actions[i];
    if (strcmp(action->output_kind, "feature") == 0 &&
        strcmp(action->output_key, "rating.disable") == 0 &&
        action->value_type == WAMBLE_TREATMENT_VALUE_BOOL &&
        action->bool_value) {
      *delta = 0.0;
      continue;
    }
    if (strcmp(action->output_kind, "behavior") != 0)
      continue;
    int ok = 0;
    double value = wamble_treatment_action_number(action, &ok);
    if (!ok)
      continue;
    if (strcmp(action->output_key, "rating.delta") == 0) {
      *delta += value;
    } else if (strcmp(action->output_key, "rating.multiplier") == 0) {
      *delta *= value;
    }
  }
}

void update_player_ratings(WambleBoard *board) {
  if (!board)
    return;

  DbMovesResult mres = wamble_query_get_moves_for_board(board->id);
  if (mres.status != DB_OK || !mres.rows || mres.count <= 0)
    return;

  uint8_t *seen = calloc((size_t)mres.count, TOKEN_LENGTH);
  if (!seen)
    return;
  int map_size = (mres.count * 2) + 1;
  int *seen_slots = NULL;
  uint8_t *seen_map_tokens = NULL;
  if (map_size > 0) {
    seen_slots = malloc(sizeof(int) * (size_t)map_size);
    seen_map_tokens = calloc((size_t)map_size, TOKEN_LENGTH);
  }
  if (!seen_slots || !seen_map_tokens) {
    free(seen_slots);
    free(seen_map_tokens);
    free(seen);
    return;
  }
  for (int i = 0; i < map_size; i++)
    seen_slots[i] = -1;
  int seen_count = 0;

  for (int i = 0; i < mres.count; i++) {
    const uint8_t *token = mres.rows[i].player_token;
    if (rating_seen_map_index(seen_map_tokens, seen_slots, map_size, token) >=
        0)
      continue;
    memcpy(&seen[seen_count * TOKEN_LENGTH], token, TOKEN_LENGTH);
    (void)rating_seen_map_insert(seen_map_tokens, seen_slots, map_size, token,
                                 seen_count);
    seen_count++;
  }

  for (int i = 0; i < seen_count; i++) {
    const uint8_t *token = &seen[i * TOKEN_LENGTH];
    WamblePlayer *player = get_player_by_token(token);
    if (!player)
      continue;
    double delta = 0.0;
    rating_apply_treatment_adjustments(board, player, &delta);
    if (delta == 0.0)
      continue;
    player->rating += delta;
    uint64_t session_id = 0;
    if (wamble_query_get_session_by_token(token, &session_id) == DB_OK &&
        session_id > 0) {
      wamble_emit_update_player_rating(token, player->rating);
    }
  }
  free(seen_map_tokens);
  free(seen_slots);
  free(seen);
}
