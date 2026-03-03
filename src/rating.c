#include "../include/wamble/wamble.h"
#include "../include/wamble/wamble_db.h"
#include <string.h>

static double rating_action_number(const WambleTreatmentAction *action,
                                   int *ok) {
  if (ok)
    *ok = 0;
  if (!action)
    return 0.0;
  if (action->value_type == WAMBLE_TREATMENT_VALUE_INT) {
    if (ok)
      *ok = 1;
    return (double)action->int_value;
  }
  if (action->value_type == WAMBLE_TREATMENT_VALUE_DOUBLE) {
    if (ok)
      *ok = 1;
    return action->double_value;
  }
  return 0.0;
}

static void rating_apply_treatment_adjustments(const WambleBoard *board,
                                               WamblePlayer *player,
                                               double *delta) {
  if (!board || !player || !delta)
    return;
  WambleFact facts[3];
  int fact_count = 0;
  memset(facts, 0, sizeof(facts));

  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "board.id");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_INT;
  facts[fact_count].int_value = (int64_t)board->id;
  fact_count++;

  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "player.rating");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_DOUBLE;
  facts[fact_count].double_value = player->rating;
  fact_count++;

  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "board.result");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_STRING;
  if (board->result == GAME_RESULT_WHITE_WINS) {
    snprintf(facts[fact_count].string_value,
             sizeof(facts[fact_count].string_value), "%s", "white");
  } else if (board->result == GAME_RESULT_BLACK_WINS) {
    snprintf(facts[fact_count].string_value,
             sizeof(facts[fact_count].string_value), "%s", "black");
  } else {
    snprintf(facts[fact_count].string_value,
             sizeof(facts[fact_count].string_value), "%s", "draw");
  }
  fact_count++;

  WambleTreatmentAction actions[16];
  int action_count = 0;
  if (db_resolve_treatment_actions(
          player->token, "", "rating.adjust", board->last_mover_treatment_group,
          facts, fact_count, actions, 16, &action_count) != DB_OK) {
    return;
  }

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
    double value = rating_action_number(action, &ok);
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

  uint8_t seen[TOKEN_LENGTH * 64];
  int seen_count = 0;
  memset(seen, 0, sizeof(seen));

  for (int i = 0; i < mres.count; i++) {
    const uint8_t *token = mres.rows[i].player_token;
    int already_seen = 0;
    for (int j = 0; j < seen_count; j++) {
      if (memcmp(&seen[j * TOKEN_LENGTH], token, TOKEN_LENGTH) == 0) {
        already_seen = 1;
        break;
      }
    }
    if (already_seen || seen_count >= 64)
      continue;
    memcpy(&seen[seen_count * TOKEN_LENGTH], token, TOKEN_LENGTH);
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
      (void)db_async_update_player_rating(session_id, player->rating);
    }
  }
}
