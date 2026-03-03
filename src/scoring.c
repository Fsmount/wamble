#include "../include/wamble/wamble.h"
#include "../include/wamble/wamble_db.h"
#include <string.h>

typedef struct {
  uint8_t player_token[TOKEN_LENGTH];
  int white_moves;
  int black_moves;
} PlayerContribution;

static double scoring_action_number(const WambleTreatmentAction *action,
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

static void scoring_apply_treatment_adjustments(const WambleBoard *board,
                                                WamblePlayer *player,
                                                int white_moves,
                                                int black_moves,
                                                double *score) {
  if (!board || !player || !score)
    return;
  WambleFact facts[5];
  int fact_count = 0;
  memset(facts, 0, sizeof(facts));

  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "board.id");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_INT;
  facts[fact_count].int_value = (int64_t)board->id;
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

  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "player.white_moves");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_INT;
  facts[fact_count].int_value = white_moves;
  fact_count++;

  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "player.black_moves");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_INT;
  facts[fact_count].int_value = black_moves;
  fact_count++;

  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "player.rating");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_DOUBLE;
  facts[fact_count].double_value = player->rating;
  fact_count++;

  WambleTreatmentAction actions[16];
  int action_count = 0;
  if (db_resolve_treatment_actions(
          player->token, "", "scoring.apply", board->last_mover_treatment_group,
          facts, fact_count, actions, 16, &action_count) != DB_OK) {
    return;
  }

  for (int i = 0; i < action_count; i++) {
    const WambleTreatmentAction *action = &actions[i];
    if (strcmp(action->output_kind, "feature") == 0 &&
        strcmp(action->output_key, "scoring.disable") == 0 &&
        action->value_type == WAMBLE_TREATMENT_VALUE_BOOL &&
        action->bool_value) {
      *score = 0.0;
      continue;
    }
    if (strcmp(action->output_kind, "behavior") != 0)
      continue;
    int ok = 0;
    double value = scoring_action_number(action, &ok);
    if (!ok)
      continue;
    if (strcmp(action->output_key, "payout.multiplier") == 0) {
      *score *= value;
    } else if (strcmp(action->output_key, "payout.bonus") == 0) {
      *score += value;
    }
  }
  if (*score < 0.0)
    *score = 0.0;
}

static ScoringStatus calculate_and_distribute_pot_for_moves_internal(
    uint64_t board_id, WambleBoard *board, const WambleMove *moves,
    int num_moves) {
  if (!board)
    return SCORING_ERR_INVALID;
  if (!moves || num_moves <= 0)
    return SCORING_NONE;

  PlayerContribution *contributions = malloc(
      sizeof(PlayerContribution) * (size_t)get_config()->max_contributors);
  if (!contributions) {
    return SCORING_ERR_DB;
  }
  int num_contributors = 0;
  int total_white_moves = 0;
  int total_black_moves = 0;

  for (int i = 0; i < num_moves; i++) {
    const WambleMove *move = &moves[i];
    int contributor_index = -1;
    for (int j = 0; j < num_contributors; j++) {
      if (tokens_equal(contributions[j].player_token, move->player_token)) {
        contributor_index = j;
        break;
      }
    }

    if (contributor_index == -1 &&
        num_contributors < get_config()->max_contributors) {
      contributor_index = num_contributors++;
      memcpy(contributions[contributor_index].player_token, move->player_token,
             TOKEN_LENGTH);
      contributions[contributor_index].white_moves = 0;
      contributions[contributor_index].black_moves = 0;
    }

    if (contributor_index != -1) {
      if (move->is_white_move) {
        contributions[contributor_index].white_moves++;
        total_white_moves++;
      } else {
        contributions[contributor_index].black_moves++;
        total_black_moves++;
      }
    }
  }

  double white_pot = 0.0;
  double black_pot = 0.0;

  if (board->result == GAME_RESULT_WHITE_WINS) {
    white_pot = get_config()->max_pot;
  } else if (board->result == GAME_RESULT_BLACK_WINS) {
    black_pot = get_config()->max_pot;
  } else if (board->result == GAME_RESULT_DRAW) {
    white_pot = get_config()->max_pot / 2.0;
    black_pot = get_config()->max_pot / 2.0;
  }

  for (int i = 0; i < num_contributors; i++) {
    PlayerContribution *contrib = &contributions[i];
    double score = 0.0;

    if (total_white_moves > 0) {
      score += ((double)contrib->white_moves / total_white_moves) * white_pot;
    }
    if (total_black_moves > 0) {
      score += ((double)contrib->black_moves / total_black_moves) * black_pot;
    }

    if (contrib->white_moves > 0 && contrib->black_moves > 0) {
      score /= 2.0;
    }

    WamblePlayer *player = get_player_by_token(contrib->player_token);
    if (player) {
      scoring_apply_treatment_adjustments(board, player, contrib->white_moves,
                                          contrib->black_moves, &score);
    }

    if (score > 0.0) {
      wamble_emit_record_payout(board_id, contrib->player_token, score);
    }

    if (player) {
      player->score += score;
    }
  }

  free(contributions);
  return SCORING_OK;
}

ScoringStatus calculate_and_distribute_pot_for_moves(WambleBoard *board,
                                                     const WambleMove *moves,
                                                     int num_moves) {
  uint64_t board_id = board ? board->id : 0;
  if (!board)
    return SCORING_ERR_INVALID;
  if (board->result == GAME_RESULT_IN_PROGRESS)
    return SCORING_NONE;
  return calculate_and_distribute_pot_for_moves_internal(board_id, board, moves,
                                                         num_moves);
}

ScoringStatus calculate_and_distribute_pot(uint64_t board_id) {
  WambleBoard *board = get_board_by_id(board_id);
  if (!board) {
    return SCORING_ERR_INVALID;
  }
  if (board->result == GAME_RESULT_IN_PROGRESS) {
    return SCORING_NONE;
  }

  DbMovesResult mres = wamble_query_get_moves_for_board(board_id);
  if (mres.status == DB_NOT_FOUND) {
    return SCORING_NONE;
  }
  if (mres.status != DB_OK) {
    return SCORING_ERR_DB;
  }
  if (mres.count <= 0 || !mres.rows) {
    return SCORING_NONE;
  }
  return calculate_and_distribute_pot_for_moves_internal(board_id, board,
                                                         mres.rows, mres.count);
}

int scoring_apply_prediction_points(const uint8_t *token, double points) {
  if (!token || points == 0.0)
    return -1;

  WamblePlayer *player = get_player_by_token(token);
  if (player) {
    player->prediction_score += points;
  }
  return 0;
}
