#include "wamble/wamble.h"
#include <string.h>

typedef struct {
  uint8_t player_token[TOKEN_LENGTH];
  int white_moves;
  int black_moves;
} PlayerContribution;

static int scoring_map_find(const uint8_t *map_tokens, const int *map_values,
                            int map_size, const uint8_t *token) {
  if (!map_tokens || !map_values || map_size <= 0 || !token)
    return -1;
  int idx = (int)(wamble_token_hash32(token) % (uint32_t)map_size);
  for (int n = 0; n < map_size; n++) {
    int slot = map_values[idx];
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

static int scoring_map_insert(uint8_t *map_tokens, int *map_values,
                              int map_size, const uint8_t *token, int value) {
  if (!map_tokens || !map_values || map_size <= 0 || !token || value < 0)
    return -1;
  int idx = (int)(wamble_token_hash32(token) % (uint32_t)map_size);
  for (int n = 0; n < map_size; n++) {
    int slot = map_values[idx];
    if (slot < 0) {
      memcpy(&map_tokens[idx * TOKEN_LENGTH], token, TOKEN_LENGTH);
      map_values[idx] = value;
      return 0;
    }
    if (memcmp(&map_tokens[idx * TOKEN_LENGTH], token, TOKEN_LENGTH) == 0) {
      map_values[idx] = value;
      return 0;
    }
    idx++;
    if (idx == map_size)
      idx = 0;
  }
  return -1;
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
  if (wamble_query_resolve_treatment_actions(
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
    double value = wamble_treatment_action_number(action, &ok);
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
  const WambleConfig *cfg = get_config();
  if (!board)
    return SCORING_ERR_INVALID;
  if (!moves || num_moves <= 0)
    return SCORING_NONE;
  if (!cfg || cfg->max_contributors <= 0)
    return SCORING_NONE;

  int max_contributors = cfg->max_contributors;
  int map_size = (max_contributors * 2) + 1;
  PlayerContribution *contributions =
      malloc(sizeof(PlayerContribution) * (size_t)max_contributors);
  int *contrib_map_values = NULL;
  uint8_t *contrib_map_tokens = NULL;
  if (!contributions) {
    return SCORING_ERR_DB;
  }
  if (map_size > 0) {
    contrib_map_values = malloc(sizeof(int) * (size_t)map_size);
    contrib_map_tokens = calloc((size_t)map_size, TOKEN_LENGTH);
  }
  if (!contrib_map_values || !contrib_map_tokens) {
    free(contrib_map_tokens);
    free(contrib_map_values);
    free(contributions);
    return SCORING_ERR_DB;
  }
  for (int i = 0; i < map_size; i++)
    contrib_map_values[i] = -1;

  int num_contributors = 0;
  int total_white_moves = 0;
  int total_black_moves = 0;

  for (int i = 0; i < num_moves; i++) {
    const WambleMove *move = &moves[i];
    int contributor_index = scoring_map_find(
        contrib_map_tokens, contrib_map_values, map_size, move->player_token);

    if (contributor_index == -1 && num_contributors < max_contributors) {
      contributor_index = num_contributors++;
      memcpy(contributions[contributor_index].player_token, move->player_token,
             TOKEN_LENGTH);
      contributions[contributor_index].white_moves = 0;
      contributions[contributor_index].black_moves = 0;
      (void)scoring_map_insert(contrib_map_tokens, contrib_map_values, map_size,
                               move->player_token, contributor_index);
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
    white_pot = cfg->max_pot;
  } else if (board->result == GAME_RESULT_BLACK_WINS) {
    black_pot = cfg->max_pot;
  } else if (board->result == GAME_RESULT_DRAW) {
    white_pot = cfg->max_pot / 2.0;
    black_pot = cfg->max_pot / 2.0;
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

  free(contrib_map_tokens);
  free(contrib_map_values);
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
