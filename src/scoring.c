#include "../include/wamble/wamble.h"
#include <string.h>

typedef struct {
  uint8_t player_token[TOKEN_LENGTH];
  int white_moves;
  int black_moves;
} PlayerContribution;

WambleBoard *get_board_by_id(uint64_t board_id);

void calculate_and_distribute_pot(uint64_t board_id) {
  LOG_INFO("Calculating and distributing pot for board %lu", board_id);
  WambleBoard *board = get_board_by_id(board_id);
  if (!board) {
    LOG_WARN("Board %lu not found for pot distribution", board_id);
    return;
  }
  if (board->result == GAME_RESULT_IN_PROGRESS) {
    LOG_WARN("Game on board %lu is still in progress, cannot distribute pot",
             board_id);
    return;
  }

  WambleMove *moves =
      malloc(sizeof(WambleMove) * get_config()->max_moves_per_board);
  int num_moves = db_get_moves_for_board(board_id, moves,
                                         get_config()->max_moves_per_board);
  if (num_moves <= 0) {
    LOG_WARN("No moves found for board %lu, cannot distribute pot", board_id);
    free(moves);
    return;
  }

  PlayerContribution *contributions =
      malloc(sizeof(PlayerContribution) * get_config()->max_contributors);
  int num_contributors = 0;
  int total_white_moves = 0;
  int total_black_moves = 0;

  for (int i = 0; i < num_moves; i++) {
    WambleMove *move = &moves[i];
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
  LOG_DEBUG("Found %d contributors for board %lu", num_contributors, board_id);

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
  LOG_DEBUG("Board %lu result: %d, white_pot: %.2f, black_pot: %.2f", board_id,
            board->result, white_pot, black_pot);

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

    uint64_t session_id = db_get_session_by_token(contrib->player_token);
    if (session_id > 0 && score > 0.0) {
      db_async_record_payout(board_id, session_id, score);
    }

    WamblePlayer *player = get_player_by_token(contrib->player_token);
    if (player) {
      player->score += score;
    }
    char token_str[TOKEN_LENGTH * 2 + 1];
    format_token_for_url(contrib->player_token, token_str);
    LOG_INFO("Player %s awarded %.2f points for board %lu", token_str, score,
             board_id);
  }
  LOG_INFO("Finished distributing pot for board %lu", board_id);

  free(moves);
  free(contributions);
}
