#include "../include/wamble/wamble.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
  uint8_t player_token[TOKEN_LENGTH];
  int white_moves;
  int black_moves;
} PlayerContribution;

WambleBoard *get_board_by_id(uint64_t board_id);

static int tokens_equal(const uint8_t *token1, const uint8_t *token2) {
  for (int i = 0; i < TOKEN_LENGTH; i++) {
    if (token1[i] != token2[i]) {
      return 0;
    }
  }
  return 1;
}

void calculate_and_distribute_pot(uint64_t board_id) {
  WambleBoard *board = get_board_by_id(board_id);
  if (!board || board->result == GAME_RESULT_IN_PROGRESS) {
    return;
  }

  static WambleMove moves[MAX_MOVES_PER_BOARD];
  int num_moves = db_get_moves_for_board(board_id, moves, MAX_MOVES_PER_BOARD);
  if (num_moves <= 0) {
    return;
  }

  PlayerContribution contributions[MAX_CONTRIBUTORS];
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

    if (contributor_index == -1 && num_contributors < MAX_CONTRIBUTORS) {
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
    white_pot = MAX_POT;
  } else if (board->result == GAME_RESULT_BLACK_WINS) {
    black_pot = MAX_POT;
  } else if (board->result == GAME_RESULT_DRAW) {
    white_pot = MAX_POT / 2.0;
    black_pot = MAX_POT / 2.0;
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

    uint64_t session_id = db_get_session_by_token(contrib->player_token);
    if (session_id > 0 && score > 0.0) {
      db_record_payout(board_id, session_id, score);
    }

    WamblePlayer *player = get_player_by_token(contrib->player_token);
    if (player) {
      player->score += score;
    }
  }
}
