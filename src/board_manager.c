#include "../include/wamble/wamble.h"
#include <math.h>
#include <string.h>

static WAMBLE_THREAD_LOCAL WambleBoard *board_pool;
static WAMBLE_THREAD_LOCAL int num_boards = 0;
static WAMBLE_THREAD_LOCAL uint64_t next_board_id = 1;
static WAMBLE_THREAD_LOCAL wamble_mutex_t board_mutex;

#define BOARD_MAP_SIZE (get_config()->max_boards * 2)
static WAMBLE_THREAD_LOCAL int *board_index_map;

static inline uint64_t mix64_hash(uint64_t x) {
  x ^= x >> 33;
  x *= 0xff51afd7ed558ccdULL;
  x ^= x >> 33;
  x *= 0xc4ceb9fe1a85ec53ULL;
  x ^= x >> 33;
  return x;
}

static void board_map_put(uint64_t id, int index) {
  uint64_t h = mix64_hash(id);
  int mask = BOARD_MAP_SIZE - 1;
  int i = (int)(h & (uint64_t)mask);
  for (int probe = 0; probe < BOARD_MAP_SIZE; probe++) {
    if (board_index_map[i] == -1) {
      board_index_map[i] = index;
      return;
    }
    i = (i + 1) & mask;
  }
}

static int board_map_get(uint64_t id) {
  uint64_t h = mix64_hash(id);
  int mask = BOARD_MAP_SIZE - 1;
  int i = (int)(h & (uint64_t)mask);
  for (int probe = 0; probe < BOARD_MAP_SIZE; probe++) {
    int idx = board_index_map[i];
    if (idx == -1)
      return -1;
    if (idx >= 0 && board_pool[idx].id == id)
      return idx;
    i = (i + 1) & mask;
  }
  return -1;
}

void board_manager_tick() {
  db_expire_reservations();
  db_archive_inactive_boards(get_config()->inactivity_timeout);
}

void board_manager_init(void) {
  if (board_pool) {
    free(board_pool);
    free(board_index_map);
    wamble_mutex_destroy(&board_mutex);
  }
  board_pool = malloc(sizeof(WambleBoard) * (size_t)get_config()->max_boards);
  board_index_map =
      malloc(sizeof(int) * (size_t)(get_config()->max_boards * 2));
  memset(board_pool, 0, sizeof(WambleBoard) * (size_t)get_config()->max_boards);
  num_boards = 0;
  next_board_id = 1;
  wamble_mutex_init(&board_mutex);
  rng_init();
  for (int i = 0; i < BOARD_MAP_SIZE; i++)
    board_index_map[i] = -1;

  DbBoardIdList dormant = db_list_boards_by_status("DORMANT");
  int dormant_count = dormant.count;
  for (int i = 0; i < dormant_count && i < get_config()->max_boards; i++) {
    WambleBoard *board = &board_pool[num_boards++];
    board->id = dormant.ids[i];

    DbBoardResult br = db_get_board(board->id);
    if (br.status == DB_OK) {
      strncpy(board->fen, br.fen, FEN_MAX_LENGTH);
      parse_fen_to_bitboard(board->fen, &board->board);
      board->state = BOARD_STATE_DORMANT;
      board->result = GAME_RESULT_IN_PROGRESS;
      board->last_move_time = 0;
      board->creation_time = time(NULL);
      board->last_assignment_time = 0;
      memset(board->reservation_player_token, 0, TOKEN_LENGTH);
      board->reservation_time = 0;
      board->reserved_for_white = false;

      if (board->id >= next_board_id) {
        next_board_id = board->id + 1;
      }
      board_map_put(board->id, i);
    } else {
      num_boards--;
    }
  }

  int boards_to_create = get_config()->min_boards - num_boards;
  if (boards_to_create > 0) {
    for (int i = 0; i < boards_to_create; i++) {
      if (num_boards < get_config()->max_boards) {
        WambleBoard *board = &board_pool[num_boards++];
        strcpy(board->fen,
               "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1");

        board->id = db_create_board(board->fen);
        if (board->id == 0) {
          board->id = next_board_id++;
        } else {
          if (board->id >= next_board_id) {
            next_board_id = board->id + 1;
          }
        }

        board->state = BOARD_STATE_DORMANT;
        board->result = GAME_RESULT_IN_PROGRESS;
        parse_fen_to_bitboard(board->fen, &board->board);
        board->last_move_time = 0;
        board->creation_time = time(NULL);
        board->last_assignment_time = 0;
        memset(board->reservation_player_token, 0, TOKEN_LENGTH);
        board->reservation_time = 0;
        board->reserved_for_white = false;
        board_map_put(board->id, num_boards - 1);
      }
    }
  }
}

WambleBoard *find_board_for_player(WamblePlayer *player) {
  time_t now = time(NULL);

  typedef struct {
    WambleBoard *board;
    double score;
  } ScoredBoard;

  ScoredBoard eligible_boards[get_config()->max_boards];
  int eligible_count = 0;
  double total_score = 0.0;

  for (int i = 0; i < num_boards; i++) {
    WambleBoard *board = &board_pool[i];

    if (board->state != BOARD_STATE_DORMANT &&
        board->state != BOARD_STATE_ACTIVE) {
      continue;
    }

    double score = 1.0;

    GamePhase phase;
    int fullmove_number = board->board.fullmove_number;
    if (fullmove_number < GAME_PHASE_EARLY_THRESHOLD) {
      phase = GAME_PHASE_EARLY;
    } else if (fullmove_number < GAME_PHASE_MID_THRESHOLD) {
      phase = GAME_PHASE_MID;
    } else {
      phase = GAME_PHASE_END;
    }

    if (player->games_played < NEW_PLAYER_GAMES_THRESHOLD) {

      if (phase == GAME_PHASE_EARLY) {
        score *= get_config()->new_player_early_phase_mult;
      } else if (phase == GAME_PHASE_MID) {
        score *= get_config()->new_player_mid_phase_mult;
      } else {
        score *= get_config()->new_player_end_phase_mult;
      }
    } else {

      if (phase == GAME_PHASE_EARLY) {
        score *= get_config()->experienced_player_early_phase_mult;
      } else if (phase == GAME_PHASE_MID) {
        score *= get_config()->experienced_player_mid_phase_mult;
      } else {
        score *= get_config()->experienced_player_end_phase_mult;
      }
    }

    score *= 1.0 / ((double)(now - board->last_assignment_time) + 1.0);

    eligible_boards[eligible_count].board = board;
    eligible_boards[eligible_count].score = score;
    total_score += score;
    eligible_count++;
  }

  WambleBoard *selected_board = NULL;

  if (eligible_count > 0 && total_score > 0) {
    double random_value = rng_double() * total_score;
    for (int i = 0; i < eligible_count; i++) {
      random_value -= eligible_boards[i].score;
      if (random_value <= 0) {
        selected_board = eligible_boards[i].board;
        break;
      }
    }
  }

  if (selected_board) {
    selected_board->state = BOARD_STATE_RESERVED;
    selected_board->reservation_time = now;
    selected_board->last_assignment_time = now;
    memcpy(selected_board->reservation_player_token, player->token,
           TOKEN_LENGTH);
    selected_board->reserved_for_white = (selected_board->board.turn == 'w');

    db_async_update_board(selected_board->id, selected_board->fen, "RESERVED");
    uint64_t session_id = db_get_session_by_token(player->token);
    if (session_id > 0) {
      db_async_create_reservation(selected_board->id, session_id,
                                  get_config()->reservation_timeout);
    }

    return selected_board;
  }

  int longest_game = db_get_longest_game_moves();
  int players = db_get_active_session_count();
  int target_boards = longest_game * players;
  if (target_boards < get_config()->min_boards) {
    target_boards = get_config()->min_boards;
  }

  if (num_boards < target_boards && num_boards < get_config()->max_boards) {
    WambleBoard *board = &board_pool[num_boards++];
    strcpy(board->fen,
           "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1");

    board->id = db_create_board(board->fen);
    if (board->id == 0) {
      board->id = next_board_id++;
    } else {
      next_board_id = board->id + 1;
    }

    board->state = BOARD_STATE_RESERVED;
    board->result = GAME_RESULT_IN_PROGRESS;
    parse_fen_to_bitboard(board->fen, &board->board);
    board->last_move_time = now;
    board->creation_time = now;
    board->last_assignment_time = now;
    memcpy(board->reservation_player_token, player->token, TOKEN_LENGTH);
    board->reserved_for_white = (board->board.turn == 'w');
    board->reservation_time = now;
    board_map_put(board->id, num_boards - 1);

    db_async_update_board(board->id, board->fen, "RESERVED");
    uint64_t session_id = db_get_session_by_token(player->token);
    if (session_id > 0) {
      db_async_create_reservation(board->id, session_id,
                                  get_config()->reservation_timeout);
    }

    return board;
  }

  return NULL;
}

void release_board(uint64_t board_id) {
  wamble_mutex_lock(&board_mutex);

  for (int i = 0; i < num_boards; i++) {
    if (board_pool[i].id == board_id) {
      board_pool[i].state = BOARD_STATE_ACTIVE;
      board_pool[i].last_move_time = time(NULL);
      memset(board_pool[i].reservation_player_token, 0, TOKEN_LENGTH);
      board_pool[i].reservation_time = 0;
      board_pool[i].reserved_for_white = false;

      db_async_update_board(board_id, board_pool[i].fen, "ACTIVE");
      db_async_remove_reservation(board_id);
      break;
    }
  }

  wamble_mutex_unlock(&board_mutex);
}

void archive_board(uint64_t board_id) {
  wamble_mutex_lock(&board_mutex);

  for (int i = 0; i < num_boards; i++) {
    if (board_pool[i].id == board_id) {
      board_pool[i].state = BOARD_STATE_ARCHIVED;

      db_async_update_board(board_id, board_pool[i].fen, "ARCHIVED");

      char winning_side = 'd';
      if (board_pool[i].result == GAME_RESULT_WHITE_WINS) {
        winning_side = 'w';
      } else if (board_pool[i].result == GAME_RESULT_BLACK_WINS) {
        winning_side = 'b';
      }
      db_async_record_game_result(board_id, winning_side);
      break;
    }
  }

  wamble_mutex_unlock(&board_mutex);
}

void update_player_ratings(WambleBoard *board) {
  DbMovesResult mres = db_get_moves_for_board(board->id);
  const WambleMove *moves = mres.rows;
  int num_moves = mres.count;

  WamblePlayer *white_player = NULL;
  WamblePlayer *black_player = NULL;

  for (int i = 0; i < num_moves; i++) {
    if (moves[i].is_white_move) {
      if (!white_player) {
        white_player = get_player_by_token(moves[i].player_token);
      }
    } else {
      if (!black_player) {
        black_player = get_player_by_token(moves[i].player_token);
      }
    }
    if (white_player && black_player) {
      break;
    }
  }

  double white_rating =
      white_player ? white_player->score : get_config()->default_rating;
  double black_rating =
      black_player ? black_player->score : get_config()->default_rating;

  double expected_white =
      1.0 / (1.0 + pow(10.0, (black_rating - white_rating) / 400.0));
  double expected_black =
      1.0 / (1.0 + pow(10.0, (white_rating - black_rating) / 400.0));

  double actual_white, actual_black;

  if (board->result == GAME_RESULT_WHITE_WINS) {
    actual_white = 1.0;
    actual_black = 0.0;
  } else if (board->result == GAME_RESULT_BLACK_WINS) {
    actual_white = 0.0;
    actual_black = 1.0;
  } else {
    actual_white = 0.5;
    actual_black = 0.5;
  }

  if (white_player) {
    white_player->score +=
        get_config()->k_factor * (actual_white - expected_white);
    white_player->games_played++;
  }
  if (black_player) {
    black_player->score +=
        get_config()->k_factor * (actual_black - expected_black);
    black_player->games_played++;
  }
}

WambleBoard *get_board_by_id(uint64_t board_id) {
  wamble_mutex_lock(&board_mutex);
  int idx = board_map_get(board_id);
  if (idx >= 0) {
    WambleBoard *b = &board_pool[idx];
    wamble_mutex_unlock(&board_mutex);
    return b;
  }
  wamble_mutex_unlock(&board_mutex);
  return NULL;
}
