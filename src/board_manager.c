#include "../include/wamble/wamble.h"
#include <math.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static WambleBoard board_pool[MAX_BOARDS];
static int num_boards = 0;
static uint64_t next_board_id = 1;
static pthread_t board_manager_thread;
static pthread_mutex_t board_mutex = PTHREAD_MUTEX_INITIALIZER;

static inline int get_player_count() { return db_get_active_session_count(); }

void board_manager_tick();

static void *board_manager_thread_main(void *arg) {
  (void)arg;
  while (1) {
    board_manager_tick();
    sleep(1);
  }
  return NULL;
}

void board_manager_tick() {
  db_expire_reservations();
  db_archive_inactive_boards(INACTIVITY_TIMEOUT);
}

static inline int get_longest_game_moves(void) {
  return db_get_longest_game_moves();
}

void board_manager_init(void) {
  memset(board_pool, 0, sizeof(board_pool));
  num_boards = 0;
  next_board_id = 1;
  srand(time(NULL));

  uint64_t board_ids[MAX_BOARDS];
  int dormant_count = db_get_boards_by_status("DORMANT", board_ids, MAX_BOARDS);

  for (int i = 0; i < dormant_count && i < MAX_BOARDS; i++) {
    WambleBoard *board = &board_pool[num_boards++];
    board->id = board_ids[i];

    char status[17];
    if (db_get_board(board->id, board->fen, status) == 0) {
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
    }
  }

  for (int i = num_boards; i < MIN_BOARDS; i++) {
    if (num_boards < MAX_BOARDS) {
      WambleBoard *board = &board_pool[num_boards++];
      strcpy(board->fen,
             "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1");

      board->id = db_create_board(board->fen);
      if (board->id == 0) {

        board->id = next_board_id++;
      } else {
        next_board_id = board->id + 1;
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
    }
  }
}

int start_board_manager_thread(void) {
  if (pthread_create(&board_manager_thread, NULL, board_manager_thread_main,
                     NULL)) {
    return -1;
  }
  pthread_detach(board_manager_thread);
  return 0;
}

WambleBoard *find_board_for_player(WamblePlayer *player) {
  time_t now = time(NULL);

  typedef struct {
    WambleBoard *board;
    double score;
  } ScoredBoard;

  ScoredBoard eligible_boards[MAX_BOARDS];
  int eligible_count = 0;
  double total_score = 0.0;

  for (int i = 0; i < num_boards; i++) {
    WambleBoard *board = &board_pool[i];

    if (board->state != BOARD_STATE_DORMANT &&
        board->state != BOARD_STATE_ACTIVE) {
      continue;
    }

    double score = 1.0;

    GamePhase phase = get_game_phase(board);
    if (player->games_played < NEW_PLAYER_GAMES_THRESHOLD) {

      if (phase == GAME_PHASE_EARLY) {
        score *= 2.0;
      } else if (phase == GAME_PHASE_MID) {
        score *= 1.0;
      } else {
        score *= 0.5;
      }
    } else {

      if (phase == GAME_PHASE_EARLY) {
        score *= 0.5;
      } else if (phase == GAME_PHASE_MID) {
        score *= 1.0;
      } else {
        score *= 2.0;
      }
    }

    score *= 1.0 / (now - board->last_assignment_time + 1);

    eligible_boards[eligible_count].board = board;
    eligible_boards[eligible_count].score = score;
    total_score += score;
    eligible_count++;
  }

  WambleBoard *selected_board = NULL;

  if (eligible_count > 0 && total_score > 0) {
    double random_value = (double)rand() / RAND_MAX * total_score;
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

    db_update_board(selected_board->id, selected_board->fen, "RESERVED");
    uint64_t session_id = db_get_session_by_token(player->token);
    if (session_id > 0) {
      db_create_reservation(selected_board->id, session_id,
                            RESERVATION_TIMEOUT);
    }

    return selected_board;
  }

  int longest_game = get_longest_game_moves();
  int players = get_player_count();
  int target_boards = longest_game * players;
  if (target_boards < MIN_BOARDS) {
    target_boards = MIN_BOARDS;
  }

  if (num_boards < target_boards && num_boards < MAX_BOARDS) {
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

    db_update_board(board->id, board->fen, "RESERVED");
    uint64_t session_id = db_get_session_by_token(player->token);
    if (session_id > 0) {
      db_create_reservation(board->id, session_id, RESERVATION_TIMEOUT);
    }

    return board;
  }

  return NULL;
}

void release_board(uint64_t board_id) {
  pthread_mutex_lock(&board_mutex);

  for (int i = 0; i < num_boards; i++) {
    if (board_pool[i].id == board_id) {
      board_pool[i].state = BOARD_STATE_ACTIVE;
      board_pool[i].last_move_time = time(NULL);
      memset(board_pool[i].reservation_player_token, 0, TOKEN_LENGTH);
      board_pool[i].reservation_time = 0;
      board_pool[i].reserved_for_white = false;

      db_update_board(board_id, board_pool[i].fen, "ACTIVE");
      db_remove_reservation(board_id);
      break;
    }
  }

  pthread_mutex_unlock(&board_mutex);
}

void archive_board(uint64_t board_id) {
  pthread_mutex_lock(&board_mutex);

  for (int i = 0; i < num_boards; i++) {
    if (board_pool[i].id == board_id) {
      board_pool[i].state = BOARD_STATE_ARCHIVED;

      db_update_board(board_id, board_pool[i].fen, "ARCHIVED");

      char winning_side = 'd';
      if (board_pool[i].result == GAME_RESULT_WHITE_WINS) {
        winning_side = 'w';
      } else if (board_pool[i].result == GAME_RESULT_BLACK_WINS) {
        winning_side = 'b';
      }
      db_record_game_result(board_id, winning_side);

      break;
    }
  }

  pthread_mutex_unlock(&board_mutex);
}

void update_player_ratings(WambleBoard *board) {
  WambleMove *moves;
  int num_moves = get_moves_for_board(board->id, &moves);

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

  double white_rating = white_player ? white_player->score : DEFAULT_RATING;
  double black_rating = black_player ? black_player->score : DEFAULT_RATING;

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
    white_player->score += K_FACTOR * (actual_white - expected_white);
    white_player->games_played++;
  }
  if (black_player) {
    black_player->score += K_FACTOR * (actual_black - expected_black);
    black_player->games_played++;
  }

  free(moves);
}

GamePhase get_game_phase(WambleBoard *board) {
  int fullmove_number = board->board.fullmove_number;
  if (fullmove_number < GAME_PHASE_EARLY_THRESHOLD) {
    return GAME_PHASE_EARLY;
  } else if (fullmove_number < GAME_PHASE_MID_THRESHOLD) {
    return GAME_PHASE_MID;
  } else {
    return GAME_PHASE_END;
  }
}

WamblePlayer *get_player_by_id(uint64_t player_id) {
  (void)player_id;

  return NULL;
}

WambleBoard *get_board_by_id(uint64_t board_id) {
  pthread_mutex_lock(&board_mutex);

  for (int i = 0; i < num_boards; i++) {
    if (board_pool[i].id == board_id) {
      pthread_mutex_unlock(&board_mutex);
      return &board_pool[i];
    }
  }

  pthread_mutex_unlock(&board_mutex);
  return NULL;
}

int get_moves_for_board(uint64_t board_id, WambleMove **moves) {
  static WambleMove move_buffer[1000];
  int count = db_get_moves_for_board(board_id, move_buffer, 1000);
  if (count <= 0) {
    *moves = NULL;
    return count;
  }

  *moves = malloc(count * sizeof(WambleMove));
  if (!*moves) {
    return -1;
  }

  memcpy(*moves, move_buffer, count * sizeof(WambleMove));
  return count;
}
