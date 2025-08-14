#include "../include/wamble/wamble.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_BOARDS 1024
#define MIN_BOARDS 4
#define INACTIVITY_TIMEOUT 300
#define RESERVATION_TIMEOUT 2

static WambleBoard board_pool[MAX_BOARDS];
static int num_boards = 0;
static uint64_t next_board_id = 1;
static pthread_t board_manager_thread;

static inline int get_player_count() { return 2; }

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
  time_t now = time(NULL);
  for (int i = 0; i < num_boards; i++) {
    WambleBoard *board = &board_pool[i];

    if (board->state == BOARD_STATE_RESERVED &&
        (now - board->reservation_time) > RESERVATION_TIMEOUT) {
      board->state = BOARD_STATE_DORMANT;
      board->reservation_player_id = 0;
      board->reservation_time = 0;
    }

    if (board->state == BOARD_STATE_ACTIVE &&
        (now - board->last_move_time) > INACTIVITY_TIMEOUT) {
      board->state = BOARD_STATE_DORMANT;
    }
  }
}

static inline int get_longest_game_moves(void) {
  int max_moves = 0;
  for (int i = 0; i < num_boards; i++) {
    if (board_pool[i].state == BOARD_STATE_ACTIVE) {
      if (board_pool[i].board.fullmove_number > max_moves) {
        max_moves = board_pool[i].board.fullmove_number;
      }
    }
  }
  return max_moves;
}

void board_manager_init(void) {
  memset(board_pool, 0, sizeof(board_pool));
  num_boards = 0;
  next_board_id = 1;

  for (int i = 0; i < MIN_BOARDS; i++) {
    if (num_boards < MAX_BOARDS) {
      WambleBoard *board = &board_pool[num_boards++];
      board->id = next_board_id++;
      board->state = BOARD_STATE_DORMANT;
      board->result = GAME_RESULT_IN_PROGRESS;
      strcpy(board->fen,
             "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1");
      parse_fen_to_bitboard(board->fen, &board->board);
      board->last_move_time = 0;
      board->reservation_player_id = 0;
      board->reservation_time = 0;
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

WambleBoard *get_or_create_board(void) {
  for (int i = 0; i < num_boards; i++) {
    if (board_pool[i].state == BOARD_STATE_DORMANT) {
      board_pool[i].state = BOARD_STATE_RESERVED;
      board_pool[i].reservation_time = time(NULL);
      return &board_pool[i];
    }
  }

  int longest_game = get_longest_game_moves();
  int players = get_player_count();
  int target_boards = longest_game * players;
  if (target_boards < MIN_BOARDS) {
    target_boards = MIN_BOARDS;
  }

  if (num_boards < target_boards && num_boards < MAX_BOARDS) {
    WambleBoard *board = &board_pool[num_boards++];
    board->id = next_board_id++;
    board->state = BOARD_STATE_RESERVED;
    board->result = GAME_RESULT_IN_PROGRESS;
    strcpy(board->fen,
           "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1");
    parse_fen_to_bitboard(board->fen, &board->board);
    board->last_move_time = time(NULL);
    board->reservation_time = time(NULL);
    return board;
  }

  return NULL;
}

void release_board(uint64_t board_id) {
  for (int i = 0; i < num_boards; i++) {
    if (board_pool[i].id == board_id) {
      board_pool[i].state = BOARD_STATE_ACTIVE;
      board_pool[i].last_move_time = time(NULL);
      board_pool[i].reservation_player_id = 0;
      board_pool[i].reservation_time = 0;
      break;
    }
  }
}

void archive_board(uint64_t board_id) {
  for (int i = 0; i < num_boards; i++) {
    if (board_pool[i].id == board_id) {
      board_pool[i].state = BOARD_STATE_ARCHIVED;
      break;
    }
  }
}