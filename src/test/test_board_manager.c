#ifdef TEST_BOARD_MANAGER

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "../../include/wamble/wamble.h"
#include "../board_manager.c"
#include "../move_engine.c"

static WamblePlayer *white_player_mock;
static WamblePlayer *black_player_mock;

WamblePlayer *get_player_by_token(const uint8_t *token) {
  if (token[0] == 2)
    return white_player_mock;
  if (token[0] == 3)
    return black_player_mock;
  return NULL;
}

int get_moves_for_board(uint64_t board_id, WambleMove **moves_ptr) {
  WambleMove *moves = malloc(sizeof(WambleMove) * 2);

  moves[0].id = 1;
  moves[0].board_id = 1;
  memset(moves[0].player_token, 0, TOKEN_LENGTH);
  moves[0].player_token[0] = 2;
  strcpy(moves[0].uci_move, "e2e4");
  moves[0].timestamp = 0;
  moves[0].is_white_move = true;

  moves[1].id = 2;
  moves[1].board_id = 1;
  memset(moves[1].player_token, 0, TOKEN_LENGTH);
  moves[1].player_token[0] = 3;
  strcpy(moves[1].uci_move, "e7e5");
  moves[1].timestamp = 0;
  moves[1].is_white_move = false;

  *moves_ptr = moves;
  return 2;
}

typedef struct {
  const char *name;
  bool (*run)(void);
} TestCase;

static WamblePlayer test_player;

static void reset_board_manager() {
  board_manager_init();
  memset(test_player.token, 0, TOKEN_LENGTH);
  test_player.token[0] = 1;
  test_player.score = 1200;
  test_player.games_played = 0;
  test_player.has_persistent_identity = false;
  test_player.last_seen_time = 0;
}

static bool test_get_game_phase() {
  WambleBoard board;

  board.board.fullmove_number = GAME_PHASE_EARLY_THRESHOLD - 1;
  if (get_game_phase(&board) != GAME_PHASE_EARLY)
    return false;

  board.board.fullmove_number = GAME_PHASE_EARLY_THRESHOLD;
  if (get_game_phase(&board) != GAME_PHASE_MID)
    return false;

  board.board.fullmove_number = GAME_PHASE_EARLY_THRESHOLD + 1;
  if (get_game_phase(&board) != GAME_PHASE_MID)
    return false;

  board.board.fullmove_number = GAME_PHASE_MID_THRESHOLD;
  if (get_game_phase(&board) != GAME_PHASE_END)
    return false;

  board.board.fullmove_number = GAME_PHASE_MID_THRESHOLD + 1;
  if (get_game_phase(&board) != GAME_PHASE_END)
    return false;

  return true;
}

static bool test_get_longest_game_moves() {
  reset_board_manager();
  board_pool[0].board.fullmove_number = 10;
  board_pool[1].board.fullmove_number = 50;
  board_pool[2].board.fullmove_number = 20;
  board_pool[3].board.fullmove_number = 5;

  int longest_moves = get_longest_game_moves();
  return longest_moves == 50;
}

static bool test_initialization() {
  reset_board_manager();
  if (num_boards != MIN_BOARDS)
    return false;

  for (int i = 0; i < MIN_BOARDS; i++) {
    if (board_pool[i].state != BOARD_STATE_DORMANT)
      return false;
    if (board_pool[i].id == 0)
      return false;
  }
  return true;
}

static bool test_get_board_reuses_dormant() {
  reset_board_manager();
  WambleBoard *board1 = find_board_for_player(&test_player);
  if (!board1 || board1->state != BOARD_STATE_RESERVED)
    return false;

  WambleBoard *board2 = find_board_for_player(&test_player);
  if (!board2 || board2->state != BOARD_STATE_RESERVED)
    return false;

  if (board1->id == board2->id)
    return false;

  return num_boards == MIN_BOARDS;
}

static bool test_no_new_board_if_at_min_capacity() {
  reset_board_manager();
  for (int i = 0; i < MIN_BOARDS; i++) {
    WambleBoard *b = find_board_for_player(&test_player);
    if (!b || b->state != BOARD_STATE_RESERVED)
      return false;
  }

  WambleBoard *new_board = find_board_for_player(&test_player);

  return new_board == NULL && num_boards == MIN_BOARDS;
}

static bool test_release_board_makes_it_active() {
  reset_board_manager();
  WambleBoard *board = find_board_for_player(&test_player);
  if (!board)
    return false;

  uint64_t id = board->id;
  release_board(id);

  if (board->state != BOARD_STATE_ACTIVE)
    return false;

  return true;
}

static bool test_archive_board_works() {
  reset_board_manager();
  WambleBoard *board = find_board_for_player(&test_player);
  if (!board)
    return false;

  uint64_t id = board->id;
  archive_board(id);

  if (board->state != BOARD_STATE_ARCHIVED)
    return false;

  return true;
}

static bool test_board_creation_when_scaling_up() {
  reset_board_manager();
  board_pool[0].board.fullmove_number = 50;

  for (int i = 0; i < MIN_BOARDS; i++) {
    board_pool[i].state = BOARD_STATE_RESERVED;
  }

  WambleBoard *new_board = find_board_for_player(&test_player);
  if (!new_board)
    return false;

  if (num_boards != MIN_BOARDS + 1)
    return false;
  if (new_board->state != BOARD_STATE_RESERVED)
    return false;

  return true;
}

static bool test_reservation_expiry() {
  reset_board_manager();
  WambleBoard *board = find_board_for_player(&test_player);
  if (!board)
    return false;

  board->reservation_time = time(NULL) - (RESERVATION_TIMEOUT + 1);

  board_manager_tick();

  return board->state == BOARD_STATE_DORMANT;
}

static bool test_inactivity_timeout() {
  reset_board_manager();
  WambleBoard *board = find_board_for_player(&test_player);
  if (!board)
    return false;

  release_board(board->id);

  board->last_move_time = time(NULL) - (INACTIVITY_TIMEOUT + 1);

  board_manager_tick();

  return board->state == BOARD_STATE_DORMANT;
}

static bool test_new_player_gets_new_board() {
  reset_board_manager();

  board_pool[0].board.fullmove_number = GAME_PHASE_EARLY_THRESHOLD - 1;
  board_pool[1].board.fullmove_number = GAME_PHASE_EARLY_THRESHOLD - 1;
  board_pool[2].board.fullmove_number = GAME_PHASE_EARLY_THRESHOLD - 1;
  board_pool[3].board.fullmove_number = GAME_PHASE_MID_THRESHOLD + 1;

  test_player.games_played = 1;

  int early_game_selections = 0;
  int total_attempts = 20;

  for (int i = 0; i < total_attempts; i++) {

    for (int j = 0; j < MIN_BOARDS; j++) {
      board_pool[j].state = BOARD_STATE_DORMANT;
      memset(board_pool[j].reservation_player_token, 0, TOKEN_LENGTH);
      board_pool[j].reservation_time = 0;
    }

    WambleBoard *board = find_board_for_player(&test_player);
    if (board && get_game_phase(board) == GAME_PHASE_EARLY) {
      early_game_selections++;
    }

    if (board) {
      board->state = BOARD_STATE_DORMANT;
      memset(board->reservation_player_token, 0, TOKEN_LENGTH);
      board->reservation_time = 0;
    }
  }

  return early_game_selections > total_attempts * 0.7;
}

static bool test_experienced_player_gets_old_board() {
  reset_board_manager();

  board_pool[0].board.fullmove_number = GAME_PHASE_EARLY_THRESHOLD - 1;
  board_pool[1].board.fullmove_number = GAME_PHASE_MID_THRESHOLD + 1;
  board_pool[2].board.fullmove_number = GAME_PHASE_MID_THRESHOLD + 1;
  board_pool[3].board.fullmove_number = GAME_PHASE_MID_THRESHOLD + 1;

  test_player.games_played = 20;

  int end_game_selections = 0;
  int total_attempts = 20;

  for (int i = 0; i < total_attempts; i++) {

    for (int j = 0; j < MIN_BOARDS; j++) {
      board_pool[j].state = BOARD_STATE_DORMANT;
      memset(board_pool[j].reservation_player_token, 0, TOKEN_LENGTH);
      board_pool[j].reservation_time = 0;
    }

    WambleBoard *board = find_board_for_player(&test_player);
    if (board && get_game_phase(board) == GAME_PHASE_END) {
      end_game_selections++;
    }

    if (board) {
      board->state = BOARD_STATE_DORMANT;
      memset(board->reservation_player_token, 0, TOKEN_LENGTH);
      board->reservation_time = 0;
    }
  }

  return end_game_selections > total_attempts * 0.7;
}

static bool test_rating_update_white_wins() {
  WamblePlayer white_player = {{0}, {0}, false, 0, 1200, 0};
  WamblePlayer black_player = {{0}, {0}, false, 0, 1200, 0};

  white_player.token[0] = 2;
  black_player.token[0] = 3;

  white_player_mock = &white_player;
  black_player_mock = &black_player;

  WambleBoard board;
  board.id = 1;
  board.result = GAME_RESULT_WHITE_WINS;

  update_player_ratings(&board);

  return white_player.score > 1200 && black_player.score < 1200;
}

static const TestCase cases[] = {
    {"get game phase", test_get_game_phase},
    {"get longest game moves", test_get_longest_game_moves},
    {"initialization", test_initialization},
    {"get board reuses dormant", test_get_board_reuses_dormant},
    {"no new board at min capacity", test_no_new_board_if_at_min_capacity},
    {"release board makes it active", test_release_board_makes_it_active},
    {"archive board works", test_archive_board_works},
    {"board creation when scaling up", test_board_creation_when_scaling_up},
    {"reservation expiry", test_reservation_expiry},
    {"inactivity timeout", test_inactivity_timeout},
    {"new player gets new board", test_new_player_gets_new_board},
    {"experienced player gets old board",
     test_experienced_player_gets_old_board},
    {"rating update white wins", test_rating_update_white_wins},
};

static int run_case(const TestCase *c) {
  if (c->run()) {
    return 1;
  }
  return 0;
}

int main(int argc, char **argv) {
  const char *filter = (argc > 1 ? argv[1] : "");
  int pass = 0, total = 0;

  for (size_t i = 0; i < (sizeof(cases) / sizeof((cases)[0])); ++i) {
    if (*filter && !strstr(cases[i].name, filter))
      continue;

    total++;
    if (run_case(&cases[i])) {
      printf("%s PASSED\n", cases[i].name);
      pass++;
    } else {
      printf("%s FAILED\n", cases[i].name);
    }
  }
  printf("%d/%d passed\n", pass, total);
  return (pass == total) ? 0 : 1;
}

#endif
