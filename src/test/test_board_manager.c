#ifdef TEST_BOARD_MANAGER

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "../include/wamble/wamble.h"
#include "../board_manager.c"
#include "../move_engine.c"


typedef struct {
  const char *name;
  bool (*run)(void);
} TestCase;

static void reset_board_manager() { board_manager_init(); }

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
  WambleBoard *board1 = get_or_create_board();
  if (!board1 || board1->state != BOARD_STATE_RESERVED)
    return false;

  WambleBoard *board2 = get_or_create_board();
  if (!board2 || board2->state != BOARD_STATE_RESERVED)
    return false;

  if (board1->id == board2->id)
    return false;

  return num_boards == MIN_BOARDS;
}

static bool test_no_new_board_if_at_min_capacity() {
  reset_board_manager();
  for (int i = 0; i < MIN_BOARDS; i++) {
    WambleBoard *b = get_or_create_board();
    if (!b || b->state != BOARD_STATE_RESERVED)
      return false;
  }

  WambleBoard *new_board = get_or_create_board();

  return new_board == NULL && num_boards == MIN_BOARDS;
}

static bool test_release_board_makes_it_active() {
  reset_board_manager();
  WambleBoard *board = get_or_create_board();
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
  WambleBoard *board = get_or_create_board();
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
  board_pool[0].state = BOARD_STATE_ACTIVE;
  board_pool[0].board.fullmove_number = 50;

  for (int i = 1; i < MIN_BOARDS; i++) {
    board_pool[i].state = BOARD_STATE_RESERVED;
  }

  WambleBoard *new_board = get_or_create_board();
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
  WambleBoard *board = get_or_create_board();
  if (!board)
    return false;

  board->reservation_time = time(NULL) - (RESERVATION_TIMEOUT + 1);

  board_manager_tick();

  return board->state == BOARD_STATE_DORMANT;
}

static bool test_inactivity_timeout() {
  reset_board_manager();
  WambleBoard *board = get_or_create_board();
  if (!board)
    return false;

  release_board(board->id);

  board->last_move_time = time(NULL) - (INACTIVITY_TIMEOUT + 1);

  board_manager_tick();

  return board->state == BOARD_STATE_DORMANT;
}

static const TestCase cases[] = {
    {"initialization", test_initialization},
    {"get board reuses dormant", test_get_board_reuses_dormant},
    {"no new board at min capacity", test_no_new_board_if_at_min_capacity},
    {"release board makes it active", test_release_board_makes_it_active},
    {"archive board works", test_archive_board_works},
    {"board creation when scaling up", test_board_creation_when_scaling_up},
    {"reservation expiry", test_reservation_expiry},
    {"inactivity timeout", test_inactivity_timeout},
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