
#ifdef TEST_BOARD_MANAGER

#include <assert.h>
#include <string.h>
#include <time.h>

#include "../../include/wamble/wamble.h"

#define MIN_BOARDS 4
#define INACTIVITY_TIMEOUT 300
#define RESERVATION_TIMEOUT 2

void calculate_and_distribute_pot(uint64_t board_id) { (void)board_id; }

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

typedef enum {
  ACTION_INIT,
  ACTION_FIND_BOARD,
  ACTION_RELEASE_BOARD,
  ACTION_ARCHIVE_BOARD,
  ACTION_TICK,
  ACTION_UPDATE_RATINGS
} TestCaseAction;

typedef struct {
  const char *name;
  TestCaseAction action;
  int player_games_played;
  uint64_t board_id_arg;
  int time_travel_seconds;
  BoardState expected_board_state;
  GameResult expected_game_result;
  bool expect_board_found;
  double expected_white_rating;
  double expected_black_rating;
} TestCase;

static WamblePlayer test_player;

static void setup_test_player(int games_played) {
  memset(&test_player, 0, sizeof(WamblePlayer));
  test_player.token[0] = 1;
  test_player.score = 1200;
  test_player.games_played = games_played;
}

static void reset_mocks() { board_manager_init(); }

static bool run_case(const TestCase *c) {
  WambleBoard *board = NULL;

  switch (c->action) {
  case ACTION_INIT: {
    WambleBoard *b = find_board_for_player(&test_player);
    return b != NULL;
  }
  case ACTION_FIND_BOARD:
    setup_test_player(c->player_games_played);
    board = find_board_for_player(&test_player);
    if ((board != NULL) != c->expect_board_found)
      return false;
    if (board && board->state != c->expected_board_state)
      return false;
    break;
  case ACTION_RELEASE_BOARD: {
    WambleBoard *target = NULL;
    for (uint64_t id = 1; id < 1000; ++id) {
      WambleBoard *b = get_board_by_id(id);
      if (b && b->state == BOARD_STATE_RESERVED) {
        target = b;
        break;
      }
    }
    if (!target)
      return false;
    release_board(target->id);
    board = get_board_by_id(target->id);
    return board && board->state == c->expected_board_state;
  }
  case ACTION_ARCHIVE_BOARD: {
    WambleBoard *target = NULL;
    for (uint64_t id = 1; id < 1000; ++id) {
      WambleBoard *b = get_board_by_id(id);
      if (b && b->state != BOARD_STATE_ARCHIVED) {
        target = b;
        break;
      }
    }
    if (!target)
      return false;
    archive_board(target->id);
    board = get_board_by_id(target->id);
    return board && board->state == c->expected_board_state;
  }
  case ACTION_TICK: {
    WambleBoard *target = NULL;
    for (uint64_t id = 1; id < 1000; ++id) {
      WambleBoard *b = get_board_by_id(id);
      if (b && (b->state == BOARD_STATE_RESERVED ||
                b->state == BOARD_STATE_ACTIVE)) {
        target = b;
        break;
      }
    }
    if (!target)
      return false;
    if (c->expected_board_state == BOARD_STATE_DORMANT &&
        target->state == BOARD_STATE_RESERVED) {
      target->reservation_time -= c->time_travel_seconds;
    } else if (c->expected_board_state == BOARD_STATE_DORMANT &&
               target->state == BOARD_STATE_ACTIVE) {
      target->last_move_time -= c->time_travel_seconds;
    }
    board_manager_tick();
    board = get_board_by_id(target->id);
    return board && board->state == c->expected_board_state;
  }
  case ACTION_UPDATE_RATINGS: {
    WamblePlayer white = {.token = {2}, .score = 1200, .games_played = 0};
    WamblePlayer black = {.token = {3}, .score = 1200, .games_played = 0};
    white_player_mock = &white;
    black_player_mock = &black;
    WambleBoard b = {.id = 1, .result = c->expected_game_result};
    update_player_ratings(&b);
    return white.score == c->expected_white_rating &&
           black.score == c->expected_black_rating;
  }
  }
  return true;
}

int main(int argc, char **argv) {
  config_load(NULL, NULL, NULL, 0);
  const char *filter = (argc > 1 ? argv[1] : "");
  int pass = 0, total = 0;

  TestCase cases[] = {
      {"initialization", ACTION_INIT, 0, 0, 0, 0, 0, true},
      {"find board for new player", ACTION_FIND_BOARD, 5, 0, 0,
       BOARD_STATE_RESERVED, GAME_RESULT_IN_PROGRESS, true},
      {"find board for experienced player", ACTION_FIND_BOARD, 20, 0, 0,
       BOARD_STATE_RESERVED, GAME_RESULT_IN_PROGRESS, true},
      {"release board", ACTION_RELEASE_BOARD, 0, 1, 0, BOARD_STATE_ACTIVE},
      {"archive board", ACTION_ARCHIVE_BOARD, 0, 2, 0, BOARD_STATE_ARCHIVED},
      {"reservation expiry", ACTION_TICK, 0, 3, RESERVATION_TIMEOUT + 1,
       BOARD_STATE_DORMANT},
      {"inactivity timeout", ACTION_TICK, 0, 4, INACTIVITY_TIMEOUT + 1,
       BOARD_STATE_DORMANT},
      {"rating update white wins", ACTION_UPDATE_RATINGS, 0, 0, 0, 0,
       GAME_RESULT_WHITE_WINS, false, 1216.0, 1184.0},
      {"rating update black wins", ACTION_UPDATE_RATINGS, 0, 0, 0, 0,
       GAME_RESULT_BLACK_WINS, false, 1184.0, 1216.0},
      {"rating update draw", ACTION_UPDATE_RATINGS, 0, 0, 0, 0,
       GAME_RESULT_DRAW, false, 1200.0, 1200.0},
  };

  for (size_t i = 0; i < (sizeof(cases) / sizeof((cases)[0])); ++i) {
    if (*filter && !strstr(cases[i].name, filter))
      continue;

    total++;
    reset_mocks();
    setup_test_player(0);

    if (cases[i].action != ACTION_INIT) {
      find_board_for_player(&test_player);
      find_board_for_player(&test_player);
      WambleBoard *b3 = find_board_for_player(&test_player);
      b3->state = BOARD_STATE_RESERVED;
      WambleBoard *b4 = find_board_for_player(&test_player);
      release_board(b4->id);
    }

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
