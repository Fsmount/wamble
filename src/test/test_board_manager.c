#ifdef TEST_BOARD_MANAGER

#include <assert.h>
#include <string.h>
#include <time.h>

#include "../../include/wamble/wamble.h"

#define MIN_BOARDS 4

ScoringStatus calculate_and_distribute_pot(uint64_t board_id) {
  (void)board_id;
  return SCORING_OK;
}

#include "../board_manager.c"
#include "../move_engine.c"

static WamblePlayer *white_player_mock;
static WamblePlayer *black_player_mock;
static WamblePlayer test_player;

WamblePlayer *get_player_by_token(const uint8_t *token) {
  if (token[0] == 1)
    return &test_player;
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
  ACTION_MARK_MOVE_PLAYED,
  ACTION_COMPLETE_GAME,
  ACTION_CHECK_RESERVATION
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
  bool expected_reservation_result;
} TestCase;

static void setup_test_player(int games_played) {
  memset(&test_player, 0, sizeof(WamblePlayer));
  test_player.token[0] = 1;
  test_player.games_played = games_played;
}

static void reset_mocks() { board_manager_init(); }

static bool run_case(TestCase *c) {
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
    board_release_reservation(target->id);
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
    board_archive(target->id);
    board = get_board_by_id(target->id);
    return board && board->state == c->expected_board_state;
  }
  case ACTION_MARK_MOVE_PLAYED: {

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
    time_t old_time = target->last_move_time;
    board_move_played(target->id);
    board = get_board_by_id(target->id);
    return board && board->state == BOARD_STATE_ACTIVE &&
           board->last_move_time > old_time;
  }
  case ACTION_COMPLETE_GAME: {
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
    board_game_completed(target->id, c->expected_game_result);
    board = get_board_by_id(target->id);
    return board && board->state == BOARD_STATE_ARCHIVED &&
           board->result == c->expected_game_result;
  }
  case ACTION_CHECK_RESERVATION: {
    WambleBoard *target = get_board_by_id(c->board_id_arg);
    if (!target)
      return false;
    bool result = board_is_reserved_for_player(target->id, test_player.token);
    return result == c->expected_reservation_result;
  }
  case ACTION_TICK: {
    WambleBoard *target = NULL;

    if (c->board_id_arg == 4) {
      for (uint64_t id = 1; id < 1000; ++id) {
        WambleBoard *b = get_board_by_id(id);
        if (b && b->state == BOARD_STATE_RESERVED) {
          board_move_played(b->id);
          target = b;
          break;
        }
      }
    } else {
      for (uint64_t id = 1; id < 1000; ++id) {
        WambleBoard *b = get_board_by_id(id);
        if (b && (b->state == BOARD_STATE_RESERVED ||
                  b->state == BOARD_STATE_ACTIVE)) {
          if (c->board_id_arg == 3 && b->state != BOARD_STATE_RESERVED) {
            continue;
          }
          target = b;
          break;
        }
      }
    }

    if (!target) {
      return false;
    }
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
      {"release board", ACTION_RELEASE_BOARD, 0, 1, 0, BOARD_STATE_DORMANT},
      {"archive board", ACTION_ARCHIVE_BOARD, 0, 2, 0, BOARD_STATE_ARCHIVED},
      {"mark move played", ACTION_MARK_MOVE_PLAYED, 0, 0, 0,
       BOARD_STATE_ACTIVE},
      {"complete game with white win", ACTION_COMPLETE_GAME, 0, 0, 0,
       BOARD_STATE_ARCHIVED, GAME_RESULT_WHITE_WINS, false},
      {"complete game with black win", ACTION_COMPLETE_GAME, 0, 0, 0,
       BOARD_STATE_ARCHIVED, GAME_RESULT_BLACK_WINS, false},
      {"complete game with draw", ACTION_COMPLETE_GAME, 0, 0, 0,
       BOARD_STATE_ARCHIVED, GAME_RESULT_DRAW, false},
      {"check valid reservation", ACTION_CHECK_RESERVATION, 0, 0, 0,
       BOARD_STATE_RESERVED, GAME_RESULT_IN_PROGRESS, false, true},
      {"reservation timeout", ACTION_TICK, 0, 3,
       (int)get_config()->reservation_timeout + 1, BOARD_STATE_DORMANT},
      {"inactivity timeout", ACTION_TICK, 0, 4,
       (int)get_config()->inactivity_timeout + 1, BOARD_STATE_DORMANT}};

  for (size_t i = 0; i < (sizeof(cases) / sizeof((cases)[0])); ++i) {
    if (*filter && !strstr(cases[i].name, filter))
      continue;

    total++;
    reset_mocks();
    setup_test_player(0);

    if (cases[i].action != ACTION_INIT) {

      WambleBoard *b1 = find_board_for_player(&test_player);
      if (cases[i].action == ACTION_CHECK_RESERVATION) {
        cases[i].board_id_arg = b1->id;
      }
      (void)find_board_for_player(&test_player);
      (void)find_board_for_player(&test_player);
      (void)find_board_for_player(&test_player);
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
