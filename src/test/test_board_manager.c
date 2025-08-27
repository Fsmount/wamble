#ifdef TEST_BOARD_MANAGER

#include <assert.h>
#include <string.h>
#include <time.h>

#include "../../include/wamble/wamble.h"

#define MAX_BOARDS 1024
#define MIN_BOARDS 4
#define INACTIVITY_TIMEOUT 300
#define RESERVATION_TIMEOUT 2

static int mock_active_players = 2;
static int mock_longest_moves = 10;
static WambleBoard mock_board_pool[MAX_BOARDS];
static int mock_num_boards = 0;
static uint64_t next_mock_board_id = 1;

void db_expire_reservations(void) {
  time_t now = time(NULL);
  for (int i = 0; i < mock_num_boards; i++) {
    if (mock_board_pool[i].state == BOARD_STATE_RESERVED &&
        (now - mock_board_pool[i].reservation_time) > RESERVATION_TIMEOUT) {
      mock_board_pool[i].state = BOARD_STATE_DORMANT;
    }
  }
}

void db_archive_inactive_boards(int timeout_seconds) {
  time_t now = time(NULL);
  for (int i = 0; i < mock_num_boards; i++) {
    if (mock_board_pool[i].state == BOARD_STATE_ACTIVE &&
        (now - mock_board_pool[i].last_move_time) > timeout_seconds) {
      mock_board_pool[i].state = BOARD_STATE_DORMANT;
    }
  }
}

int db_get_active_session_count(void) { return mock_active_players; }
int db_get_longest_game_moves(void) { return mock_longest_moves; }
void rng_init(void) {}
double rng_double(void) { return 0.5; }

int db_update_board(uint64_t board_id, const char *fen, const char *status) {
  for (int i = 0; i < mock_num_boards; i++) {
    if (mock_board_pool[i].id == board_id) {
      strncpy(mock_board_pool[i].fen, fen, FEN_MAX_LENGTH);
      if (strcmp(status, "ACTIVE") == 0)
        mock_board_pool[i].state = BOARD_STATE_ACTIVE;
      else if (strcmp(status, "RESERVED") == 0)
        mock_board_pool[i].state = BOARD_STATE_RESERVED;
      else if (strcmp(status, "DORMANT") == 0)
        mock_board_pool[i].state = BOARD_STATE_DORMANT;
      else if (strcmp(status, "ARCHIVED") == 0)
        mock_board_pool[i].state = BOARD_STATE_ARCHIVED;
      return 0;
    }
  }
  return -1;
}

int db_get_board(uint64_t board_id, char *fen_out, char *status_out) {
  for (int i = 0; i < mock_num_boards; i++) {
    if (mock_board_pool[i].id == board_id) {
      strcpy(fen_out, mock_board_pool[i].fen);
      switch (mock_board_pool[i].state) {
      case BOARD_STATE_ACTIVE:
        strcpy(status_out, "ACTIVE");
        break;
      case BOARD_STATE_RESERVED:
        strcpy(status_out, "RESERVED");
        break;
      case BOARD_STATE_DORMANT:
        strcpy(status_out, "DORMANT");
        break;
      case BOARD_STATE_ARCHIVED:
        strcpy(status_out, "ARCHIVED");
        break;
      }
      return 0;
    }
  }
  return -1;
}

int db_get_boards_by_status(const char *status, uint64_t *board_ids,
                            int max_boards) {
  int count = 0;
  BoardState state;
  if (strcmp(status, "DORMANT") == 0)
    state = BOARD_STATE_DORMANT;
  else
    return 0;

  for (int i = 0; i < mock_num_boards && count < max_boards; i++) {
    if (mock_board_pool[i].state == state) {
      board_ids[count++] = mock_board_pool[i].id;
    }
  }
  return count;
}

uint64_t db_create_board(const char *fen) {
  if (mock_num_boards >= MAX_BOARDS)
    return 0;
  WambleBoard *board = &mock_board_pool[mock_num_boards++];
  board->id = next_mock_board_id++;
  strncpy(board->fen, fen, FEN_MAX_LENGTH);
  board->fen[FEN_MAX_LENGTH - 1] = '\0';
  board->state = BOARD_STATE_DORMANT;
  return board->id;
}

uint64_t db_get_session_by_token(const uint8_t *token) { return 1; }
int db_create_reservation(uint64_t board_id, uint64_t session_id,
                          int timeout_seconds) {
  return 0;
}
void db_remove_reservation(uint64_t board_id) {}
int db_record_game_result(uint64_t board_id, char winning_side) { return 0; }
int db_record_move(uint64_t board_id, uint64_t session_id, const char *move_uci,
                   int move_number) {
  return 0;
}
void db_async_update_board(uint64_t board_id, const char *fen,
                           const char *status) {
  (void)db_update_board(board_id, fen, status);
}
void db_async_create_reservation(uint64_t board_id, uint64_t session_id,
                                 int timeout_seconds) {
  (void)db_create_reservation(board_id, session_id, timeout_seconds);
}
void db_async_remove_reservation(uint64_t board_id) {
  db_remove_reservation(board_id);
}
void db_async_record_game_result(uint64_t board_id, char winning_side) {
  (void)db_record_game_result(board_id, winning_side);
}
void db_async_record_move(uint64_t board_id, uint64_t session_id,
                          const char *move_uci, int move_number) {
  (void)db_record_move(board_id, session_id, move_uci, move_number);
}
void calculate_and_distribute_pot(uint64_t board_id) {}

#include "../board_manager.c"
#include "../move_engine.c"

static WamblePlayer *white_player_mock;
static WamblePlayer *black_player_mock;

void db_update_session_last_seen(uint64_t session_id) { (void)session_id; }
double db_get_player_total_score(uint64_t session_id) {
  (void)session_id;
  return 0.0;
}
uint64_t db_create_session(const uint8_t *token, uint64_t player_id) {
  (void)token;
  (void)player_id;
  return 1;
}
int db_get_session_games_played(uint64_t session_id) {
  (void)session_id;
  return 0;
}

WamblePlayer *get_player_by_token(const uint8_t *token) {
  if (token[0] == 2)
    return white_player_mock;
  if (token[0] == 3)
    return black_player_mock;
  return NULL;
}

int db_get_moves_for_board(uint64_t board_id, WambleMove *moves_out,
                           int max_moves) {
  if (max_moves < 2) {
    return 0;
  }

  moves_out[0] = (WambleMove){.id = 1,
                              .board_id = 1,
                              .player_token = {2},
                              .timestamp = 0,
                              .is_white_move = true};
  strcpy(moves_out[0].uci_move, "e2e4");

  moves_out[1] = (WambleMove){.id = 2,
                              .board_id = 1,
                              .player_token = {3},
                              .timestamp = 0,
                              .is_white_move = false};
  strcpy(moves_out[1].uci_move, "e7e5");

  return 2;
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

static void reset_mocks() {
  mock_active_players = 2;
  mock_longest_moves = 10;
  mock_num_boards = 0;
  next_mock_board_id = 1;
  memset(mock_board_pool, 0, sizeof(mock_board_pool));
  board_manager_init();
}

static bool run_case(const TestCase *c) {
  WambleBoard *board = NULL;

  switch (c->action) {
  case ACTION_INIT:
    return mock_num_boards >= MIN_BOARDS;
  case ACTION_FIND_BOARD:
    setup_test_player(c->player_games_played);
    board = find_board_for_player(&test_player);
    if ((board != NULL) != c->expect_board_found)
      return false;
    if (board && board->state != c->expected_board_state)
      return false;
    break;
  case ACTION_RELEASE_BOARD:
    release_board(c->board_id_arg);
    board = get_board_by_id(c->board_id_arg);
    return board && board->state == c->expected_board_state;
  case ACTION_ARCHIVE_BOARD:
    archive_board(c->board_id_arg);
    board = get_board_by_id(c->board_id_arg);
    return board && board->state == c->expected_board_state;
  case ACTION_TICK:
    board = get_board_by_id(c->board_id_arg);
    if (!board)
      return false;
    if (c->expected_board_state == BOARD_STATE_DORMANT &&
        board->state == BOARD_STATE_RESERVED) {
      board->reservation_time -= c->time_travel_seconds;
    } else if (c->expected_board_state == BOARD_STATE_DORMANT &&
               board->state == BOARD_STATE_ACTIVE) {
      board->last_move_time -= c->time_travel_seconds;
    }
    board_manager_tick();

    board = NULL;
    for (int i = 0; i < mock_num_boards; i++) {
      if (mock_board_pool[i].id == c->board_id_arg) {
        board = &mock_board_pool[i];
        break;
      }
    }
    return board && board->state == c->expected_board_state;
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
