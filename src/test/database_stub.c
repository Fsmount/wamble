#include "../../include/wamble/wamble.h"
#include <string.h>
#include <time.h>

WambleBoard *get_board_by_id(uint64_t board_id) __attribute__((weak));

static unsigned long long rng_state = 0x0123456789abcdefULL;

void rng_init(void) __attribute__((weak));
uint64_t rng_u64(void) __attribute__((weak));
double rng_double(void) __attribute__((weak));
void rng_bytes(uint8_t *out, size_t len) __attribute__((weak));

void rng_init(void) { rng_state = 0x0123456789abcdefULL; }
uint64_t rng_u64(void) {
  rng_state ^= rng_state >> 12;
  rng_state ^= rng_state << 25;
  rng_state ^= rng_state >> 27;
  return rng_state * 2685821657736338717ULL;
}
double rng_double(void) { return 0.5; }
void rng_bytes(uint8_t *out, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if ((i % 8) == 0)
      (void)rng_u64();
    out[i] = (uint8_t)((rng_state >> ((i % 8) * 8)) & 0xFF);
  }
}

#define STUB_MAX_BOARDS 4096
static uint64_t stub_boards[STUB_MAX_BOARDS];
static int stub_board_count = 0;
static uint64_t stub_next_board_id = 1;

#define STUB_MAX_MOVES 2048
static WambleMove stub_moves[STUB_MAX_MOVES];
static int stub_move_count = 0;

void dbstub_reset_moves(void) {
  stub_move_count = 0;
  memset(stub_moves, 0, sizeof(stub_moves));
}
void dbstub_add_move(uint64_t board_id, const uint8_t *player_token,
                     bool is_white, const char *uci) {
  if (stub_move_count >= STUB_MAX_MOVES)
    return;
  WambleMove *m = &stub_moves[stub_move_count++];
  memset(m, 0, sizeof(*m));
  m->id = (uint64_t)stub_move_count;
  m->board_id = board_id;
  memcpy(m->player_token, player_token, TOKEN_LENGTH);
  m->is_white_move = is_white;
  if (uci) {
    strncpy(m->uci_move, uci, MAX_UCI_LENGTH - 1);
    m->uci_move[MAX_UCI_LENGTH - 1] = '\0';
  }
  m->timestamp = time(NULL);
}

int db_init(const char *connection_string) {
  (void)connection_string;
  return 0;
}
void db_cleanup(void) {}
void db_tick(void) {}
void db_cleanup_thread(void) {}

uint64_t db_create_session(const uint8_t *token, uint64_t player_id) {
  (void)token;
  (void)player_id;
  return 1;
}
uint64_t db_get_session_by_token(const uint8_t *token) {
  (void)token;
  return 0;
}
void db_update_session_last_seen(uint64_t session_id) { (void)session_id; }
int db_get_session_games_played(uint64_t session_id) {
  (void)session_id;
  return 0;
}
uint64_t db_create_player(const uint8_t *public_key) {
  (void)public_key;
  return 1;
}
uint64_t db_get_player_by_public_key(const uint8_t *public_key) {
  (void)public_key;
  return 1;
}
int db_link_session_to_player(uint64_t session_id, uint64_t player_id) {
  (void)session_id;
  (void)player_id;
  return 0;
}
int db_get_trust_tier_by_token(const uint8_t *token) {
  (void)token;
  return 0;
}

int db_get_active_session_count(void) { return 2; }
int db_get_longest_game_moves(void) { return 10; }

uint64_t db_create_board(const char *fen) {
  (void)fen;
  if (stub_board_count >= STUB_MAX_BOARDS)
    return 0;
  uint64_t id = stub_next_board_id++;
  stub_boards[stub_board_count++] = id;
  return id;
}

int db_update_board(uint64_t board_id, const char *fen, const char *status) {
  (void)board_id;
  (void)fen;
  (void)status;
  return 0;
}

int db_get_board(uint64_t board_id, char *fen_out, char *status_out) {
  (void)board_id;
  (void)fen_out;
  (void)status_out;
  return -1;
}

int db_get_boards_by_status(const char *status, uint64_t *board_ids,
                            int max_boards) {
  (void)status;
  (void)board_ids;
  (void)max_boards;
  return 0;
}

int db_record_move(uint64_t board_id, uint64_t session_id, const char *move_uci,
                   int move_number) {
  (void)board_id;
  (void)session_id;
  (void)move_uci;
  (void)move_number;
  return 0;
}

int db_get_moves_for_board(uint64_t board_id, WambleMove *moves_out,
                           int max_moves) {
  int count = 0;
  if (stub_move_count > 0) {
    for (int i = 0; i < stub_move_count && count < max_moves; i++) {
      if (stub_moves[i].board_id == board_id) {
        moves_out[count++] = stub_moves[i];
      }
    }
    return count;
  }
  if (board_id == 1 && max_moves >= 2) {
    memset(&moves_out[0], 0, sizeof(WambleMove));
    moves_out[0].id = 1;
    moves_out[0].board_id = 1;
    moves_out[0].is_white_move = true;
    moves_out[0].player_token[0] = 2;
    strncpy(moves_out[0].uci_move, "e2e4", MAX_UCI_LENGTH - 1);
    memset(&moves_out[1], 0, sizeof(WambleMove));
    moves_out[1].id = 2;
    moves_out[1].board_id = 1;
    moves_out[1].is_white_move = false;
    moves_out[1].player_token[0] = 3;
    strncpy(moves_out[1].uci_move, "e7e5", MAX_UCI_LENGTH - 1);
    return 2;
  }
  return 0;
}

int db_create_reservation(uint64_t board_id, uint64_t session_id,
                          int timeout_seconds) {
  (void)board_id;
  (void)session_id;
  (void)timeout_seconds;
  return 0;
}
void db_remove_reservation(uint64_t board_id) { (void)board_id; }

void db_expire_reservations(void) {
  time_t now = time(NULL);
  if (!get_board_by_id)
    return;
  for (int i = 0; i < stub_board_count; i++) {
    uint64_t id = stub_boards[i];
    WambleBoard *b = get_board_by_id(id);
    if (!b)
      continue;
    if (b->state == BOARD_STATE_RESERVED) {
      if ((now - b->reservation_time) > get_config()->reservation_timeout) {
        b->state = BOARD_STATE_DORMANT;
      }
    }
  }
}

void db_archive_inactive_boards(int timeout_seconds) {
  time_t now = time(NULL);
  if (!get_board_by_id)
    return;
  for (int i = 0; i < stub_board_count; i++) {
    uint64_t id = stub_boards[i];
    WambleBoard *b = get_board_by_id(id);
    if (!b)
      continue;
    if (b->state == BOARD_STATE_ACTIVE) {
      if ((now - b->last_move_time) > timeout_seconds) {
        b->state = BOARD_STATE_DORMANT;
      }
    }
  }
}

int db_record_game_result(uint64_t board_id, char winning_side) {
  (void)board_id;
  (void)winning_side;
  return 0;
}

int db_record_payout(uint64_t board_id, uint64_t session_id, double points) {
  (void)board_id;
  (void)session_id;
  (void)points;
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
void db_async_record_payout(uint64_t board_id, uint64_t session_id,
                            double points) {
  (void)db_record_payout(board_id, session_id, points);
}

double db_get_player_total_score(uint64_t session_id) {
  (void)session_id;
  return 0.0;
}
