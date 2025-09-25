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
typedef struct {
  uint64_t id;
  char fen[FEN_MAX_LENGTH];
  char status[STATUS_MAX_LENGTH];
  time_t last_assignment_time;
} StubBoard;
static StubBoard stub_boards[STUB_MAX_BOARDS];
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
void db_async_update_session_last_seen(uint64_t session_id) {
  (void)session_id;
}
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
int db_async_link_session_to_player(uint64_t session_id, uint64_t player_id) {
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
  if (stub_board_count >= STUB_MAX_BOARDS)
    return 0;
  uint64_t id = stub_next_board_id++;
  StubBoard *sb = &stub_boards[stub_board_count++];
  sb->id = id;
  strncpy(sb->fen, fen ? fen : "", FEN_MAX_LENGTH - 1);
  sb->fen[FEN_MAX_LENGTH - 1] = '\0';
  strncpy(sb->status, "DORMANT", STATUS_MAX_LENGTH - 1);
  sb->status[STATUS_MAX_LENGTH - 1] = '\0';
  sb->last_assignment_time = time(NULL);
  return id;
}

int db_async_update_board(uint64_t board_id, const char *fen,
                          const char *status) {
  for (int i = 0; i < stub_board_count; i++) {
    if (stub_boards[i].id == board_id) {
      if (fen) {
        strncpy(stub_boards[i].fen, fen, FEN_MAX_LENGTH - 1);
        stub_boards[i].fen[FEN_MAX_LENGTH - 1] = '\0';
      }
      if (status) {
        strncpy(stub_boards[i].status, status, STATUS_MAX_LENGTH - 1);
        stub_boards[i].status[STATUS_MAX_LENGTH - 1] = '\0';
      }
      return 0;
    }
  }
  return -1;
}

DbBoardResult db_get_board(uint64_t board_id) {
  DbBoardResult r = {0};
  r.status = DB_NOT_FOUND;
  for (int i = 0; i < stub_board_count; i++) {
    if (stub_boards[i].id == board_id) {
      r.status = DB_OK;
      strncpy(r.fen, stub_boards[i].fen, FEN_MAX_LENGTH - 1);
      r.fen[FEN_MAX_LENGTH - 1] = '\0';
      strncpy(r.status_text, stub_boards[i].status, STATUS_MAX_LENGTH - 1);
      r.status_text[STATUS_MAX_LENGTH - 1] = '\0';
      r.last_assignment_time = stub_boards[i].last_assignment_time;
      break;
    }
  }
  return r;
}

DbBoardIdList db_list_boards_by_status(const char *status) {
  static uint64_t ids[STUB_MAX_BOARDS];
  int count = 0;
  for (int i = 0; i < stub_board_count; i++) {
    if (strncmp(stub_boards[i].status, status, STATUS_MAX_LENGTH) == 0) {
      ids[count++] = stub_boards[i].id;
    }
  }
  DbBoardIdList list = {0};
  list.status = DB_OK;
  list.ids = (count > 0) ? ids : NULL;
  list.count = count;
  return list;
}

int db_async_record_move(uint64_t board_id, uint64_t session_id,
                         const char *move_uci, int move_number) {
  (void)board_id;
  (void)session_id;
  (void)move_uci;
  (void)move_number;
  return 0;
}

DbMovesResult db_get_moves_for_board(uint64_t board_id) {
  DbMovesResult out = {0};
  out.status = DB_OK;
  out.rows = NULL;
  out.count = 0;
  int count = 0;
  if (stub_move_count > 0) {
    for (int i = 0; i < stub_move_count; i++) {
      if (stub_moves[i].board_id == board_id) {
        count++;
      }
    }
    if (count > 0) {
      static WambleMove tls_rows[STUB_MAX_MOVES];
      int w = 0;
      for (int i = 0; i < stub_move_count; i++) {
        if (stub_moves[i].board_id == board_id) {
          tls_rows[w++] = stub_moves[i];
        }
      }
      out.rows = tls_rows;
      out.count = count;
    }
    return out;
  }
  if (board_id == 1) {
    static WambleMove tls_rows2[2];
    memset(&tls_rows2[0], 0, sizeof(WambleMove));
    tls_rows2[0].id = 1;
    tls_rows2[0].board_id = 1;
    tls_rows2[0].is_white_move = true;
    tls_rows2[0].player_token[0] = 2;
    strncpy(tls_rows2[0].uci_move, "e2e4", MAX_UCI_LENGTH - 1);
    memset(&tls_rows2[1], 0, sizeof(WambleMove));
    tls_rows2[1].id = 2;
    tls_rows2[1].board_id = 1;
    tls_rows2[1].is_white_move = false;
    tls_rows2[1].player_token[0] = 3;
    strncpy(tls_rows2[1].uci_move, "e7e5", MAX_UCI_LENGTH - 1);
    out.rows = tls_rows2;
    out.count = 2;
    return out;
  }
  return out;
}

int db_async_create_reservation(uint64_t board_id, uint64_t session_id,
                                int timeout_seconds) {
  (void)board_id;
  (void)session_id;
  (void)timeout_seconds;
  return 0;
}
void db_async_remove_reservation(uint64_t board_id) { (void)board_id; }

void db_expire_reservations(void) {
  time_t now = time(NULL);
  if (!get_board_by_id)
    return;
  for (int i = 0; i < stub_board_count; i++) {
    uint64_t id = stub_boards[i].id;
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
    uint64_t id = stub_boards[i].id;
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

int db_async_record_game_result(uint64_t board_id, char winning_side) {
  (void)board_id;
  (void)winning_side;
  return 0;
}

int db_async_record_payout(uint64_t board_id, uint64_t session_id,
                           double points) {
  (void)board_id;
  (void)session_id;
  (void)points;
  return 0;
}

double db_get_player_total_score(uint64_t session_id) {
  (void)session_id;
  return 0.0;
}

double db_get_player_rating(uint64_t session_id) {
  (void)session_id;
  return 0.0;
}

int db_async_update_player_rating(uint64_t session_id, double rating) {
  (void)session_id;
  (void)rating;
  return 0;
}

int db_async_update_board_assignment_time(uint64_t board_id) {
  for (int i = 0; i < stub_board_count; i++) {
    if (stub_boards[i].id == board_id) {
      stub_boards[i].last_assignment_time = time(NULL);
      return 0;
    }
  }
  return -1;
}
