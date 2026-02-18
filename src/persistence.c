#include "../include/wamble/wamble.h"
#include "../include/wamble/wamble_db.h"
#include <stdlib.h>
#include <string.h>

static WAMBLE_THREAD_LOCAL const WambleQueryService *g_qs_tls = NULL;
static const WambleQueryService *g_qs_default = NULL;
static WAMBLE_THREAD_LOCAL WambleIntentBuffer *g_intents_tls = NULL;
static WAMBLE_THREAD_LOCAL PersistenceStatus g_persist_status =
    PERSISTENCE_STATUS_OK;

static void persistence_set_status(PersistenceStatus st) {
  switch (st) {
  case PERSISTENCE_STATUS_OK:
  case PERSISTENCE_STATUS_EMPTY:
    if (g_persist_status != PERSISTENCE_STATUS_ALLOC_FAIL &&
        g_persist_status != PERSISTENCE_STATUS_NO_BUFFER &&
        g_persist_status != PERSISTENCE_STATUS_APPLY_FAIL) {
      g_persist_status = st;
    }
    break;
  default:
    g_persist_status = st;
    break;
  }
}

void wamble_set_query_service(const WambleQueryService *svc) {
  g_qs_tls = svc;
  g_qs_default = svc;
}

const WambleQueryService *wamble_get_query_service(void) {
  if (g_qs_tls)
    return g_qs_tls;
  return g_qs_default;
}

void wamble_set_intent_buffer(struct WambleIntentBuffer *buf) {
  g_intents_tls = buf;
}
struct WambleIntentBuffer *wamble_get_intent_buffer(void) {
  return g_intents_tls;
}

void wamble_persistence_clear_status(void) {
  g_persist_status = PERSISTENCE_STATUS_OK;
}

void wamble_intents_init(struct WambleIntentBuffer *buf) {
  if (!buf)
    return;
  buf->items = NULL;
  buf->count = 0;
  buf->capacity = 0;
}

void wamble_intents_free(struct WambleIntentBuffer *buf) {
  if (!buf)
    return;
  if (buf->items) {
    free(buf->items);
    buf->items = NULL;
  }
  buf->count = 0;
  buf->capacity = 0;
}

void wamble_intents_clear(struct WambleIntentBuffer *buf) {
  if (!buf)
    return;
  buf->count = 0;
}

static void intents_ensure(struct WambleIntentBuffer *buf, int add) {
  if (!buf)
    return;
  int need = buf->count + add;
  if (need <= buf->capacity)
    return;
  int newcap = buf->capacity > 0 ? buf->capacity : 8;
  while (newcap < need)
    newcap *= 2;
  struct WamblePersistenceIntent *ni =
      (struct WamblePersistenceIntent *)realloc(
          buf->items, (size_t)newcap * sizeof(*buf->items));
  if (!ni) {
    persistence_set_status(PERSISTENCE_STATUS_ALLOC_FAIL);
    return;
  }
  buf->items = ni;
  buf->capacity = newcap;
}

static void intents_push(struct WamblePersistenceIntent in) {
  WambleIntentBuffer *buf = wamble_get_intent_buffer();
  if (!buf) {
    persistence_set_status(PERSISTENCE_STATUS_NO_BUFFER);
    return;
  }
  intents_ensure(buf, 1);
  if (buf->count < buf->capacity) {
    buf->items[buf->count++] = in;
  }
}

void wamble_emit_update_board(uint64_t board_id, const char *fen,
                              const char *status) {
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_UPDATE_BOARD;
  it.as.update_board.board_id = board_id;
  if (fen) {
    size_t n = strnlen(fen, FEN_MAX_LENGTH - 1);
    memcpy(it.as.update_board.fen, fen, n);
    it.as.update_board.fen[n] = '\0';
  } else {
    it.as.update_board.fen[0] = '\0';
  }
  if (status) {
    size_t m = strnlen(status, STATUS_MAX_LENGTH - 1);
    memcpy(it.as.update_board.status, status, m);
    it.as.update_board.status[m] = '\0';
  } else {
    it.as.update_board.status[0] = '\0';
  }
  intents_push(it);
}

void wamble_emit_update_board_assignment_time(uint64_t board_id) {
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_UPDATE_BOARD_ASSIGNMENT_TIME;
  it.as.update_board_assignment_time.board_id = board_id;
  intents_push(it);
}

void wamble_emit_create_reservation(uint64_t board_id, const uint8_t *token,
                                    int timeout_seconds) {
  if (!token)
    return;
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_CREATE_RESERVATION;
  it.as.create_reservation.board_id = board_id;
  memcpy(it.as.create_reservation.token, token, TOKEN_LENGTH);
  it.as.create_reservation.timeout_seconds = timeout_seconds;
  intents_push(it);
}

void wamble_emit_remove_reservation(uint64_t board_id) {
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_REMOVE_RESERVATION;
  it.as.remove_reservation.board_id = board_id;
  intents_push(it);
}

void wamble_emit_record_game_result(uint64_t board_id, char winning_side) {
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_RECORD_GAME_RESULT;
  it.as.record_game_result.board_id = board_id;
  it.as.record_game_result.winning_side = winning_side;
  intents_push(it);
}

void wamble_emit_record_move(uint64_t board_id, const uint8_t *token,
                             const char *move_uci, int move_number) {
  if (board_id == 0 || !token || !move_uci)
    return;
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_RECORD_MOVE;
  it.as.record_move.board_id = board_id;
  memcpy(it.as.record_move.token, token, TOKEN_LENGTH);
  it.as.record_move.move_number = move_number;
  size_t len = strnlen(move_uci, MAX_UCI_LENGTH - 1);
  memcpy(it.as.record_move.move_uci, move_uci, len);
  it.as.record_move.move_uci[len] = '\0';
  intents_push(it);
}

void wamble_emit_update_session_last_seen(const uint8_t *token) {
  if (!token)
    return;
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_UPDATE_SESSION_LAST_SEEN;
  memcpy(it.as.update_session_last_seen.token, token, TOKEN_LENGTH);
  intents_push(it);
}

void wamble_emit_create_session(const uint8_t *token, uint64_t player_id) {
  if (!token)
    return;
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_CREATE_SESSION;
  memcpy(it.as.create_session.token, token, TOKEN_LENGTH);
  it.as.create_session.player_id = player_id;
  intents_push(it);
}

void wamble_emit_link_session_to_pubkey(const uint8_t *token,
                                        const uint8_t *public_key) {
  if (!public_key || !token)
    return;
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_LINK_SESSION_TO_PUBKEY;
  memcpy(it.as.link_session_to_pubkey.token, token, TOKEN_LENGTH);
  memcpy(it.as.link_session_to_pubkey.public_key, public_key, 32);
  intents_push(it);
}

void wamble_emit_record_payout(uint64_t board_id, const uint8_t *token,
                               double points) {
  if (!token || points <= 0.0)
    return;
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_RECORD_PAYOUT;
  it.as.record_payout.board_id = board_id;
  memcpy(it.as.record_payout.token, token, TOKEN_LENGTH);
  it.as.record_payout.points = points;
  intents_push(it);
}

void wamble_emit_create_board(uint64_t board_id, const char *fen,
                              const char *status) {
  if (board_id == 0 || !fen || !status)
    return;
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_CREATE_BOARD;
  it.as.create_board.board_id = board_id;
  size_t fen_len = strnlen(fen, FEN_MAX_LENGTH - 1);
  memcpy(it.as.create_board.fen, fen, fen_len);
  it.as.create_board.fen[fen_len] = '\0';
  size_t status_len = strnlen(status, STATUS_MAX_LENGTH - 1);
  memcpy(it.as.create_board.status, status, status_len);
  it.as.create_board.status[status_len] = '\0';
  intents_push(it);
}

static int apply_one_intent_db(const struct WamblePersistenceIntent *it) {
  switch (it->type) {
  case WAMBLE_INTENT_UPDATE_BOARD:
    return db_async_update_board(it->as.update_board.board_id,
                                 it->as.update_board.fen,
                                 it->as.update_board.status);
  case WAMBLE_INTENT_UPDATE_BOARD_ASSIGNMENT_TIME:
    return db_async_update_board_assignment_time(
        it->as.update_board_assignment_time.board_id);
  case WAMBLE_INTENT_CREATE_RESERVATION: {
    uint64_t sid = 0;
    DbStatus st =
        db_get_session_by_token(it->as.create_reservation.token, &sid);
    if (st != DB_OK || sid == 0)
      return 0;
    return db_async_create_reservation(
        it->as.create_reservation.board_id, sid,
        it->as.create_reservation.timeout_seconds);
  }
  case WAMBLE_INTENT_REMOVE_RESERVATION:
    db_async_remove_reservation(it->as.remove_reservation.board_id);
    return 0;
  case WAMBLE_INTENT_RECORD_GAME_RESULT:
    return db_async_record_game_result(it->as.record_game_result.board_id,
                                       it->as.record_game_result.winning_side);
  case WAMBLE_INTENT_UPDATE_SESSION_LAST_SEEN: {
    uint64_t sid = 0;
    DbStatus st =
        db_get_session_by_token(it->as.update_session_last_seen.token, &sid);
    if (st != DB_OK || sid == 0)
      return 0;
    db_async_update_session_last_seen(sid);
    return 0;
  }
  case WAMBLE_INTENT_CREATE_SESSION: {
    uint64_t sid = db_create_session(it->as.create_session.token,
                                     it->as.create_session.player_id);
    return sid > 0 ? 0 : -1;
  }
  case WAMBLE_INTENT_LINK_SESSION_TO_PUBKEY: {
    uint64_t sid = 0;
    if (db_get_session_by_token(it->as.link_session_to_pubkey.token, &sid) !=
            DB_OK ||
        sid == 0)
      return -1;
    uint64_t pid =
        db_get_player_by_public_key(it->as.link_session_to_pubkey.public_key);
    if (pid == 0) {
      pid = db_create_player(it->as.link_session_to_pubkey.public_key);
    }
    if (pid > 0) {
      return db_async_link_session_to_player(sid, pid);
    }
    return -1;
  }
  case WAMBLE_INTENT_RECORD_PAYOUT: {
    uint64_t sid = 0;
    DbStatus st = db_get_session_by_token(it->as.record_payout.token, &sid);
    if (st != DB_OK || sid == 0)
      return 0;
    return db_async_record_payout(it->as.record_payout.board_id, sid,
                                  it->as.record_payout.points);
  }
  case WAMBLE_INTENT_CREATE_BOARD:
    return db_insert_board(it->as.create_board.board_id,
                           it->as.create_board.fen, it->as.create_board.status);
  case WAMBLE_INTENT_RECORD_MOVE: {
    uint64_t sid = 0;
    DbStatus st = db_get_session_by_token(it->as.record_move.token, &sid);
    if (st != DB_OK || sid == 0)
      return 0;
    return db_async_record_move(it->as.record_move.board_id, sid,
                                it->as.record_move.move_uci,
                                it->as.record_move.move_number);
  }
  default:
    return 0;
  }
}

PersistenceStatus
wamble_apply_intents_with_db_checked(struct WambleIntentBuffer *buf,
                                     int max_batch, int *out_attempted,
                                     int *out_failures) {
  if (!buf) {
    if (out_attempted)
      *out_attempted = 0;
    if (out_failures)
      *out_failures = 0;
    persistence_set_status(PERSISTENCE_STATUS_NO_BUFFER);
    return g_persist_status;
  }
  if (buf->count <= 0) {
    if (out_attempted)
      *out_attempted = 0;
    if (out_failures)
      *out_failures = 0;
    persistence_set_status(PERSISTENCE_STATUS_EMPTY);
    return g_persist_status;
  }
  int to_apply = buf->count;
  if (max_batch > 0 && to_apply > max_batch)
    to_apply = max_batch;
  int failures = 0;
  int write_idx = 0;
  for (int i = 0; i < to_apply; i++) {
    struct WamblePersistenceIntent *it = &buf->items[i];
    int rc = apply_one_intent_db(it);
    if (rc < 0) {
      failures++;
      buf->items[write_idx++] = *it;
    }
  }
  if (to_apply < buf->count) {
    int tail = buf->count - to_apply;
    memmove(&buf->items[write_idx], &buf->items[to_apply],
            (size_t)tail * sizeof(*buf->items));
    buf->count = write_idx + tail;
  } else if (failures > 0) {
    buf->count = write_idx;
  } else {
    wamble_intents_clear(buf);
  }
  if (failures > 0) {
    persistence_set_status(PERSISTENCE_STATUS_APPLY_FAIL);
  } else {
    persistence_set_status(PERSISTENCE_STATUS_OK);
  }
  if (out_attempted)
    *out_attempted = to_apply;
  if (out_failures)
    *out_failures = failures;
  return g_persist_status;
}
