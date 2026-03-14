#include "../include/wamble/wamble.h"
#include "../include/wamble/wamble_db.h"
#include <limits.h>
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
static struct WambleIntentBuffer *wamble_get_intent_buffer(void) {
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

static void intent_copy_str(char *dst, size_t dst_cap, const char *src) {
  if (!dst || dst_cap == 0)
    return;
  if (!src) {
    dst[0] = '\0';
    return;
  }
  size_t n = strnlen(src, dst_cap - 1);
  memcpy(dst, src, n);
  dst[n] = '\0';
}

void wamble_emit_update_board(uint64_t board_id, const char *fen,
                              const char *status) {
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_UPDATE_BOARD;
  it.as.update_board.board_id = board_id;
  intent_copy_str(it.as.update_board.fen, sizeof(it.as.update_board.fen), fen);
  intent_copy_str(it.as.update_board.status, sizeof(it.as.update_board.status),
                  status);
  intents_push(it);
}

void wamble_emit_update_board_assignment_time(uint64_t board_id) {
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_UPDATE_BOARD_ASSIGNMENT_TIME;
  it.as.update_board_assignment_time.board_id = board_id;
  intents_push(it);
}

void wamble_emit_create_reservation(uint64_t board_id, const uint8_t *token,
                                    int timeout_seconds,
                                    bool reserved_for_white) {
  if (!token)
    return;
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_CREATE_RESERVATION;
  it.as.create_reservation.board_id = board_id;
  memcpy(it.as.create_reservation.token, token, TOKEN_LENGTH);
  it.as.create_reservation.timeout_seconds = timeout_seconds;
  it.as.create_reservation.reserved_for_white = reserved_for_white ? 1 : 0;
  intents_push(it);
}

void wamble_emit_remove_reservation(uint64_t board_id) {
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_REMOVE_RESERVATION;
  it.as.remove_reservation.board_id = board_id;
  intents_push(it);
}

void wamble_emit_record_game_result(uint64_t board_id, char winning_side,
                                    int move_count, int duration_seconds,
                                    const char *termination_reason) {
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_RECORD_GAME_RESULT;
  it.as.record_game_result.board_id = board_id;
  it.as.record_game_result.winning_side = winning_side;
  it.as.record_game_result.move_count = move_count;
  it.as.record_game_result.duration_seconds = duration_seconds;
  intent_copy_str(it.as.record_game_result.termination_reason,
                  sizeof(it.as.record_game_result.termination_reason),
                  termination_reason);
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
  intent_copy_str(it.as.record_move.move_uci,
                  sizeof(it.as.record_move.move_uci), move_uci);
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
  it.as.create_session.treatment_group_key[0] = '\0';
  intents_push(it);
}

void wamble_emit_update_board_move_meta(uint64_t board_id,
                                        const char *group_key) {
  if (board_id == 0)
    return;
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_UPDATE_BOARD_MOVE_META;
  it.as.update_board_move_meta.board_id = board_id;
  intent_copy_str(
      it.as.update_board_move_meta.last_mover_treatment_group,
      sizeof(it.as.update_board_move_meta.last_mover_treatment_group),
      group_key);
  intents_push(it);
}

void wamble_emit_update_board_reservation_meta(uint64_t board_id,
                                               time_t reservation_time,
                                               bool reserved_for_white) {
  if (board_id == 0)
    return;
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_UPDATE_BOARD_RESERVATION_META;
  it.as.update_board_reservation_meta.board_id = board_id;
  it.as.update_board_reservation_meta.reservation_time = reservation_time;
  it.as.update_board_reservation_meta.reserved_for_white =
      reserved_for_white ? 1 : 0;
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

void wamble_emit_unlink_session_identity(const uint8_t *token) {
  if (!token)
    return;
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_UNLINK_SESSION_IDENTITY;
  memcpy(it.as.unlink_session_identity.token, token, TOKEN_LENGTH);
  intents_push(it);
}

void wamble_emit_record_payout(uint64_t board_id, const uint8_t *token,
                               double points) {
  if (!token || points == 0.0)
    return;
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_RECORD_PAYOUT;
  it.as.record_payout.board_id = board_id;
  memcpy(it.as.record_payout.token, token, TOKEN_LENGTH);
  it.as.record_payout.points = points;
  intents_push(it);
}

void wamble_emit_update_player_rating(const uint8_t *token, double rating) {
  if (!token)
    return;
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_UPDATE_PLAYER_RATING;
  memcpy(it.as.update_player_rating.token, token, TOKEN_LENGTH);
  it.as.update_player_rating.rating = rating;
  intents_push(it);
}

void wamble_emit_resolve_prediction(uint64_t board_id, const uint8_t *token,
                                    int move_number, const char *status,
                                    double points_awarded) {
  if (board_id == 0 || !token || move_number <= 0 || !status)
    return;
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_RESOLVE_PREDICTION;
  it.as.resolve_prediction.board_id = board_id;
  memcpy(it.as.resolve_prediction.token, token, TOKEN_LENGTH);
  it.as.resolve_prediction.move_number = move_number;
  it.as.resolve_prediction.points_awarded = points_awarded;
  size_t len = strnlen(status, STATUS_MAX_LENGTH - 1);
  memcpy(it.as.resolve_prediction.status, status, len);
  it.as.resolve_prediction.status[len] = '\0';
  intents_push(it);
}

void wamble_emit_create_board(uint64_t board_id, const char *fen,
                              const char *status, int mode_variant_id) {
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
  it.as.create_board.mode_variant_id = mode_variant_id;
  intents_push(it);
}

typedef struct {
  uint8_t token[TOKEN_LENGTH];
  DbStatus status;
  uint64_t session_id;
} SessionResolveEntry;

typedef struct {
  SessionResolveEntry *items;
  int count;
  int capacity;
} SessionResolveCache;

static DbStatus resolve_session_id_cached(SessionResolveCache *cache,
                                          const uint8_t *token,
                                          uint64_t *out_session_id) {
  if (!token || !out_session_id)
    return DB_ERR_BAD_DATA;
  if (cache && cache->items) {
    for (int i = 0; i < cache->count; i++) {
      if (memcmp(cache->items[i].token, token, TOKEN_LENGTH) == 0) {
        *out_session_id = cache->items[i].session_id;
        return cache->items[i].status;
      }
    }
  }

  uint64_t sid = 0;
  DbStatus st = wamble_query_get_session_by_token(token, &sid);
  if (cache && cache->items && cache->count < cache->capacity) {
    SessionResolveEntry *ent = &cache->items[cache->count++];
    memcpy(ent->token, token, TOKEN_LENGTH);
    ent->status = st;
    ent->session_id = sid;
  }
  *out_session_id = sid;
  return st;
}

static void cache_put_session(SessionResolveCache *cache, const uint8_t *token,
                              DbStatus st, uint64_t sid) {
  if (!cache || !cache->items || !token)
    return;
  for (int i = 0; i < cache->count; i++) {
    if (memcmp(cache->items[i].token, token, TOKEN_LENGTH) == 0) {
      cache->items[i].status = st;
      cache->items[i].session_id = sid;
      return;
    }
  }
  if (cache->count >= cache->capacity)
    return;
  SessionResolveEntry *ent = &cache->items[cache->count++];
  memcpy(ent->token, token, TOKEN_LENGTH);
  ent->status = st;
  ent->session_id = sid;
}

static int apply_one_intent_db(const struct WamblePersistenceIntent *it,
                               SessionResolveCache *cache) {
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
        resolve_session_id_cached(cache, it->as.create_reservation.token, &sid);
    if (st != DB_OK || sid == 0)
      return 0;
    return db_async_create_reservation(
        it->as.create_reservation.board_id, sid,
        it->as.create_reservation.timeout_seconds,
        it->as.create_reservation.reserved_for_white);
  }
  case WAMBLE_INTENT_REMOVE_RESERVATION:
    db_async_remove_reservation(it->as.remove_reservation.board_id);
    return 0;
  case WAMBLE_INTENT_RECORD_GAME_RESULT:
    return db_async_record_game_result(
        it->as.record_game_result.board_id,
        it->as.record_game_result.winning_side,
        it->as.record_game_result.move_count,
        it->as.record_game_result.duration_seconds,
        it->as.record_game_result.termination_reason);
  case WAMBLE_INTENT_UPDATE_SESSION_LAST_SEEN: {
    uint64_t sid = 0;
    DbStatus st = resolve_session_id_cached(
        cache, it->as.update_session_last_seen.token, &sid);
    if (st != DB_OK || sid == 0)
      return 0;
    db_async_update_session_last_seen(sid);
    return 0;
  }
  case WAMBLE_INTENT_CREATE_SESSION: {
    uint64_t sid = db_create_session(it->as.create_session.token,
                                     it->as.create_session.player_id);
    cache_put_session(cache, it->as.create_session.token,
                      sid > 0 ? DB_OK : DB_ERR_EXEC, sid);
    return sid > 0 ? 0 : -1;
  }
  case WAMBLE_INTENT_LINK_SESSION_TO_PUBKEY: {
    const WambleQueryService *qs = wamble_get_query_service();
    uint64_t sid = 0;
    if (resolve_session_id_cached(cache, it->as.link_session_to_pubkey.token,
                                  &sid) != DB_OK ||
        sid == 0 || !qs || !qs->link_session_to_pubkey)
      return -1;
    return qs->link_session_to_pubkey(sid,
                                      it->as.link_session_to_pubkey.public_key);
  }
  case WAMBLE_INTENT_UNLINK_SESSION_IDENTITY: {
    const WambleQueryService *qs = wamble_get_query_service();
    uint64_t sid = 0;
    if (resolve_session_id_cached(cache, it->as.unlink_session_identity.token,
                                  &sid) != DB_OK ||
        sid == 0 || !qs || !qs->unlink_session_identity)
      return -1;
    return qs->unlink_session_identity(sid);
  }
  case WAMBLE_INTENT_RECORD_PAYOUT: {
    uint64_t sid = 0;
    DbStatus st =
        resolve_session_id_cached(cache, it->as.record_payout.token, &sid);
    if (st != DB_OK || sid == 0)
      return 0;
    return db_async_record_payout(it->as.record_payout.board_id, sid,
                                  it->as.record_payout.points);
  }
  case WAMBLE_INTENT_UPDATE_PLAYER_RATING: {
    uint64_t sid = 0;
    DbStatus st = resolve_session_id_cached(
        cache, it->as.update_player_rating.token, &sid);
    if (st != DB_OK || sid == 0)
      return 0;
    return db_async_update_player_rating(sid,
                                         it->as.update_player_rating.rating);
  }
  case WAMBLE_INTENT_CREATE_BOARD: {
    int rc =
        db_insert_board(it->as.create_board.board_id, it->as.create_board.fen,
                        it->as.create_board.status);
    if (rc != 0)
      return rc;
    if (it->as.create_board.mode_variant_id >= 0)
      return db_insert_board_mode_variant(it->as.create_board.board_id,
                                          it->as.create_board.mode_variant_id);
    return 0;
  }
  case WAMBLE_INTENT_RECORD_MOVE: {
    uint64_t sid = 0;
    DbStatus st =
        resolve_session_id_cached(cache, it->as.record_move.token, &sid);
    if (st != DB_OK || sid == 0)
      return 0;
    return db_async_record_move(it->as.record_move.board_id, sid,
                                it->as.record_move.move_uci,
                                it->as.record_move.move_number);
  }
  case WAMBLE_INTENT_UPDATE_BOARD_MOVE_META:
    return db_async_update_board_move_meta(
        it->as.update_board_move_meta.board_id,
        it->as.update_board_move_meta.last_mover_treatment_group);
  case WAMBLE_INTENT_UPDATE_BOARD_RESERVATION_META:
    return db_async_update_board_reservation_meta(
        it->as.update_board_reservation_meta.board_id,
        it->as.update_board_reservation_meta.reservation_time,
        it->as.update_board_reservation_meta.reserved_for_white);
  case WAMBLE_INTENT_RECORD_PREDICTION: {
    uint64_t sid = 0;
    DbStatus st =
        resolve_session_id_cached(cache, it->as.record_prediction.token, &sid);
    if (st != DB_OK || sid == 0)
      return 0;
    return db_async_create_prediction(
        it->as.record_prediction.board_id, sid,
        it->as.record_prediction.parent_id,
        it->as.record_prediction.predicted_move_uci,
        it->as.record_prediction.move_number, 0);
  }
  case WAMBLE_INTENT_RESOLVE_PREDICTION: {
    uint64_t sid = 0;
    DbStatus st =
        resolve_session_id_cached(cache, it->as.resolve_prediction.token, &sid);
    if (st != DB_OK || sid == 0)
      return 0;
    return db_async_resolve_prediction(
        it->as.resolve_prediction.board_id, sid,
        it->as.resolve_prediction.move_number, it->as.resolve_prediction.status,
        it->as.resolve_prediction.points_awarded);
  }
  default:
    return 0;
  }
}

typedef struct {
  int idx;
  const struct WamblePersistenceIntent *it;
} IntentRef;

static int append_ref_cmp(const void *a, const void *b) {
  const IntentRef *ra = (const IntentRef *)a;
  const IntentRef *rb = (const IntentRef *)b;
  if (ra->it->type != rb->it->type)
    return (int)ra->it->type - (int)rb->it->type;
  if (ra->it->as.record_move.board_id < rb->it->as.record_move.board_id)
    return -1;
  if (ra->it->as.record_move.board_id > rb->it->as.record_move.board_id)
    return 1;

  const uint8_t *ta = NULL;
  const uint8_t *tb = NULL;
  if (ra->it->type == WAMBLE_INTENT_RECORD_MOVE) {
    ta = ra->it->as.record_move.token;
    tb = rb->it->as.record_move.token;
  } else {
    ta = ra->it->as.record_payout.token;
    tb = rb->it->as.record_payout.token;
  }
  int tok_cmp = memcmp(ta, tb, TOKEN_LENGTH);
  if (tok_cmp != 0)
    return tok_cmp;

  if (ra->it->type == WAMBLE_INTENT_RECORD_MOVE) {
    if (ra->it->as.record_move.move_number < rb->it->as.record_move.move_number)
      return -1;
    if (ra->it->as.record_move.move_number > rb->it->as.record_move.move_number)
      return 1;
    return strcmp(ra->it->as.record_move.move_uci,
                  rb->it->as.record_move.move_uci);
  }
  if (ra->it->as.record_payout.points < rb->it->as.record_payout.points)
    return -1;
  if (ra->it->as.record_payout.points > rb->it->as.record_payout.points)
    return 1;
  return 0;
}

static int
intent_payload_estimate_bytes(const struct WamblePersistenceIntent *it) {
  if (!it)
    return 1;
  switch (it->type) {
  case WAMBLE_INTENT_UPDATE_BOARD:
    return 8 + 4 + FEN_MAX_LENGTH + STATUS_MAX_LENGTH;
  case WAMBLE_INTENT_CREATE_BOARD:
    return 8 + 4 + FEN_MAX_LENGTH + STATUS_MAX_LENGTH;
  case WAMBLE_INTENT_UPDATE_BOARD_ASSIGNMENT_TIME:
    return 8;
  case WAMBLE_INTENT_CREATE_RESERVATION:
    return 8 + TOKEN_LENGTH + 8;
  case WAMBLE_INTENT_REMOVE_RESERVATION:
    return 8;
  case WAMBLE_INTENT_RECORD_GAME_RESULT:
    return 8 + 1 + 4 + 4 + 32;
  case WAMBLE_INTENT_UPDATE_SESSION_LAST_SEEN:
    return TOKEN_LENGTH;
  case WAMBLE_INTENT_CREATE_SESSION:
    return TOKEN_LENGTH + 12;
  case WAMBLE_INTENT_LINK_SESSION_TO_PUBKEY:
    return TOKEN_LENGTH + 32;
  case WAMBLE_INTENT_UNLINK_SESSION_IDENTITY:
    return TOKEN_LENGTH;
  case WAMBLE_INTENT_RECORD_PAYOUT:
    return 8 + TOKEN_LENGTH + 8;
  case WAMBLE_INTENT_UPDATE_PLAYER_RATING:
    return TOKEN_LENGTH + 8;
  case WAMBLE_INTENT_RECORD_MOVE:
    return 8 + TOKEN_LENGTH + MAX_UCI_LENGTH + 4;
  case WAMBLE_INTENT_UPDATE_BOARD_MOVE_META:
    return 8 + 4;
  case WAMBLE_INTENT_UPDATE_BOARD_RESERVATION_META:
    return 8 + 8 + 1;
  case WAMBLE_INTENT_RECORD_PREDICTION:
    return 16 + TOKEN_LENGTH + MAX_UCI_LENGTH + 4;
  case WAMBLE_INTENT_RESOLVE_PREDICTION:
    return 8 + TOKEN_LENGTH + 4 + STATUS_MAX_LENGTH + 8;
  default:
    return sizeof(*it);
  }
}

PersistenceStatus wamble_apply_intents_with_db_checked(
    struct WambleIntentBuffer *buf, int max_intents, int max_payload_bytes,
    int *out_selected_bytes, int *out_attempted, int *out_failures) {
  if (!buf) {
    if (out_selected_bytes)
      *out_selected_bytes = 0;
    if (out_attempted)
      *out_attempted = 0;
    if (out_failures)
      *out_failures = 0;
    persistence_set_status(PERSISTENCE_STATUS_NO_BUFFER);
    return g_persist_status;
  }
  if (buf->count <= 0) {
    if (out_selected_bytes)
      *out_selected_bytes = 0;
    if (out_attempted)
      *out_attempted = 0;
    if (out_failures)
      *out_failures = 0;
    persistence_set_status(PERSISTENCE_STATUS_EMPTY);
    return g_persist_status;
  }
  int intent_limit = (max_intents > 0) ? max_intents : buf->count;
  if (intent_limit > buf->count)
    intent_limit = buf->count;
  int payload_limit = (max_payload_bytes > 0) ? max_payload_bytes : INT_MAX;
  int selected_payload_bytes = 0;
  int to_apply = 0;
  for (int i = 0; i < intent_limit; i++) {
    int est = intent_payload_estimate_bytes(&buf->items[i]);
    if (est < 1)
      est = 1;
    if (to_apply > 0 && selected_payload_bytes + est > payload_limit)
      break;
    selected_payload_bytes += est;
    to_apply++;
  }
  if (to_apply == 0 && buf->count > 0) {
    to_apply = 1;
    selected_payload_bytes = intent_payload_estimate_bytes(&buf->items[0]);
    if (selected_payload_bytes < 1)
      selected_payload_bytes = 1;
  }
  if (out_selected_bytes)
    *out_selected_bytes = selected_payload_bytes;

  uint8_t *handled = (uint8_t *)calloc((size_t)to_apply, 1);
  IntentRef *append_refs =
      (IntentRef *)malloc(sizeof(*append_refs) * (size_t)to_apply);
  int *exec_idx = (int *)malloc(sizeof(*exec_idx) * (size_t)to_apply);
  if (!handled || !append_refs) {
    free(handled);
    free(append_refs);
    free(exec_idx);
    handled = NULL;
    append_refs = NULL;
    exec_idx = NULL;
  }

  int failures = 0;
  int write_idx = 0;
  int exec_count = 0;
  int txn_success = 0;
  SessionResolveEntry *session_cache_items = NULL;
  SessionResolveCache session_cache = {0};

  if (to_apply > 0) {
    session_cache_items = (SessionResolveEntry *)calloc(
        (size_t)to_apply, sizeof(*session_cache_items));
    if (session_cache_items) {
      session_cache.items = session_cache_items;
      session_cache.capacity = to_apply;
    }
  }

  if (handled && append_refs && exec_idx) {
    for (int i = to_apply - 1; i >= 0; i--) {
      if (handled[i])
        continue;
      struct WamblePersistenceIntent *it = &buf->items[i];

      if (it->type == WAMBLE_INTENT_UPDATE_BOARD) {
        handled[i] = 1;
        for (int j = i - 1; j >= 0; j--) {
          if (!handled[j] && buf->items[j].type == WAMBLE_INTENT_UPDATE_BOARD &&
              buf->items[j].as.update_board.board_id ==
                  it->as.update_board.board_id)
            handled[j] = 1;
        }
        exec_idx[exec_count++] = i;
        continue;
      }
      if (it->type == WAMBLE_INTENT_UPDATE_BOARD_ASSIGNMENT_TIME) {
        handled[i] = 1;
        for (int j = i - 1; j >= 0; j--) {
          if (!handled[j] &&
              buf->items[j].type ==
                  WAMBLE_INTENT_UPDATE_BOARD_ASSIGNMENT_TIME &&
              buf->items[j].as.update_board_assignment_time.board_id ==
                  it->as.update_board_assignment_time.board_id) {
            handled[j] = 1;
          }
        }
        exec_idx[exec_count++] = i;
        continue;
      }
      if (it->type == WAMBLE_INTENT_UPDATE_BOARD_MOVE_META) {
        handled[i] = 1;
        for (int j = i - 1; j >= 0; j--) {
          if (!handled[j] &&
              buf->items[j].type == WAMBLE_INTENT_UPDATE_BOARD_MOVE_META &&
              buf->items[j].as.update_board_move_meta.board_id ==
                  it->as.update_board_move_meta.board_id) {
            handled[j] = 1;
          }
        }
        exec_idx[exec_count++] = i;
        continue;
      }
      if (it->type == WAMBLE_INTENT_UPDATE_BOARD_RESERVATION_META) {
        handled[i] = 1;
        for (int j = i - 1; j >= 0; j--) {
          if (!handled[j] &&
              buf->items[j].type ==
                  WAMBLE_INTENT_UPDATE_BOARD_RESERVATION_META &&
              buf->items[j].as.update_board_reservation_meta.board_id ==
                  it->as.update_board_reservation_meta.board_id) {
            handled[j] = 1;
          }
        }
        exec_idx[exec_count++] = i;
        continue;
      }
      if (it->type == WAMBLE_INTENT_UPDATE_SESSION_LAST_SEEN) {
        handled[i] = 1;
        for (int j = i - 1; j >= 0; j--) {
          if (!handled[j] &&
              buf->items[j].type == WAMBLE_INTENT_UPDATE_SESSION_LAST_SEEN &&
              memcmp(buf->items[j].as.update_session_last_seen.token,
                     it->as.update_session_last_seen.token,
                     TOKEN_LENGTH) == 0) {
            handled[j] = 1;
          }
        }
        exec_idx[exec_count++] = i;
        continue;
      }
      if (it->type == WAMBLE_INTENT_REMOVE_RESERVATION) {
        handled[i] = 1;
        for (int j = i - 1; j >= 0; j--) {
          if (!handled[j] &&
              buf->items[j].type == WAMBLE_INTENT_REMOVE_RESERVATION &&
              buf->items[j].as.remove_reservation.board_id ==
                  it->as.remove_reservation.board_id) {
            handled[j] = 1;
          }
        }
        exec_idx[exec_count++] = i;
      }
    }

    int append_count = 0;
    for (int i = 0; i < to_apply; i++) {
      if (handled[i])
        continue;
      if (buf->items[i].type == WAMBLE_INTENT_RECORD_MOVE ||
          buf->items[i].type == WAMBLE_INTENT_RECORD_PAYOUT) {
        append_refs[append_count].idx = i;
        append_refs[append_count].it = &buf->items[i];
        append_count++;
      }
    }
    qsort(append_refs, (size_t)append_count, sizeof(*append_refs),
          append_ref_cmp);
    for (int i = 0; i < append_count; i++) {
      int idx = append_refs[i].idx;
      if (handled[idx])
        continue;
      handled[idx] = 1;
      exec_idx[exec_count++] = idx;
    }

    for (int i = 0; i < to_apply; i++) {
      if (handled[i])
        continue;
      handled[i] = 1;
      exec_idx[exec_count++] = i;
    }

    if (exec_count > 0 && db_write_batch_begin() == 0) {
      int ok = 1;
      for (int i = 0; i < exec_count; i++) {
        if (apply_one_intent_db(&buf->items[exec_idx[i]], &session_cache) < 0) {
          ok = 0;
          break;
        }
      }
      if (ok && db_write_batch_commit() == 0) {
        txn_success = 1;
      } else {
        db_write_batch_rollback();
      }
    }

    if (!txn_success) {
      for (int i = 0; i < exec_count; i++) {
        struct WamblePersistenceIntent *it = &buf->items[exec_idx[i]];
        if (apply_one_intent_db(it, &session_cache) < 0) {
          failures++;
          buf->items[write_idx++] = *it;
        }
      }
    }
  } else {
    for (int i = 0; i < to_apply; i++) {
      struct WamblePersistenceIntent *it = &buf->items[i];
      int rc = apply_one_intent_db(it, &session_cache);
      if (rc < 0) {
        failures++;
        buf->items[write_idx++] = *it;
      }
    }
  }
  free(session_cache_items);
  if (txn_success) {
    failures = 0;
    write_idx = 0;
  }
  free(exec_idx);
  free(append_refs);
  free(handled);

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
