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
  DbStatus st = db_get_session_by_token(token, &sid);
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
    uint64_t sid = 0;
    if (resolve_session_id_cached(cache, it->as.link_session_to_pubkey.token,
                                  &sid) != DB_OK ||
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
    DbStatus st =
        resolve_session_id_cached(cache, it->as.record_payout.token, &sid);
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
    DbStatus st =
        resolve_session_id_cached(cache, it->as.record_move.token, &sid);
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
    return 8 + TOKEN_LENGTH + 4;
  case WAMBLE_INTENT_REMOVE_RESERVATION:
    return 8;
  case WAMBLE_INTENT_RECORD_GAME_RESULT:
    return 8 + 1;
  case WAMBLE_INTENT_UPDATE_SESSION_LAST_SEEN:
    return TOKEN_LENGTH;
  case WAMBLE_INTENT_CREATE_SESSION:
    return TOKEN_LENGTH + 8;
  case WAMBLE_INTENT_LINK_SESSION_TO_PUBKEY:
    return TOKEN_LENGTH + 32;
  case WAMBLE_INTENT_RECORD_PAYOUT:
    return 8 + TOKEN_LENGTH + 8;
  case WAMBLE_INTENT_RECORD_MOVE:
    return 8 + TOKEN_LENGTH + MAX_UCI_LENGTH + 4;
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
