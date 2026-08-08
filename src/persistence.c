#include "../include/wamble/wamble.h"
#include "../include/wamble/wamble_db.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
  PERSISTENCE_STATUS_OK = 0,
  PERSISTENCE_STATUS_NO_BUFFER = 1,
  PERSISTENCE_STATUS_ALLOC_FAIL = 2,
  PERSISTENCE_STATUS_APPLY_FAIL = 3,
  PERSISTENCE_STATUS_EMPTY = 4,
} PersistenceStatus;

typedef enum {
  WAMBLE_INTENT_UPDATE_BOARD = 1,
  WAMBLE_INTENT_UPDATE_BOARD_ASSIGNMENT_TIME = 2,
  WAMBLE_INTENT_CREATE_RESERVATION = 3,
  WAMBLE_INTENT_REMOVE_RESERVATION = 4,
  WAMBLE_INTENT_RECORD_GAME_RESULT = 5,
  WAMBLE_INTENT_UPDATE_SESSION_LAST_SEEN = 6,
  WAMBLE_INTENT_CREATE_SESSION = 7,
  WAMBLE_INTENT_LINK_SESSION_TO_PUBKEY = 8,
  WAMBLE_INTENT_RECORD_PAYOUT = 9,
  WAMBLE_INTENT_CREATE_BOARD = 10,
  WAMBLE_INTENT_RECORD_MOVE = 11,
  WAMBLE_INTENT_UPDATE_BOARD_MOVE_META = 12,
  WAMBLE_INTENT_UPDATE_BOARD_RESERVATION_META = 13,
  WAMBLE_INTENT_RECORD_PREDICTION = 14,
  WAMBLE_INTENT_RESOLVE_PREDICTION = 15,
  WAMBLE_INTENT_UNLINK_SESSION_IDENTITY = 16,
  WAMBLE_INTENT_UPDATE_PLAYER_RATING = 17,
  WAMBLE_INTENT_RECORD_LAST_MOVE_SHOWN = 18,
  WAMBLE_INTENT_RECORD_PROFILE_TERMS_ACCEPTANCE = 19,
  WAMBLE_INTENT_ASSIGN_SESSION_TREATMENT = 20,
} WambleIntentType;

typedef struct WamblePersistenceIntent {
  WambleIntentType type;
  union {
    struct {
      uint64_t board_id;
      char fen[FEN_MAX_LENGTH];
      char status[STATUS_MAX_LENGTH];
    } update_board;
    struct {
      uint64_t board_id;
      char fen[FEN_MAX_LENGTH];
      char status[STATUS_MAX_LENGTH];
      int mode_variant_id;
    } create_board;
    struct {
      uint64_t board_id;
    } update_board_assignment_time;
    struct {
      uint64_t board_id;
      uint8_t token[TOKEN_LENGTH];
      int timeout_seconds;
      int reserved_for_white;
    } create_reservation;
    struct {
      uint64_t board_id;
    } remove_reservation;
    struct {
      uint64_t board_id;
      char winning_side;
      int move_count;
      int duration_seconds;
      char termination_reason[32];
    } record_game_result;
    struct {
      uint8_t token[TOKEN_LENGTH];
    } update_session_last_seen;
    struct {
      uint8_t token[TOKEN_LENGTH];
      uint64_t player_id;
      char treatment_group_key[128];
    } create_session;
    struct {
      uint8_t token[TOKEN_LENGTH];
      uint8_t public_key[32];
    } link_session_to_pubkey;
    struct {
      uint8_t token[TOKEN_LENGTH];
    } unlink_session_identity;
    struct {
      uint64_t board_id;
      uint8_t token[TOKEN_LENGTH];
      double points;
      double canonical_points;
    } record_payout;
    struct {
      uint8_t token[TOKEN_LENGTH];
      double rating;
    } update_player_rating;
    struct {
      uint64_t board_id;
      uint8_t token[TOKEN_LENGTH];
      char move_uci[MAX_UCI_LENGTH];
      int move_number;
    } record_move;
    struct {
      uint8_t token[TOKEN_LENGTH];
      char profile_name[128];
      uint8_t tos_hash[WAMBLE_FRAGMENT_HASH_LENGTH];
      char tos_text[FEN_MAX_LENGTH];
    } record_profile_terms_acceptance;
    struct {
      uint8_t token[TOKEN_LENGTH];
      char profile_name[128];
    } assign_session_treatment;
    struct {
      uint64_t board_id;
      char last_mover_treatment_group[128];
    } update_board_move_meta;
    struct {
      uint64_t board_id;
      uint8_t token[TOKEN_LENGTH];
      char shown_uci[MAX_UCI_LENGTH];
    } record_last_move_shown;
    struct {
      uint64_t board_id;
      time_t reservation_time;
      int reserved_for_white;
    } update_board_reservation_meta;
    struct {
      uint64_t board_id;
      uint64_t parent_id;
      uint8_t token[TOKEN_LENGTH];
      char predicted_move_uci[MAX_UCI_LENGTH];
      int move_number;
      int correct_streak;
    } record_prediction;
    struct {
      uint64_t board_id;
      uint8_t token[TOKEN_LENGTH];
      int move_number;
      char status[STATUS_MAX_LENGTH];
      double points_awarded;
    } resolve_prediction;
  } as;
} WamblePersistenceIntent;

typedef struct WambleIntentBuffer {
  struct WamblePersistenceIntent *items;
  int count;
  int capacity;
} WambleIntentBuffer;

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

struct WambleIntentBuffer *wamble_intents_create(void) {
  struct WambleIntentBuffer *buf =
      (struct WambleIntentBuffer *)calloc(1, sizeof(*buf));
  if (!buf)
    return NULL;
  wamble_intents_init(buf);
  return buf;
}

void wamble_intents_destroy(struct WambleIntentBuffer *buf) {
  if (!buf)
    return;
  wamble_intents_free(buf);
  free(buf);
}

int wamble_intents_count(const struct WambleIntentBuffer *buf) {
  return buf ? buf->count : 0;
}

struct WambleIntentBuffer *
wamble_intents_clone(const struct WambleIntentBuffer *src) {
  struct WambleIntentBuffer *dst = wamble_intents_create();
  if (!dst)
    return NULL;
  if (!src || src->count <= 0)
    return dst;
  dst->items = (struct WamblePersistenceIntent *)malloc((size_t)src->count *
                                                        sizeof(*dst->items));
  if (!dst->items) {
    wamble_intents_destroy(dst);
    return NULL;
  }
  memcpy(dst->items, src->items, (size_t)src->count * sizeof(*dst->items));
  dst->count = src->count;
  dst->capacity = src->count;
  return dst;
}

int wamble_intents_replace_flushed_prefix(struct WambleIntentBuffer *dst,
                                          struct WambleIntentBuffer *remaining,
                                          int copied_count) {
  if (!dst || copied_count <= 0)
    return 0;
  if (copied_count > dst->count)
    copied_count = dst->count;
  int tail_count = dst->count - copied_count;
  int remaining_count = remaining ? remaining->count : 0;
  int new_count = remaining_count + tail_count;

  if (remaining_count > 0) {
    memcpy(dst->items, remaining->items,
           (size_t)remaining_count * sizeof(*dst->items));
    remaining->count = 0;
  }
  if (tail_count > 0) {
    memmove(dst->items + remaining_count, dst->items + copied_count,
            (size_t)tail_count * sizeof(*dst->items));
  }
  dst->count = new_count;
  return 0;
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

int wamble_intents_append_buffer(struct WambleIntentBuffer *dst,
                                 struct WambleIntentBuffer *src) {
  if (!dst || !src || src->count <= 0)
    return 0;
  intents_ensure(dst, src->count);
  if (dst->capacity - dst->count < src->count)
    return -1;
  memcpy(&dst->items[dst->count], src->items,
         (size_t)src->count * sizeof(*src->items));
  dst->count += src->count;
  src->count = 0;
  return 0;
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

void wamble_emit_assign_session_treatment(const uint8_t *token,
                                          const char *profile_name) {
  if (!token)
    return;
  db_invalidate_treatment_action_cache();
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_ASSIGN_SESSION_TREATMENT;
  memcpy(it.as.assign_session_treatment.token, token, TOKEN_LENGTH);
  intent_copy_str(it.as.assign_session_treatment.profile_name,
                  sizeof(it.as.assign_session_treatment.profile_name),
                  profile_name);
  intents_push(it);
}

void wamble_emit_record_profile_terms_acceptance(
    const uint8_t *token, const char *profile_name,
    const uint8_t tos_hash[WAMBLE_FRAGMENT_HASH_LENGTH], const char *tos_text) {
  if (!token || !tos_hash || !tos_text)
    return;
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_RECORD_PROFILE_TERMS_ACCEPTANCE;
  memcpy(it.as.record_profile_terms_acceptance.token, token, TOKEN_LENGTH);
  memcpy(it.as.record_profile_terms_acceptance.tos_hash, tos_hash,
         WAMBLE_FRAGMENT_HASH_LENGTH);
  intent_copy_str(it.as.record_profile_terms_acceptance.profile_name,
                  sizeof(it.as.record_profile_terms_acceptance.profile_name),
                  profile_name);
  intent_copy_str(it.as.record_profile_terms_acceptance.tos_text,
                  sizeof(it.as.record_profile_terms_acceptance.tos_text),
                  tos_text);
  intents_push(it);
}

void wamble_emit_record_prediction(uint64_t board_id, const uint8_t *token,
                                   uint64_t parent_prediction_id,
                                   const char *predicted_move_uci,
                                   int move_number, int correct_streak) {
  if (board_id == 0 || !token || !predicted_move_uci || move_number <= 0)
    return;
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_RECORD_PREDICTION;
  it.as.record_prediction.board_id = board_id;
  it.as.record_prediction.parent_id = parent_prediction_id;
  memcpy(it.as.record_prediction.token, token, TOKEN_LENGTH);
  intent_copy_str(it.as.record_prediction.predicted_move_uci,
                  sizeof(it.as.record_prediction.predicted_move_uci),
                  predicted_move_uci);
  it.as.record_prediction.move_number = move_number;
  it.as.record_prediction.correct_streak = correct_streak;
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

void wamble_emit_record_last_move_shown(uint64_t board_id, const uint8_t *token,
                                        const char *shown_uci) {
  if (board_id == 0 || !token || !shown_uci || !shown_uci[0])
    return;
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_RECORD_LAST_MOVE_SHOWN;
  it.as.record_last_move_shown.board_id = board_id;
  memcpy(it.as.record_last_move_shown.token, token, TOKEN_LENGTH);
  intent_copy_str(it.as.record_last_move_shown.shown_uci,
                  sizeof(it.as.record_last_move_shown.shown_uci), shown_uci);
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

void wamble_emit_record_payout_with_canonical(uint64_t board_id,
                                              const uint8_t *token,
                                              double points,
                                              double canonical_points);

void wamble_emit_record_payout(uint64_t board_id, const uint8_t *token,
                               double points) {
  wamble_emit_record_payout_with_canonical(board_id, token, points, points);
}

void wamble_emit_record_payout_with_canonical(uint64_t board_id,
                                              const uint8_t *token,
                                              double points,
                                              double canonical_points) {
  if (!token || (points == 0.0 && canonical_points == 0.0))
    return;
  struct WamblePersistenceIntent it = {0};
  it.type = WAMBLE_INTENT_RECORD_PAYOUT;
  it.as.record_payout.board_id = board_id;
  memcpy(it.as.record_payout.token, token, TOKEN_LENGTH);
  it.as.record_payout.points = points;
  it.as.record_payout.canonical_points = canonical_points;
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

void wamble_persist_board_created(uint64_t board_id, const char *fen,
                                  int mode_variant_id) {
  wamble_emit_create_board(board_id, fen, "DORMANT", mode_variant_id);
}

void wamble_persist_board_mark_dormant(uint64_t board_id, const char *fen) {
  wamble_emit_update_board(board_id, fen, "DORMANT");
}

void wamble_persist_board_reservation_created(uint64_t board_id,
                                              const uint8_t *token,
                                              int timeout_seconds,
                                              bool reserved_for_white) {
  wamble_emit_create_reservation(board_id, token, timeout_seconds,
                                 reserved_for_white);
}

void wamble_persist_board_last_mover_snapshot(uint64_t board_id,
                                              const char *group_key) {
  wamble_emit_update_board_move_meta(board_id, group_key);
}

void wamble_persist_board_reserved(uint64_t board_id, const char *fen,
                                   const uint8_t *token, int timeout_seconds,
                                   bool reserved_for_white,
                                   time_t reservation_time,
                                   bool create_reservation) {
  wamble_emit_update_board(board_id, fen, "RESERVED");
  wamble_emit_update_board_assignment_time(board_id);
  wamble_emit_update_board_reservation_meta(board_id, reservation_time,
                                            reserved_for_white);
  if (create_reservation)
    wamble_emit_create_reservation(board_id, token, timeout_seconds,
                                   reserved_for_white);
}

void wamble_persist_board_activated(uint64_t board_id, const char *fen,
                                    const char *last_mover_group) {
  wamble_emit_update_board(board_id, fen, "ACTIVE");
  wamble_emit_update_board_move_meta(board_id, last_mover_group);
  wamble_emit_remove_reservation(board_id);
  wamble_emit_update_board_reservation_meta(board_id, 0, false);
}

void wamble_persist_board_reservation_released(uint64_t board_id,
                                               const char *fen) {
  wamble_emit_update_board(board_id, fen, "DORMANT");
  wamble_emit_remove_reservation(board_id);
  wamble_emit_update_board_reservation_meta(board_id, 0, false);
}

void wamble_persist_board_archived_result(uint64_t board_id, const char *fen,
                                          char winning_side, int move_count,
                                          int duration_seconds,
                                          const char *termination_reason) {
  wamble_emit_update_board(board_id, fen, "ARCHIVED");
  wamble_emit_record_game_result(board_id, winning_side, move_count,
                                 duration_seconds, termination_reason);
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
    return db_apply_update_board(it->as.update_board.board_id,
                                 it->as.update_board.fen,
                                 it->as.update_board.status);
  case WAMBLE_INTENT_UPDATE_BOARD_ASSIGNMENT_TIME:
    return db_apply_update_board_assignment_time(
        it->as.update_board_assignment_time.board_id);
  case WAMBLE_INTENT_CREATE_RESERVATION: {
    uint64_t sid = 0;
    DbStatus st =
        resolve_session_id_cached(cache, it->as.create_reservation.token, &sid);
    if (st != DB_OK || sid == 0)
      return -1;
    return db_apply_create_reservation(
        it->as.create_reservation.board_id, sid,
        it->as.create_reservation.timeout_seconds,
        it->as.create_reservation.reserved_for_white);
  }
  case WAMBLE_INTENT_REMOVE_RESERVATION:
    return db_apply_remove_reservation(it->as.remove_reservation.board_id);
  case WAMBLE_INTENT_RECORD_GAME_RESULT:
    return db_apply_record_game_result(
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
      return -1;
    return db_apply_update_session_last_seen(sid);
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
    return db_apply_link_session_to_pubkey(
        sid, it->as.link_session_to_pubkey.public_key);
  }
  case WAMBLE_INTENT_UNLINK_SESSION_IDENTITY: {
    uint64_t sid = 0;
    if (resolve_session_id_cached(cache, it->as.unlink_session_identity.token,
                                  &sid) != DB_OK ||
        sid == 0)
      return -1;
    return db_apply_unlink_session_identity(sid);
  }
  case WAMBLE_INTENT_RECORD_PAYOUT: {
    uint64_t sid = 0;
    DbStatus st =
        resolve_session_id_cached(cache, it->as.record_payout.token, &sid);
    if (st != DB_OK || sid == 0)
      return -1;
    return db_apply_record_payout_with_canonical(
        it->as.record_payout.board_id, sid, it->as.record_payout.points,
        it->as.record_payout.canonical_points);
  }
  case WAMBLE_INTENT_UPDATE_PLAYER_RATING: {
    uint64_t sid = 0;
    DbStatus st = resolve_session_id_cached(
        cache, it->as.update_player_rating.token, &sid);
    if (st != DB_OK || sid == 0)
      return -1;
    return db_apply_update_player_rating(sid,
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
      return -1;
    return db_apply_record_move(it->as.record_move.board_id, sid,
                                it->as.record_move.move_uci,
                                it->as.record_move.move_number);
  }
  case WAMBLE_INTENT_UPDATE_BOARD_MOVE_META:
    return db_apply_update_board_move_meta(
        it->as.update_board_move_meta.board_id,
        it->as.update_board_move_meta.last_mover_treatment_group);
  case WAMBLE_INTENT_UPDATE_BOARD_RESERVATION_META:
    return db_apply_update_board_reservation_meta(
        it->as.update_board_reservation_meta.board_id,
        it->as.update_board_reservation_meta.reservation_time,
        it->as.update_board_reservation_meta.reserved_for_white);
  case WAMBLE_INTENT_RECORD_PREDICTION: {
    uint64_t sid = 0;
    DbStatus st =
        resolve_session_id_cached(cache, it->as.record_prediction.token, &sid);
    if (st != DB_OK || sid == 0)
      return -1;
    return db_apply_create_prediction(
        it->as.record_prediction.board_id, sid,
        it->as.record_prediction.parent_id,
        it->as.record_prediction.predicted_move_uci,
        it->as.record_prediction.move_number,
        it->as.record_prediction.correct_streak);
  }
  case WAMBLE_INTENT_RECORD_PROFILE_TERMS_ACCEPTANCE: {
    uint64_t acceptance_id = 0;
    DbStatus st = db_record_profile_terms_acceptance(
        it->as.record_profile_terms_acceptance.token,
        it->as.record_profile_terms_acceptance.profile_name,
        it->as.record_profile_terms_acceptance.tos_hash,
        it->as.record_profile_terms_acceptance.tos_text, &acceptance_id);
    return st == DB_OK ? 0 : -1;
  }
  case WAMBLE_INTENT_ASSIGN_SESSION_TREATMENT:
    return db_assign_session_treatment(
               it->as.assign_session_treatment.token,
               it->as.assign_session_treatment.profile_name, NULL, 0,
               NULL) == DB_OK
               ? 0
               : -1;
  case WAMBLE_INTENT_RESOLVE_PREDICTION: {
    uint64_t sid = 0;
    DbStatus st =
        resolve_session_id_cached(cache, it->as.resolve_prediction.token, &sid);
    if (st != DB_OK || sid == 0)
      return -1;
    return db_apply_resolve_prediction(
        it->as.resolve_prediction.board_id, sid,
        it->as.resolve_prediction.move_number, it->as.resolve_prediction.status,
        it->as.resolve_prediction.points_awarded);
  }
  case WAMBLE_INTENT_RECORD_LAST_MOVE_SHOWN: {
    uint64_t sid = 0;
    DbStatus st = resolve_session_id_cached(
        cache, it->as.record_last_move_shown.token, &sid);
    if (st != DB_OK || sid == 0)
      return -1;
    return db_apply_record_last_move_shown(
        it->as.record_last_move_shown.board_id, sid,
        it->as.record_last_move_shown.shown_uci);
  }
  default:
    return -1;
  }
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
  case WAMBLE_INTENT_RECORD_LAST_MOVE_SHOWN:
    return 8 + TOKEN_LENGTH + MAX_UCI_LENGTH;
  case WAMBLE_INTENT_RECORD_PROFILE_TERMS_ACCEPTANCE:
    return TOKEN_LENGTH + 128 + WAMBLE_FRAGMENT_HASH_LENGTH + FEN_MAX_LENGTH;
  case WAMBLE_INTENT_ASSIGN_SESSION_TREATMENT:
    return TOKEN_LENGTH + 128;
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

  int failures = 0;
  int write_idx = 0;
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

  for (int i = 0; i < to_apply; i++) {
    struct WamblePersistenceIntent *it = &buf->items[i];
    if (apply_one_intent_db(it, &session_cache) < 0) {
      failures = 1;
      int pending = to_apply - i;
      memmove(&buf->items[write_idx], it,
              (size_t)pending * sizeof(*buf->items));
      write_idx += pending;
      break;
    }
  }
  free(session_cache_items);

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

int wamble_persistence_flush_buffer(struct WambleIntentBuffer *buf,
                                    const WambleQueryService *qs,
                                    int max_batches, int max_intents,
                                    int max_payload_bytes) {
  if (!buf || max_batches <= 0)
    return 1;
  wamble_set_query_service(qs);
  wamble_set_intent_buffer(buf);
  for (int i = 0; i < max_batches && buf->count > 0; i++) {
    int attempted = 0;
    int failures = 0;
    wamble_persistence_clear_status();
    PersistenceStatus st = wamble_apply_intents_with_db_checked(
        buf, max_intents, max_payload_bytes, NULL, &attempted, &failures);
    if (st == PERSISTENCE_STATUS_OK || st == PERSISTENCE_STATUS_EMPTY) {
      if (attempted > 0)
        continue;
      break;
    }
    if (attempted <= 0 || failures > 0 || st == PERSISTENCE_STATUS_APPLY_FAIL)
      break;
  }
  return buf->count <= 0;
}
