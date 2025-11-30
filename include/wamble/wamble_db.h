#ifndef WAMBLE_DB_H
#define WAMBLE_DB_H

#include "../include/wamble/wamble.h"

struct WambleQueryService;

int db_init(const char *connection_string);
void db_cleanup(void);
void db_tick(void);

uint64_t db_create_session(const uint8_t *token, uint64_t player_id);
DbStatus db_get_session_by_token(const uint8_t *token, uint64_t *out_session);
DbStatus db_get_persistent_session_by_token(const uint8_t *token,
                                            uint64_t *out_session);
void db_async_update_session_last_seen(uint64_t session_id);

uint64_t db_create_board(const char *fen);
DbStatus db_get_max_board_id(uint64_t *out_max_id);
int db_insert_board(uint64_t board_id, const char *fen, const char *status);
int db_async_update_board(uint64_t board_id, const char *fen,
                          const char *status);
int db_async_update_board_assignment_time(uint64_t board_id);

DbBoardResult db_get_board(uint64_t board_id);
DbBoardIdList db_list_boards_by_status(const char *status);

int db_async_record_move(uint64_t board_id, uint64_t session_id,
                         const char *move_uci, int move_number);

DbMovesResult db_get_moves_for_board(uint64_t board_id);

int db_async_create_reservation(uint64_t board_id, uint64_t session_id,
                                int timeout_seconds);
void db_async_remove_reservation(uint64_t board_id);

int db_async_record_game_result(uint64_t board_id, char winning_side);
int db_async_record_payout(uint64_t board_id, uint64_t session_id,
                           double points);
DbStatus db_get_player_total_score(uint64_t session_id, double *out_total);
DbStatus db_get_player_rating(uint64_t session_id, double *out_rating);
int db_async_update_player_rating(uint64_t session_id, double rating);

DbStatus db_get_active_session_count(int *out_count);
DbStatus db_get_longest_game_moves(int *out_max_moves);
DbStatus db_get_session_games_played(uint64_t session_id, int *out_games);

uint64_t db_create_player(const uint8_t *public_key);
uint64_t db_get_player_by_public_key(const uint8_t *public_key);
int db_async_link_session_to_player(uint64_t session_id, uint64_t player_id);

void db_expire_reservations(void);

void db_cleanup_thread(void);

DbStatus db_get_trust_tier_by_token(const uint8_t *token, int *out_trust);

void db_archive_inactive_boards(int timeout_seconds);

typedef struct WambleQueryService {
  DbBoardIdList (*list_boards_by_status)(const char *status);
  DbBoardResult (*get_board)(uint64_t board_id);
  DbStatus (*get_longest_game_moves)(int *out_max_moves);
  DbStatus (*get_active_session_count)(int *out_count);
  DbStatus (*get_max_board_id)(uint64_t *out_max_id);
  DbStatus (*get_session_by_token)(const uint8_t *token, uint64_t *out_session);
  DbStatus (*get_persistent_session_by_token)(const uint8_t *token,
                                              uint64_t *out_session);
  DbStatus (*get_player_total_score)(uint64_t session_id, double *out_total);
  DbStatus (*get_player_rating)(uint64_t session_id, double *out_rating);
  DbStatus (*get_session_games_played)(uint64_t session_id, int *out_games);
  DbMovesResult (*get_moves_for_board)(uint64_t board_id);
  DbStatus (*get_trust_tier_by_token)(const uint8_t *token, int *out_trust);
} WambleQueryService;

const WambleQueryService *wamble_get_db_query_service(void);

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
    } create_board;
    struct {
      uint64_t board_id;
    } update_board_assignment_time;
    struct {
      uint64_t board_id;
      uint8_t token[TOKEN_LENGTH];
      int timeout_seconds;
    } create_reservation;
    struct {
      uint64_t board_id;
    } remove_reservation;
    struct {
      uint64_t board_id;
      char winning_side;
    } record_game_result;
    struct {
      uint8_t token[TOKEN_LENGTH];
    } update_session_last_seen;
    struct {
      uint8_t token[TOKEN_LENGTH];
      uint64_t player_id;
    } create_session;
    struct {
      uint8_t token[TOKEN_LENGTH];
      uint8_t public_key[32];
    } link_session_to_pubkey;
    struct {
      uint64_t board_id;
      uint8_t token[TOKEN_LENGTH];
      double points;
    } record_payout;
    struct {
      uint64_t board_id;
      uint8_t token[TOKEN_LENGTH];
      char move_uci[MAX_UCI_LENGTH];
      int move_number;
    } record_move;
  } as;
} WamblePersistenceIntent;

typedef struct WambleIntentBuffer {
  struct WamblePersistenceIntent *items;
  int count;
  int capacity;
} WambleIntentBuffer;

void wamble_set_query_service(const WambleQueryService *svc);
const WambleQueryService *wamble_get_query_service(void);

void wamble_set_intent_buffer(struct WambleIntentBuffer *buf);
struct WambleIntentBuffer *wamble_get_intent_buffer(void);

void wamble_intents_init(struct WambleIntentBuffer *buf);
void wamble_intents_free(struct WambleIntentBuffer *buf);
void wamble_intents_clear(struct WambleIntentBuffer *buf);

void wamble_persistence_clear_status(void);

PersistenceStatus
wamble_apply_intents_with_db_checked(struct WambleIntentBuffer *buf,
                                     int *out_failures);

#endif
