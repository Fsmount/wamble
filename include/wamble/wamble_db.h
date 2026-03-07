#ifndef WAMBLE_DB_H
#define WAMBLE_DB_H

#include "../include/wamble/wamble.h"

struct WambleQueryService;
int db_init(const char *connection_string);
int db_set_global_store_connection(const char *connection_string);
int db_validate_global_policy(void);
int db_store_config_snapshot(const char *profile_key, const char *config_text);
int db_load_config_snapshot(const char *profile_key, char **out_config_text);
int db_record_config_event(const char *profile_key, const char *config_text,
                           const char *source, const char *result,
                           const char *error_text);
void db_cleanup(void);
void db_tick(void);
int db_write_batch_begin(void);
int db_write_batch_commit(void);
void db_write_batch_rollback(void);

uint64_t db_create_session(const uint8_t *token, uint64_t player_id);
DbStatus db_assign_session_treatment(const uint8_t *token, const char *profile,
                                     const WambleFact *facts, int fact_count,
                                     WambleTreatmentAssignment *out);
DbStatus db_get_session_treatment_assignment(const uint8_t *token,
                                             WambleTreatmentAssignment *out);
void db_async_update_session_last_seen(uint64_t session_id);

uint64_t db_create_board(const char *fen);
int db_insert_board(uint64_t board_id, const char *fen, const char *status);
int db_async_update_board(uint64_t board_id, const char *fen,
                          const char *status);
int db_async_update_board_assignment_time(uint64_t board_id);
int db_async_update_board_move_meta(uint64_t board_id,
                                    const char *last_mover_treatment_group);
int db_async_update_board_reservation_meta(uint64_t board_id,
                                           time_t reservation_time,
                                           int reserved_for_white);

int db_async_record_move(uint64_t board_id, uint64_t session_id,
                         const char *move_uci, int move_number);
DbStatus db_create_prediction(uint64_t board_id, uint64_t session_id,
                              uint64_t parent_prediction_id,
                              const char *predicted_move_uci, int move_number,
                              int correct_streak, uint64_t *out_prediction_id);
int db_async_create_prediction(uint64_t board_id, uint64_t session_id,
                               uint64_t parent_prediction_id,
                               const char *predicted_move_uci, int move_number,
                               int correct_streak);
int db_async_resolve_prediction(uint64_t board_id, uint64_t session_id,
                                int move_number, const char *status,
                                double points_awarded);
DbPredictionsResult db_get_pending_predictions(void);

int db_async_create_reservation(uint64_t board_id, uint64_t session_id,
                                int timeout_seconds, int reserved_for_white);
void db_async_remove_reservation(uint64_t board_id);

int db_async_record_game_result(uint64_t board_id, char winning_side,
                                int move_count, int duration_seconds,
                                const char *termination_reason);
int db_async_record_payout(uint64_t board_id, uint64_t session_id,
                           double points);
int db_async_update_player_rating(uint64_t session_id, double rating);

DbLeaderboardResult db_get_leaderboard(uint64_t requester_session_id,
                                       uint8_t leaderboard_type, int limit);

void db_expire_reservations(void);

void db_cleanup_thread(void);

DbStatus db_resolve_policy_decision(const uint8_t *token, const char *profile,
                                    const char *action, const char *resource,
                                    const char *context_key,
                                    const char *context_value,
                                    WamblePolicyDecision *out);
int db_apply_config_policy_rules(const char *profile_key);
int db_validate_global_treatments(void);
int db_apply_config_treatment_rules(const char *profile_key);
DbStatus db_resolve_treatment_actions(const uint8_t *token, const char *profile,
                                      const char *hook_name,
                                      const char *opponent_group_key,
                                      const WambleFact *facts, int fact_count,
                                      WambleTreatmentAction *out, int max_out,
                                      int *out_count);
int db_treatment_edge_allows(const char *profile, const char *source_group_key,
                             const char *target_group_key);

void db_archive_inactive_boards(int timeout_seconds);

typedef struct WambleQueryService {
  DbBoardIdList (*list_boards_by_status)(const char *status);
  DbBoardResult (*get_board)(uint64_t board_id);
  DbStatus (*get_longest_game_moves)(int *out_max_moves);
  DbStatus (*get_active_session_count)(int *out_count);
  DbStatus (*get_max_board_id)(uint64_t *out_max_id);
  DbStatus (*get_session_by_token)(const uint8_t *token, uint64_t *out_session);
  uint64_t (*create_session)(const uint8_t *token, uint64_t player_id);
  DbStatus (*get_persistent_session_by_token)(const uint8_t *token,
                                              uint64_t *out_session);
  DbStatus (*get_player_total_score)(uint64_t session_id, double *out_total);
  DbStatus (*get_player_prediction_score)(uint64_t session_id,
                                          double *out_total);
  DbStatus (*get_player_rating)(uint64_t session_id, double *out_rating);
  DbStatus (*get_session_games_played)(uint64_t session_id, int *out_games);
  DbStatus (*get_persistent_player_stats)(
      const uint8_t *public_key, WamblePersistentPlayerStats *out_stats);
  DbLeaderboardResult (*get_leaderboard)(uint64_t requester_session_id,
                                         uint8_t leaderboard_type, int limit);
  DbMovesResult (*get_moves_for_board)(uint64_t board_id);
  DbPredictionsResult (*get_pending_predictions)(void);
  DbStatus (*create_prediction)(uint64_t board_id, uint64_t session_id,
                                uint64_t parent_prediction_id,
                                const char *predicted_move_uci, int move_number,
                                int correct_streak,
                                uint64_t *out_prediction_id);
  int (*link_session_to_pubkey)(uint64_t session_id, const uint8_t *public_key);
  int (*unlink_session_identity)(uint64_t session_id);
  DbStatus (*get_session_treatment_assignment)(const uint8_t *token,
                                               WambleTreatmentAssignment *out);
  DbStatus (*resolve_policy_decision)(const uint8_t *token, const char *profile,
                                      const char *action, const char *resource,
                                      const char *context_key,
                                      const char *context_value,
                                      WamblePolicyDecision *out);
  DbStatus (*resolve_treatment_actions)(
      const uint8_t *token, const char *profile, const char *hook_name,
      const char *opponent_group_key, const WambleFact *facts, int fact_count,
      WambleTreatmentAction *out, int max_out, int *out_count);
  int (*treatment_edge_allows)(const char *profile,
                               const char *source_group_key,
                               const char *target_group_key);
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
  WAMBLE_INTENT_UPDATE_BOARD_MOVE_META = 12,
  WAMBLE_INTENT_UPDATE_BOARD_RESERVATION_META = 13,
  WAMBLE_INTENT_RECORD_PREDICTION = 14,
  WAMBLE_INTENT_RESOLVE_PREDICTION = 15,
  WAMBLE_INTENT_UNLINK_SESSION_IDENTITY = 16,
  WAMBLE_INTENT_UPDATE_PLAYER_RATING = 17,
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
      uint64_t board_id;
      char last_mover_treatment_group[128];
    } update_board_move_meta;
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

void wamble_set_query_service(const WambleQueryService *svc);
const WambleQueryService *wamble_get_query_service(void);

void wamble_set_intent_buffer(struct WambleIntentBuffer *buf);

void wamble_intents_init(struct WambleIntentBuffer *buf);
void wamble_intents_free(struct WambleIntentBuffer *buf);
void wamble_intents_clear(struct WambleIntentBuffer *buf);

void wamble_persistence_clear_status(void);

PersistenceStatus wamble_apply_intents_with_db_checked(
    struct WambleIntentBuffer *buf, int max_intents, int max_payload_bytes,
    int *out_selected_bytes, int *out_attempted, int *out_failures);

#endif
