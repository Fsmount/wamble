#ifndef WAMBLE_DB_H
#define WAMBLE_DB_H

#include "../include/wamble/wamble.h"

struct WambleQueryService;
int db_init(const char *connection_string);
int db_set_global_store_connection(const char *connection_string);
int db_format_connection_string(const WambleConfig *cfg, int global_store,
                                char *out, size_t out_len);
void db_invalidate_treatment_action_cache(void);
int db_validate_global_policy(void);
int db_store_config_snapshot(const char *profile_key, const char *config_text);
int db_load_config_snapshot(const char *profile_key, char **out_config_text);
int db_record_config_event(const char *profile_key, const char *config_text,
                           const char *source, const char *result,
                           const char *error_text);
void db_cleanup(void);
void db_tick(void);
typedef int (*WambleDbBoundaryCheckFn)(const char *operation);
void wamble_set_db_boundary_check_for_tests(WambleDbBoundaryCheckFn fn);
int db_write_batch_begin(void);
int db_write_batch_commit(void);
void db_write_batch_rollback(void);

uint64_t db_create_session(const uint8_t *token, uint64_t player_id);
DbStatus db_record_profile_terms_acceptance(
    const uint8_t *token, const char *profile_name,
    const uint8_t tos_hash[WAMBLE_FRAGMENT_HASH_LENGTH], const char *tos_text,
    uint64_t *out_acceptance_id);
DbStatus db_has_profile_terms_acceptance(
    const uint8_t *token, const char *profile_name,
    const uint8_t tos_hash[WAMBLE_FRAGMENT_HASH_LENGTH], int *out_accepted);
DbStatus
db_get_latest_profile_terms_acceptance(const uint8_t *token,
                                       const char *profile_name,
                                       WambleProfileTermsAcceptance *out);
DbStatus db_assign_session_treatment(const uint8_t *token, const char *profile,
                                     const WambleFact *facts, int fact_count,
                                     WambleTreatmentAssignment *out);
DbStatus db_get_session_treatment_assignment(const uint8_t *token,
                                             WambleTreatmentAssignment *out);
int db_apply_update_session_last_seen(uint64_t session_id);
int db_apply_link_session_to_pubkey(uint64_t session_id,
                                    const uint8_t *public_key);
int db_apply_unlink_session_identity(uint64_t session_id);

uint64_t db_create_board(const char *fen);
int db_insert_board(uint64_t board_id, const char *fen, const char *status);
int db_insert_board_mode_variant(uint64_t board_id, int mode_variant_id);
int db_apply_update_board(uint64_t board_id, const char *fen,
                          const char *status);
int db_apply_update_board_assignment_time(uint64_t board_id);
int db_apply_update_board_move_meta(uint64_t board_id,
                                    const char *last_mover_treatment_group);
int db_apply_record_last_move_shown(uint64_t board_id, uint64_t session_id,
                                    const char *shown_uci);
int db_apply_update_board_reservation_meta(uint64_t board_id,
                                           time_t reservation_time,
                                           int reserved_for_white);

int db_apply_record_move(uint64_t board_id, uint64_t session_id,
                         const char *move_uci, int move_number);
DbStatus db_create_prediction(uint64_t board_id, uint64_t session_id,
                              uint64_t parent_prediction_id,
                              const char *predicted_move_uci, int move_number,
                              int correct_streak, uint64_t *out_prediction_id);
int db_apply_create_prediction(uint64_t board_id, uint64_t session_id,
                               uint64_t parent_prediction_id,
                               const char *predicted_move_uci, int move_number,
                               int correct_streak);
int db_apply_resolve_prediction(uint64_t board_id, uint64_t session_id,
                                int move_number, const char *status,
                                double points_awarded);
DbPredictionsResult db_get_pending_predictions(void);

int db_apply_create_reservation(uint64_t board_id, uint64_t session_id,
                                int timeout_seconds, int reserved_for_white);
int db_apply_remove_reservation(uint64_t board_id);

int db_apply_record_game_result(uint64_t board_id, char winning_side,
                                int move_count, int duration_seconds,
                                const char *termination_reason);
int db_apply_record_payout(uint64_t board_id, uint64_t session_id,
                           double points);
int db_apply_record_payout_with_canonical(uint64_t board_id,
                                          uint64_t session_id,
                                          double points_awarded,
                                          double points_canonical);
int db_apply_update_player_rating(uint64_t session_id, double rating);

DbLeaderboardResult db_get_leaderboard(uint64_t requester_session_id,
                                       uint8_t leaderboard_type, int limit,
                                       int offset);

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
  DbStatus (*has_profile_terms_acceptance)(
      const uint8_t *token, const char *profile_name,
      const uint8_t tos_hash[WAMBLE_FRAGMENT_HASH_LENGTH], int *out_accepted);
  DbStatus (*has_profile_terms_acceptance_for_config)(
      const WambleConfig *cfg, const uint8_t *token, const char *profile_name,
      const uint8_t tos_hash[WAMBLE_FRAGMENT_HASH_LENGTH], int *out_accepted);
  DbStatus (*get_latest_profile_terms_acceptance)(
      const uint8_t *token, const char *profile_name,
      WambleProfileTermsAcceptance *out);
  DbStatus (*get_persistent_session_by_token)(const uint8_t *token,
                                              uint64_t *out_session);
  DbStatus (*get_player_total_score)(uint64_t session_id, double *out_total);
  DbStatus (*get_player_prediction_score)(uint64_t session_id,
                                          double *out_total);
  DbStatus (*get_player_rating)(uint64_t session_id, double *out_rating);
  DbStatus (*get_session_games_played)(uint64_t session_id, int *out_games);
  DbStatus (*get_session_chess960_games_played)(uint64_t session_id,
                                                int *out_games);
  DbStatus (*get_session_player_stats)(uint64_t session_id,
                                       WamblePersistentPlayerStats *out_stats);
  DbStatus (*get_identity_total_score)(uint64_t global_identity_id,
                                       double *out_total);
  DbStatus (*get_identity_games_played)(uint64_t global_identity_id,
                                        int *out_games);
  DbStatus (*get_identity_chess960_games_played)(uint64_t global_identity_id,
                                                 int *out_games);
  DbStatus (*get_identity_player_stats)(uint64_t global_identity_id,
                                        WamblePersistentPlayerStats *out_stats);
  DbStatus (*get_session_global_identity_id)(uint64_t session_id,
                                             uint64_t *out_identity_id);
  DbStatus (*get_identity_tags_csv)(uint64_t global_identity_id, char *out_csv,
                                    size_t out_csv_size);
  DbStatus (*get_identity_handle)(uint64_t global_identity_id, char *out_handle,
                                  size_t out_handle_size);
  DbStatus (*get_global_identity_id_by_handle)(const char *handle,
                                               uint64_t *out_identity_id);
  DbStatus (*get_session_public_key)(uint64_t session_id,
                                     uint8_t out_public_key[32],
                                     int *out_has_identity);
  DbStatus (*get_session_public_key_by_token)(const uint8_t *token,
                                              uint8_t out_public_key[32],
                                              int *out_has_identity);
  DbStatus (*get_latest_session_by_global_identity_id)(
      uint64_t global_identity_id, uint64_t *out_session_id);
  DbStatus (*get_latest_session_by_public_key)(
      const uint8_t public_key[WAMBLE_PUBLIC_KEY_LENGTH],
      uint64_t *out_session_id);
  DbStatus (*get_session_token_by_id)(uint64_t session_id,
                                      uint8_t out_token[TOKEN_LENGTH]);
  DbStatus (*get_session_treatment_group)(uint64_t session_id, char *out_group,
                                          size_t out_group_size);
  DbActiveReservationsResult (*get_active_reservations_by_public_key)(
      const uint8_t public_key[WAMBLE_PUBLIC_KEY_LENGTH]);
  DbActiveReservationsResult (
      *get_active_reservations_by_public_key_for_config)(
      const WambleConfig *cfg,
      const uint8_t public_key[WAMBLE_PUBLIC_KEY_LENGTH]);
  DbStatus (*get_persistent_player_stats)(
      const uint8_t *public_key, WamblePersistentPlayerStats *out_stats);
  DbLeaderboardResult (*get_leaderboard)(uint64_t requester_session_id,
                                         uint8_t leaderboard_type, int limit,
                                         int offset);
  DbMovesResult (*get_moves_for_board)(uint64_t board_id);
  DbPredictionsResult (*get_pending_predictions)(void);
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
void wamble_set_query_service(const WambleQueryService *svc);
const WambleQueryService *wamble_get_query_service(void);

#endif
