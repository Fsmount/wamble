#include "common/wamble_test.h"
#include "wamble/wamble.h"
#include "wamble/wamble_db.h"
#include <math.h>
#include <stdio.h>
#include <string.h>

static void prediction_test_token_hex(const uint8_t *token,
                                      char out[(TOKEN_LENGTH * 2) + 1]) {
  static const char *hex = "0123456789abcdef";
  for (int i = 0; i < TOKEN_LENGTH; i++) {
    out[i * 2] = hex[(token[i] >> 4) & 0x0f];
    out[i * 2 + 1] = hex[token[i] & 0x0f];
  }
  out[TOKEN_LENGTH * 2] = '\0';
}

static void prediction_test_fill_token(uint8_t token[TOKEN_LENGTH],
                                       uint8_t base) {
  for (int i = 0; i < TOKEN_LENGTH; i++)
    token[i] = (uint8_t)(base + i);
}

static int prediction_test_init_board(WambleBoard *board, uint64_t board_id,
                                      const char *fen) {
  memset(board, 0, sizeof(*board));
  board->id = board_id;
  snprintf(board->fen, sizeof(board->fen), "%s", fen);
  return parse_fen_to_bitboard(fen, &board->board);
}

static int prediction_test_store_board(WambleBoard *board, uint64_t board_id,
                                       const char *fen) {
  char sql[512];
  if (prediction_test_init_board(board, board_id, fen) != 0)
    return -1;
  snprintf(sql, sizeof(sql),
           "INSERT INTO boards (id, fen, status) "
           "VALUES (%llu, '%s', 'ACTIVE') "
           "ON CONFLICT (id) DO UPDATE SET fen = EXCLUDED.fen, "
           "status = EXCLUDED.status;",
           (unsigned long long)board_id, fen);
  return test_db_apply_sql(sql);
}

static int prediction_test_prepare_db_runtime(const char *cfg_path,
                                              const char *extra_sql) {
  const char *cfg = "(def prediction-mode 2)\n"
                    "(def prediction-view-depth-limit 4)\n";
  if (wamble_test_prepare_db(cfg_path, cfg, extra_sql) != 0)
    return -1;
  return prediction_manager_init() == PREDICTION_MANAGER_OK ? 0 : -1;
}

static void prediction_test_teardown(void) {
  db_cleanup();
  wamble_set_query_service(NULL);
}

static int prediction_test_find_row(const WamblePredictionView *rows, int count,
                                    uint64_t id) {
  for (int i = 0; i < count; i++) {
    if (rows[i].id == id)
      return i;
  }
  return -1;
}

static int prediction_test_find_pending_row(const DbPredictionRow *rows,
                                            int count, uint64_t id) {
  for (int i = 0; i < count; i++) {
    if (rows[i].id == id)
      return i;
  }
  return -1;
}

static int prediction_test_seed_session(const uint8_t *token) {
  char token_hex[(TOKEN_LENGTH * 2) + 1];
  char sql[512];
  prediction_test_token_hex(token, token_hex);
  snprintf(sql, sizeof(sql),
           "WITH gid AS ("
           "  INSERT INTO global_identities DEFAULT VALUES RETURNING id"
           ") "
           "INSERT INTO sessions (token, player_id, global_identity_id) "
           "SELECT decode('%s', 'hex'), NULL, id FROM gid;",
           token_hex);
  return test_db_apply_sql(sql);
}

WAMBLE_TEST(prediction_config_loads_prediction_options) {
  const char *cfg_path = "build/test_prediction_config.conf";
  FILE *f = fopen(cfg_path, "wb");
  T_ASSERT(f != NULL);
  fputs("(def prediction-mode 2)\n"
        "(def prediction-base-points 1.5)\n"
        "(def prediction-streak-multiplier 3.0)\n"
        "(def prediction-streak-cap 7)\n"
        "(def prediction-gated-percent 42)\n"
        "(def prediction-penalty-incorrect 0.25)\n"
        "(def prediction-match-policy \"from-to-only\")\n"
        "(def prediction-view-depth-limit 4)\n"
        "(def prediction-max-pending 9)\n",
        f);
  fclose(f);

  T_ASSERT_STATUS(config_load(cfg_path, NULL, NULL, 0), CONFIG_LOAD_OK);
  const WambleConfig *cfg = get_config();
  T_ASSERT(cfg != NULL);
  T_ASSERT_EQ_INT(cfg->prediction_mode, 2);
  T_ASSERT(fabs(cfg->prediction_base_points - 1.5) < 0.001);
  T_ASSERT(fabs(cfg->prediction_streak_multiplier - 3.0) < 0.001);
  T_ASSERT_EQ_INT(cfg->prediction_streak_cap, 7);
  T_ASSERT_EQ_INT(cfg->prediction_gated_percent, 42);
  T_ASSERT(fabs(cfg->prediction_penalty_incorrect - 0.25) < 0.001);
  T_ASSERT(strcmp(cfg->prediction_match_policy, "from-to-only") == 0);
  T_ASSERT_EQ_INT(cfg->prediction_view_depth_limit, 4);
  T_ASSERT_EQ_INT(cfg->prediction_max_pending, 9);
  return 0;
}

WAMBLE_TEST(prediction_tree_children_advance_target_ply) {
  const char *cfg_path = "build/test_prediction_tree_target_ply.conf";
  const char *sql =
      "INSERT INTO global_policy_rules "
      "(global_identity_id, action, resource, scope, effect, permission_level, "
      "reason, source) VALUES "
      "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test'), "
      "(0, 'prediction.write', 'streak', '*', 'allow', 4, 'write', 'test'), "
      "(0, 'prediction.read', 'tree', '*', 'allow', 4, 'read', 'test');";
  uint8_t root_token[TOKEN_LENGTH];
  uint8_t child_token[TOKEN_LENGTH];
  WambleBoard board;
  uint64_t root_id = 0;
  uint64_t child_id = 0;
  WamblePredictionView rows[16];
  int count = 0;
  int root_idx = -1;
  int child_idx = -1;

  if (prediction_test_prepare_db_runtime(cfg_path, sql) != 0)
    T_FAIL_SIMPLE("prediction_test_prepare_db_runtime failed");

  prediction_test_fill_token(root_token, 0x10);
  prediction_test_fill_token(child_token, 0x40);
  T_ASSERT_STATUS_OK(prediction_test_seed_session(root_token));
  T_ASSERT_STATUS_OK(prediction_test_seed_session(child_token));
  T_ASSERT_STATUS_OK(prediction_test_store_board(
      &board, 41, "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1"));

  T_ASSERT_EQ_INT(
      prediction_submit_with_parent(&board, root_token, "e2e4", 0, 0, &root_id),
      PREDICTION_OK);
  T_ASSERT(root_id > 0);
  T_ASSERT_EQ_INT(prediction_submit_with_parent(&board, child_token, "e7e5",
                                                root_id, 0, &child_id),
                  PREDICTION_OK);
  T_ASSERT(child_id > 0);

  T_ASSERT_EQ_INT(
      prediction_collect_tree(board.id, root_token, 0, 4, rows, 16, &count),
      PREDICTION_OK);
  T_ASSERT_EQ_INT(count, 2);
  root_idx = prediction_test_find_row(rows, count, root_id);
  child_idx = prediction_test_find_row(rows, count, child_id);
  T_ASSERT(root_idx >= 0);
  T_ASSERT(child_idx >= 0);
  T_ASSERT_EQ_INT(rows[root_idx].target_ply, 1);
  T_ASSERT_EQ_INT(rows[root_idx].depth, 0);
  T_ASSERT_EQ_INT((int)rows[child_idx].parent_id, (int)root_id);
  T_ASSERT_EQ_INT(rows[child_idx].target_ply, 2);
  T_ASSERT_EQ_INT(rows[child_idx].depth, 1);
  T_ASSERT_STREQ(rows[child_idx].status, "PENDING");

  T_ASSERT_STATUS_OK(prediction_test_init_board(
      &board, 41,
      "rnbqkbnr/pppppppp/8/8/4P3/8/PPPP1PPP/RNBQKBNR b KQkq - 0 1"));
  T_ASSERT_EQ_INT(prediction_resolve_move(&board, "e2e4"), PREDICTION_OK);

  T_ASSERT_EQ_INT(
      prediction_collect_tree(board.id, root_token, 0, 4, rows, 16, &count),
      PREDICTION_OK);
  root_idx = prediction_test_find_row(rows, count, root_id);
  child_idx = prediction_test_find_row(rows, count, child_id);
  T_ASSERT(root_idx >= 0);
  T_ASSERT(child_idx >= 0);
  T_ASSERT_STREQ(rows[root_idx].status, "CORRECT");
  T_ASSERT_STREQ(rows[child_idx].status, "PENDING");
  T_ASSERT_EQ_INT(rows[child_idx].target_ply, 2);

  T_ASSERT_STATUS_OK(prediction_test_init_board(
      &board, 41,
      "rnbqkbnr/pppp1ppp/8/4p3/4P3/8/PPPP1PPP/RNBQKBNR w KQkq e6 0 2"));
  T_ASSERT_EQ_INT(prediction_resolve_move(&board, "e7e5"), PREDICTION_OK);

  T_ASSERT_EQ_INT(
      prediction_collect_tree(board.id, root_token, 0, 4, rows, 16, &count),
      PREDICTION_OK);
  child_idx = prediction_test_find_row(rows, count, child_id);
  T_ASSERT(child_idx >= 0);
  T_ASSERT_STREQ(rows[child_idx].status, "CORRECT");
  return 0;
}

WAMBLE_TEST(prediction_incorrect_branch_expires_descendants) {
  const char *cfg_path = "build/test_prediction_tree_expire.conf";
  const char *sql =
      "INSERT INTO global_policy_rules "
      "(global_identity_id, action, resource, scope, effect, permission_level, "
      "reason, source) VALUES "
      "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test'), "
      "(0, 'prediction.write', 'streak', '*', 'allow', 4, 'write', 'test'), "
      "(0, 'prediction.read', 'tree', '*', 'allow', 4, 'read', 'test');";
  uint8_t root_token[TOKEN_LENGTH];
  uint8_t child_token[TOKEN_LENGTH];
  WambleBoard board;
  uint64_t root_id = 0;
  uint64_t child_id = 0;
  WamblePredictionView rows[16];
  int count = 0;
  int root_idx = -1;
  int child_idx = -1;

  if (prediction_test_prepare_db_runtime(cfg_path, sql) != 0)
    T_FAIL_SIMPLE("prediction_test_prepare_db_runtime failed");

  prediction_test_fill_token(root_token, 0x70);
  prediction_test_fill_token(child_token, 0xa0);
  T_ASSERT_STATUS_OK(prediction_test_seed_session(root_token));
  T_ASSERT_STATUS_OK(prediction_test_seed_session(child_token));
  T_ASSERT_STATUS_OK(prediction_test_store_board(
      &board, 42, "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1"));

  T_ASSERT_EQ_INT(
      prediction_submit_with_parent(&board, root_token, "d2d4", 0, 0, &root_id),
      PREDICTION_OK);
  T_ASSERT_EQ_INT(prediction_submit_with_parent(&board, child_token, "d7d5",
                                                root_id, 0, &child_id),
                  PREDICTION_OK);

  T_ASSERT_STATUS_OK(prediction_test_init_board(
      &board, 42,
      "rnbqkbnr/pppppppp/8/8/4P3/8/PPPP1PPP/RNBQKBNR b KQkq - 0 1"));
  T_ASSERT_EQ_INT(prediction_resolve_move(&board, "e2e4"), PREDICTION_OK);

  T_ASSERT_EQ_INT(
      prediction_collect_tree(board.id, root_token, 0, 4, rows, 16, &count),
      PREDICTION_OK);
  root_idx = prediction_test_find_row(rows, count, root_id);
  child_idx = prediction_test_find_row(rows, count, child_id);
  T_ASSERT(root_idx >= 0);
  T_ASSERT(child_idx >= 0);
  T_ASSERT_STREQ(rows[root_idx].status, "INCORRECT");
  T_ASSERT_STREQ(rows[child_idx].status, "EXPIRED");
  T_ASSERT_EQ_INT(rows[child_idx].target_ply, 2);
  return 0;
}

WAMBLE_TEST(prediction_write_allows_replies_without_read_access) {
  const char *cfg_path = "build/test_prediction_write_without_read.conf";
  const char *sql =
      "INSERT INTO global_policy_rules "
      "(global_identity_id, action, resource, scope, effect, permission_level, "
      "reason, source) VALUES "
      "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test'), "
      "(0, 'prediction.write', 'streak', '*', 'allow', 1, 'write', 'test');";
  uint8_t root_token[TOKEN_LENGTH];
  uint8_t child_token[TOKEN_LENGTH];
  WambleBoard board;
  uint64_t root_id = 0;
  uint64_t child_id = 0;
  WamblePredictionView rows[4];
  int count = 0;
  DbPredictionsResult pending = {0};
  int root_idx = -1;
  int child_idx = -1;

  if (prediction_test_prepare_db_runtime(cfg_path, sql) != 0)
    T_FAIL_SIMPLE("prediction_test_prepare_db_runtime failed");

  prediction_test_fill_token(root_token, 0x21);
  prediction_test_fill_token(child_token, 0x51);
  T_ASSERT_STATUS_OK(prediction_test_seed_session(root_token));
  T_ASSERT_STATUS_OK(prediction_test_seed_session(child_token));
  T_ASSERT_STATUS_OK(prediction_test_store_board(
      &board, 43, "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1"));

  T_ASSERT_EQ_INT(
      prediction_submit_with_parent(&board, root_token, "e2e4", 0, 0, &root_id),
      PREDICTION_OK);
  T_ASSERT(root_id > 0);
  T_ASSERT_EQ_INT(prediction_submit_with_parent(&board, child_token, "e7e5",
                                                root_id, 0, &child_id),
                  PREDICTION_OK);
  T_ASSERT(child_id > 0);

  T_ASSERT_EQ_INT(
      prediction_collect_tree(board.id, root_token, 0, 4, rows, 4, &count),
      PREDICTION_ERR_NOT_ALLOWED);
  T_ASSERT_EQ_INT(count, 0);

  pending = db_get_pending_predictions();
  T_ASSERT_STATUS(pending.status, DB_OK);
  T_ASSERT_EQ_INT(pending.count, 2);
  root_idx =
      prediction_test_find_pending_row(pending.rows, pending.count, root_id);
  child_idx =
      prediction_test_find_pending_row(pending.rows, pending.count, child_id);
  T_ASSERT(root_idx >= 0);
  T_ASSERT(child_idx >= 0);
  T_ASSERT_EQ_INT(pending.rows[root_idx].move_number, 1);
  T_ASSERT_EQ_INT(pending.rows[root_idx].depth, 0);
  T_ASSERT_EQ_INT((int)pending.rows[child_idx].parent_prediction_id,
                  (int)root_id);
  T_ASSERT_EQ_INT(pending.rows[child_idx].move_number, 2);
  T_ASSERT_EQ_INT(pending.rows[child_idx].depth, 1);
  return 0;
}

WAMBLE_TEST(prediction_write_depth_zero_blocks_child_reply) {
  const char *cfg_path = "build/test_prediction_write_root_only.conf";
  const char *sql =
      "INSERT INTO global_policy_rules "
      "(global_identity_id, action, resource, scope, effect, permission_level, "
      "reason, source) VALUES "
      "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'trust', 'test'), "
      "(0, 'prediction.write', 'streak', '*', 'allow', 0, 'write', 'test');";
  uint8_t root_token[TOKEN_LENGTH];
  uint8_t child_token[TOKEN_LENGTH];
  WambleBoard board;
  uint64_t root_id = 0;
  DbPredictionsResult pending = {0};
  int root_idx = -1;

  if (prediction_test_prepare_db_runtime(cfg_path, sql) != 0)
    T_FAIL_SIMPLE("prediction_test_prepare_db_runtime failed");

  prediction_test_fill_token(root_token, 0x61);
  prediction_test_fill_token(child_token, 0x91);
  T_ASSERT_STATUS_OK(prediction_test_seed_session(root_token));
  T_ASSERT_STATUS_OK(prediction_test_seed_session(child_token));
  T_ASSERT_STATUS_OK(prediction_test_store_board(
      &board, 44, "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1"));

  T_ASSERT_EQ_INT(
      prediction_submit_with_parent(&board, root_token, "d2d4", 0, 0, &root_id),
      PREDICTION_OK);
  T_ASSERT(root_id > 0);
  T_ASSERT_EQ_INT(prediction_submit_with_parent(&board, child_token, "d7d5",
                                                root_id, 0, NULL),
                  PREDICTION_ERR_NOT_ALLOWED);

  pending = db_get_pending_predictions();
  T_ASSERT_STATUS(pending.status, DB_OK);
  T_ASSERT_EQ_INT(pending.count, 1);
  root_idx =
      prediction_test_find_pending_row(pending.rows, pending.count, root_id);
  T_ASSERT(root_idx >= 0);
  T_ASSERT_EQ_INT(pending.rows[root_idx].move_number, 1);
  T_ASSERT_EQ_INT(pending.rows[root_idx].depth, 0);
  return 0;
}

WAMBLE_TESTS_BEGIN_NAMED(prediction_tests) {
  WAMBLE_TESTS_ADD_FM(prediction_config_loads_prediction_options, "prediction");
  WAMBLE_TESTS_ADD_DB_EX_SM(prediction_tree_children_advance_target_ply,
                            WAMBLE_SUITE_FUNCTIONAL, "prediction", NULL,
                            prediction_test_teardown, 0);
  WAMBLE_TESTS_ADD_DB_EX_SM(prediction_incorrect_branch_expires_descendants,
                            WAMBLE_SUITE_FUNCTIONAL, "prediction", NULL,
                            prediction_test_teardown, 0);
  WAMBLE_TESTS_ADD_DB_EX_SM(prediction_write_allows_replies_without_read_access,
                            WAMBLE_SUITE_FUNCTIONAL, "prediction", NULL,
                            prediction_test_teardown, 0);
  WAMBLE_TESTS_ADD_DB_EX_SM(prediction_write_depth_zero_blocks_child_reply,
                            WAMBLE_SUITE_FUNCTIONAL, "prediction", NULL,
                            prediction_test_teardown, 0);
}
WAMBLE_TESTS_END()
