#include "common/wamble_test.h"
#include "common/wamble_test_helpers.h"
#include "wamble/wamble.h"
#include "wamble/wamble_db.h"
#include <math.h>
#include <string.h>

static int nearly_equal(double a, double b) { return fabs(a - b) < 0.001; }

static int g_allow_submit = 1;
static int g_allow_read = 1;
static int g_read_depth_cap = 2;

static DbStatus mock_prediction_policy(const uint8_t *token,
                                       const char *profile, const char *action,
                                       const char *resource,
                                       const char *context_key,
                                       const char *context_value,
                                       WamblePolicyDecision *out) {
  (void)token;
  (void)profile;
  (void)context_key;
  (void)context_value;
  if (!out || !action || !resource)
    return DB_ERR_BAD_DATA;
  memset(out, 0, sizeof(*out));
  snprintf(out->action, sizeof(out->action), "%s", action);
  snprintf(out->resource, sizeof(out->resource), "%s", resource);
  snprintf(out->effect, sizeof(out->effect), "deny");

  if (strcmp(action, "prediction.submit") == 0) {
    out->allowed = g_allow_submit;
    out->rule_id = 1;
    snprintf(out->effect, sizeof(out->effect), "%s",
             g_allow_submit ? "allow" : "deny");
    return DB_OK;
  }
  if (strcmp(action, "prediction.read") == 0) {
    out->allowed = g_allow_read;
    out->permission_level = g_read_depth_cap;
    out->rule_id = 2;
    snprintf(out->effect, sizeof(out->effect), "%s",
             g_allow_read ? "allow" : "deny");
    return DB_OK;
  }
  out->allowed = 1;
  out->rule_id = 3;
  snprintf(out->effect, sizeof(out->effect), "%s", "allow");
  return DB_OK;
}

static void install_prediction_policy(void) {
  static WambleQueryService svc;
  memset(&svc, 0, sizeof(svc));
  svc.resolve_policy_decision = mock_prediction_policy;
  wamble_set_query_service(&svc);
}

static int write_prediction_config(char *out_path, size_t out_path_size,
                                   const char *extra) {
  if (wamble_test_path(out_path, out_path_size, "prediction",
                       "prediction.conf") != 0) {
    return -1;
  }
  FILE *f = fopen(out_path, "w");
  if (!f)
    return -1;
  fputs(extra ? extra : "", f);
  fclose(f);
  return 0;
}

static int setup_prediction_env(const char *extra_cfg) {
  char path[512];
  char status[128];
  if (write_prediction_config(path, sizeof(path), extra_cfg) != 0)
    return -1;
  if (config_load(path, NULL, status, sizeof(status)) < 0)
    return -1;
  player_manager_init();
  board_manager_init();
  prediction_manager_init();
  install_prediction_policy();
  g_allow_submit = 1;
  g_allow_read = 1;
  g_read_depth_cap = 2;
  return 0;
}

static void reserve_for_current_turn(WambleBoard *board, WamblePlayer *player) {
  memcpy(board->reservation_player_token, player->token, TOKEN_LENGTH);
  board->reserved_for_white = (board->board.turn == 'w');
}

WAMBLE_TEST(prediction_config_loads_prediction_options) {
  T_ASSERT_EQ_INT(
      setup_prediction_env("(def prediction-mode 2)\n"
                           "(def prediction-base-points 1.5)\n"
                           "(def prediction-streak-multiplier 3.0)\n"
                           "(def prediction-streak-cap 7)\n"
                           "(def prediction-gated-percent 42)\n"
                           "(def prediction-penalty-incorrect 0.25)\n"
                           "(def prediction-match-policy \"from-to-only\")\n"
                           "(def prediction-view-depth-limit 4)\n"
                           "(def prediction-max-pending 9)\n"),
      0);

  const WambleConfig *cfg = get_config();
  T_ASSERT(cfg != NULL);
  T_ASSERT_EQ_INT(cfg->prediction_mode, 2);
  T_ASSERT(nearly_equal(cfg->prediction_base_points, 1.5));
  T_ASSERT(nearly_equal(cfg->prediction_streak_multiplier, 3.0));
  T_ASSERT_EQ_INT(cfg->prediction_streak_cap, 7);
  T_ASSERT_EQ_INT(cfg->prediction_gated_percent, 42);
  T_ASSERT(nearly_equal(cfg->prediction_penalty_incorrect, 0.25));
  T_ASSERT(strcmp(cfg->prediction_match_policy, "from-to-only") == 0);
  T_ASSERT_EQ_INT(cfg->prediction_view_depth_limit, 4);
  T_ASSERT_EQ_INT(cfg->prediction_max_pending, 9);
  return 0;
}

WAMBLE_TEST(prediction_submit_uses_policy_dsl) {
  T_ASSERT_EQ_INT(setup_prediction_env("(def prediction-mode 2)\n"), 0);
  WamblePlayer *p = create_new_player();
  T_ASSERT(p != NULL);
  WambleBoard *b = find_board_for_player(p);
  T_ASSERT(b != NULL);
  reserve_for_current_turn(b, p);

  g_allow_submit = 0;
  T_ASSERT_EQ_INT(prediction_submit(b, p->token, "e2e4", 0),
                  PREDICTION_ERR_NOT_ALLOWED);

  g_allow_submit = 1;
  T_ASSERT_EQ_INT(prediction_submit(b, p->token, "e2e4", 0), PREDICTION_OK);
  return 0;
}

WAMBLE_TEST(prediction_scoring_is_separate_from_main_score) {
  T_ASSERT_EQ_INT(setup_prediction_env("(def prediction-mode 1)\n"
                                       "(def prediction-base-points 3.5)\n"),
                  0);

  WamblePlayer *p = create_new_player();
  T_ASSERT(p != NULL);
  WambleBoard *b = find_board_for_player(p);
  T_ASSERT(b != NULL);
  reserve_for_current_turn(b, p);

  T_ASSERT_EQ_INT(prediction_submit(b, p->token, "e2e4", 0), PREDICTION_OK);
  T_ASSERT_STATUS_OK(validate_and_apply_move_status(b, p, "e2e4", NULL));
  T_ASSERT_EQ_INT(prediction_resolve_move(b, "e2e4"), PREDICTION_OK);
  T_ASSERT(nearly_equal(p->score, 0.0));
  T_ASSERT(nearly_equal(p->prediction_score, 3.5));
  return 0;
}

WAMBLE_TEST(prediction_tree_respects_policy_depth_cap) {
  T_ASSERT_EQ_INT(setup_prediction_env("(def prediction-mode 2)\n"
                                       "(def prediction-view-depth-limit 8)\n"),
                  0);

  WamblePlayer *p = create_new_player();
  T_ASSERT(p != NULL);
  WambleBoard *b = find_board_for_player(p);
  T_ASSERT(b != NULL);
  reserve_for_current_turn(b, p);

  uint64_t root_id = 0;
  uint64_t child_id = 0;
  T_ASSERT_EQ_INT(
      prediction_submit_with_parent(b, p->token, "e2e4", 0, 0, &root_id),
      PREDICTION_OK);
  T_ASSERT(root_id > 0);
  T_ASSERT_EQ_INT(
      prediction_submit_with_parent(b, p->token, "e7e5", root_id, 0, &child_id),
      PREDICTION_ERR_DUPLICATE);

  prediction_clear_board(b->id);
  T_ASSERT_EQ_INT(
      prediction_submit_with_parent(b, p->token, "e2e4", 0, 0, &root_id),
      PREDICTION_OK);
  memcpy(b->reservation_player_token, p->token, TOKEN_LENGTH);
  T_ASSERT_STATUS_OK(validate_and_apply_move_status(b, p, "e2e4", NULL));
  T_ASSERT_EQ_INT(prediction_resolve_move(b, "e2e4"), PREDICTION_OK);

  T_ASSERT_EQ_INT(
      prediction_submit_with_parent(b, p->token, "e7e5", root_id, 0, &child_id),
      PREDICTION_OK);

  WamblePredictionView rows[8];
  int count = 0;
  g_read_depth_cap = 0;
  T_ASSERT_EQ_INT(
      prediction_collect_tree(b->id, p->token, 0, 7, rows, 8, &count),
      PREDICTION_OK);
  T_ASSERT_EQ_INT(count, 1);
  T_ASSERT_EQ_INT(rows[0].depth, 0);

  g_read_depth_cap = 2;
  T_ASSERT_EQ_INT(
      prediction_collect_tree(b->id, p->token, 0, 7, rows, 8, &count),
      PREDICTION_OK);
  T_ASSERT_EQ_INT(count, 2);
  return 0;
}

WAMBLE_TEST(prediction_gated_mode_still_checks_mode_policy) {
  T_ASSERT_EQ_INT(setup_prediction_env("(def prediction-mode 3)\n"
                                       "(def prediction-gated-percent 100)\n"),
                  0);

  WamblePlayer *p = create_new_player();
  T_ASSERT(p != NULL);
  WambleBoard *b = find_board_for_player(p);
  T_ASSERT(b != NULL);
  reserve_for_current_turn(b, p);

  g_allow_submit = 0;
  T_ASSERT_EQ_INT(prediction_submit(b, p->token, "e2e4", 0),
                  PREDICTION_ERR_NOT_ALLOWED);
  g_allow_submit = 1;
  T_ASSERT_EQ_INT(prediction_submit(b, p->token, "e2e4", 0), PREDICTION_OK);
  return 0;
}

WAMBLE_TESTS_BEGIN_NAMED(prediction_tests) {
  WAMBLE_TESTS_ADD_FM(prediction_config_loads_prediction_options, "prediction");
  WAMBLE_TESTS_ADD_FM(prediction_submit_uses_policy_dsl, "prediction");
  WAMBLE_TESTS_ADD_FM(prediction_scoring_is_separate_from_main_score,
                      "prediction");
  WAMBLE_TESTS_ADD_FM(prediction_tree_respects_policy_depth_cap, "prediction");
  WAMBLE_TESTS_ADD_FM(prediction_gated_mode_still_checks_mode_policy,
                      "prediction");
}
WAMBLE_TESTS_END()
