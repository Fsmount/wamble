#include "common/wamble_test.h"
#include "common/wamble_test_helpers.h"
#include "wamble/wamble.h"
#include "wamble/wamble_db.h"

WAMBLE_TEST(board_reservation_flow) {
  char msg[128];
  T_ASSERT_STATUS(config_load(NULL, NULL, msg, sizeof(msg)),
                  CONFIG_LOAD_DEFAULTS);
  player_manager_init();
  board_manager_init();

  WamblePlayer *p = create_new_player();
  T_ASSERT(p != NULL);

  WambleBoard *b = find_board_for_player(p);
  T_ASSERT(b != NULL);
  T_ASSERT(board_is_reserved_for_player(b->id, p->token));

  return 0;
}

WAMBLE_TEST(board_move_transitions_to_active) {
  char msg[128];
  T_ASSERT_STATUS(config_load(NULL, NULL, msg, sizeof(msg)),
                  CONFIG_LOAD_DEFAULTS);
  player_manager_init();
  board_manager_init();

  WamblePlayer *p = create_new_player();
  T_ASSERT(p != NULL);
  WambleBoard *b = find_board_for_player(p);
  T_ASSERT(b != NULL);

  board_move_played(b->id, NULL, NULL);
  WambleBoard *b2 = get_board_by_id(b->id);
  T_ASSERT(b2 != NULL);
  T_ASSERT_EQ_INT(b2->state, BOARD_STATE_ACTIVE);
  {
    ReservationReleaseNotification notice = {0};
    T_ASSERT_EQ_INT(board_collect_reservation_release_notifications(&notice, 1),
                    0);
  }
  return 0;
}

WAMBLE_TEST(board_release_cancels_reservation) {
  char msg[128];
  T_ASSERT_STATUS(config_load(NULL, NULL, msg, sizeof(msg)),
                  CONFIG_LOAD_DEFAULTS);
  player_manager_init();
  board_manager_init();

  WamblePlayer *p = create_new_player();
  T_ASSERT(p != NULL);
  WambleBoard *b = find_board_for_player(p);
  T_ASSERT(b != NULL);

  board_release_reservation(b->id);
  WambleBoard *b2 = get_board_by_id(b->id);
  T_ASSERT(b2 != NULL);
  T_ASSERT_EQ_INT(b2->state, BOARD_STATE_DORMANT);
  return 0;
}

WAMBLE_TEST(board_repeat_assignment_reuses_existing_reservation) {
  char msg[128];
  T_ASSERT_STATUS(config_load(NULL, NULL, msg, sizeof(msg)),
                  CONFIG_LOAD_DEFAULTS);
  player_manager_init();
  board_manager_init();

  WamblePlayer *p = create_new_player();
  T_ASSERT(p != NULL);
  WambleBoard *b1 = find_board_for_player(p);
  T_ASSERT(b1 != NULL);
  time_t reserved_at = b1->reservation_time;

  WambleBoard *b2 = find_board_for_player(p);
  T_ASSERT(b2 != NULL);
  T_ASSERT_EQ_INT((int)b2->id, (int)b1->id);
  T_ASSERT_EQ_INT((int)b2->reservation_time, (int)reserved_at);
  return 0;
}

WAMBLE_TEST(board_fill_active_reservation_for_token_reports_live_reservation) {
  char msg[128];
  T_ASSERT_STATUS(config_load(NULL, NULL, msg, sizeof(msg)),
                  CONFIG_LOAD_DEFAULTS);
  player_manager_init();
  board_manager_init();

  WamblePlayer *p = create_new_player();
  T_ASSERT(p != NULL);
  WambleBoard *b = find_board_for_player(p);
  T_ASSERT(b != NULL);

  DbActiveReservationEntry row = {0};
  T_ASSERT_EQ_INT(board_fill_active_reservation_for_token(p->token, &row), 1);
  T_ASSERT_EQ_INT((int)row.board_id, (int)b->id);
  T_ASSERT_EQ_INT((int)row.reserved_at, (int)b->reservation_time);
  T_ASSERT(row.expires_at > row.reserved_at);
  T_ASSERT_EQ_INT((int)row.available, 1);
  return 0;
}

WAMBLE_TEST(board_complete_archives) {
  char msg[128];
  T_ASSERT_STATUS(config_load(NULL, NULL, msg, sizeof(msg)),
                  CONFIG_LOAD_DEFAULTS);
  player_manager_init();
  board_manager_init();

  WamblePlayer *p = create_new_player();
  T_ASSERT(p != NULL);
  WambleBoard *b = find_board_for_player(p);
  T_ASSERT(b != NULL);

  b->result = GAME_RESULT_WHITE_WINS;
  board_game_completed(b->id, b->result);
  WambleBoard *b2 = get_board_by_id(b->id);
  T_ASSERT(b2 != NULL);
  T_ASSERT_EQ_INT(b2->state, BOARD_STATE_ARCHIVED);
  return 0;
}

WAMBLE_TEST(board_reservation_timeout_transitions_to_dormant) {
  char msg[128];
  T_ASSERT_STATUS(config_load(NULL, NULL, msg, sizeof(msg)),
                  CONFIG_LOAD_DEFAULTS);
  player_manager_init();
  board_manager_init();
  WamblePlayer *p = create_new_player();
  T_ASSERT(p != NULL);
  WambleBoard *b = find_board_for_player(p);
  T_ASSERT(b != NULL);
  T_ASSERT_EQ_INT(b->state, BOARD_STATE_RESERVED);

  b->reservation_time -= (get_config()->reservation_timeout + 1);
  board_manager_tick();
  WambleBoard *after = get_board_by_id(b->id);
  T_ASSERT(after != NULL);
  T_ASSERT_EQ_INT(after->state, BOARD_STATE_DORMANT);
  return 0;
}

WAMBLE_TEST(board_inactivity_timeout_transitions_to_dormant) {
  char msg[128];
  T_ASSERT_STATUS(config_load(NULL, NULL, msg, sizeof(msg)),
                  CONFIG_LOAD_DEFAULTS);
  player_manager_init();
  board_manager_init();
  WamblePlayer *p = create_new_player();
  T_ASSERT(p != NULL);
  WambleBoard *b = find_board_for_player(p);
  T_ASSERT(b != NULL);
  board_move_played(b->id, NULL, NULL);
  WambleBoard *active = get_board_by_id(b->id);
  T_ASSERT(active != NULL);
  T_ASSERT_EQ_INT(active->state, BOARD_STATE_ACTIVE);
  active->last_move_time -= (get_config()->inactivity_timeout + 1);
  board_manager_tick();
  WambleBoard *after = get_board_by_id(b->id);
  T_ASSERT(after != NULL);
  T_ASSERT_EQ_INT(after->state, BOARD_STATE_DORMANT);
  return 0;
}

WAMBLE_TEST(board_inactivity_dormant_enqueues_release_for_last_mover) {
  char msg[128];
  T_ASSERT_STATUS(config_load(NULL, NULL, msg, sizeof(msg)),
                  CONFIG_LOAD_DEFAULTS);
  player_manager_init();
  board_manager_init();
  WamblePlayer *p = create_new_player();
  T_ASSERT(p != NULL);
  uint8_t mover_token[TOKEN_LENGTH];
  memcpy(mover_token, p->token, TOKEN_LENGTH);
  WambleBoard *b = find_board_for_player(p);
  T_ASSERT(b != NULL);
  uint64_t board_id = b->id;

  board_move_played(b->id, mover_token, "e2e4");
  WambleBoard *active = get_board_by_id(board_id);
  T_ASSERT(active != NULL);
  T_ASSERT_EQ_INT(active->state, BOARD_STATE_ACTIVE);

  ReservationReleaseNotification drained[8];
  (void)board_collect_reservation_release_notifications(drained, 8);

  active->last_move_time -= (get_config()->inactivity_timeout + 1);
  board_manager_tick();
  WambleBoard *after = get_board_by_id(board_id);
  T_ASSERT(after != NULL);
  T_ASSERT_EQ_INT(after->state, BOARD_STATE_DORMANT);

  int n = board_collect_reservation_release_notifications(drained, 8);
  T_ASSERT_EQ_INT(n, 1);
  T_ASSERT(tokens_equal(drained[0].token, mover_token));
  T_ASSERT_EQ_INT((int)drained[0].board_id, (int)board_id);
  return 0;
}

static int board_manager_db_prepare(void) {
  char cfg_path[512];
  if (!wamble_db_available())
    return -1;
  if (test_db_apply_migrations(NULL) != 0)
    return -1;
  if (test_db_reset(NULL) != 0)
    return -1;
  if (wamble_test_path(cfg_path, sizeof(cfg_path), "board_manager",
                       "db_runtime.conf") != 0)
    return -1;
  if (wamble_test_write_db_config_file(cfg_path, "") != 0)
    return -1;
  if (config_load(cfg_path, NULL, NULL, 0) < 0)
    return -1;
  if (db_set_global_store_connection(NULL) != 0)
    return -1;
  if (db_init(NULL) != 0)
    return -1;
  return 0;
}

static int setup_experiment_pairing_db_test(const char *cfg_path,
                                            const char *cfg) {
  if (board_manager_db_prepare() != 0)
    return -1;
  if (wamble_test_write_optional_db_config_file(cfg_path, cfg) != 0)
    return -1;
  if (config_load(cfg_path, NULL, NULL, 0) != CONFIG_LOAD_OK)
    return -1;
  if (db_apply_config_treatment_rules("__default__") != DB_OK)
    return -1;
  player_manager_init();
  board_manager_init();
  return 0;
}

static int import_prior_move_boards_at_capacity(const char *last_mover_group) {
  int count = get_config()->max_boards;
  if (count <= 0)
    return -1;
  WambleBoard *boards = (WambleBoard *)calloc((size_t)count, sizeof(*boards));
  if (!boards)
    return -1;
  for (int i = 0; i < count; i++) {
    WambleBoard *board = &boards[i];
    board->id = (uint64_t)(200 + i);
    snprintf(board->fen, sizeof(board->fen), "%s",
             "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1");
    board->state = BOARD_STATE_ACTIVE;
    board->result = GAME_RESULT_IN_PROGRESS;
    board->last_move_time = wamble_now_wall();
    if (last_mover_group) {
      snprintf(board->last_mover_treatment_group,
               sizeof(board->last_mover_treatment_group), "%s",
               last_mover_group);
    }
  }
  int rc = board_manager_import(boards, count, (uint64_t)(200 + count));
  free(boards);
  return rc;
}

WAMBLE_TEST(board_pairing_fails_closed_when_current_assignment_missing) {
  const char *cfg_path = "build/test_board_pairing_missing_current.conf";
  const char *cfg = "(def max-players 1)\n"
                    "(def max-boards 1)\n"
                    "(def min-boards 0)\n"
                    "(def experiment-enabled 1)\n"
                    "(treatment-group \"control\" 10)\n"
                    "(treatment-group \"vip\" 20)\n"
                    "(treatment-default \"control\")\n"
                    "(treatment-assign \"*\" \"*\" \"control\" 50)\n"
                    "(treatment-edge \"control\" \"vip\")\n";
  T_ASSERT_EQ_INT(setup_experiment_pairing_db_test(cfg_path, cfg), 0);
  T_ASSERT_EQ_INT(get_config()->experiment_enabled, 1);
  T_ASSERT_EQ_INT(get_config()->max_boards, 1);
  T_ASSERT_EQ_INT(get_config()->min_boards, 0);

  WamblePlayer *p = create_new_player();
  T_ASSERT(p != NULL);
  T_ASSERT(db_create_session(p->token, 0) > 0);
  WambleTreatmentAssignment assignment = {0};
  T_ASSERT_STATUS(db_get_session_treatment_assignment(p->token, &assignment),
                  DB_NOT_FOUND);
  T_ASSERT_EQ_INT(import_prior_move_boards_at_capacity("vip"), 0);

  WambleBoard *chosen = find_board_for_player(p);
  T_ASSERT(chosen == NULL);
  return 0;
}

WAMBLE_TEST(board_pairing_fails_closed_when_prior_mover_group_missing) {
  const char *cfg_path = "build/test_board_pairing_missing_previous.conf";
  const char *cfg = "(def max-players 1)\n"
                    "(def max-boards 1)\n"
                    "(def min-boards 0)\n"
                    "(def experiment-enabled 1)\n"
                    "(treatment-group \"control\" 10)\n"
                    "(treatment-default \"control\")\n"
                    "(treatment-assign \"*\" \"*\" \"control\" 50)\n";
  T_ASSERT_EQ_INT(setup_experiment_pairing_db_test(cfg_path, cfg), 0);
  T_ASSERT_EQ_INT(get_config()->experiment_enabled, 1);
  T_ASSERT_EQ_INT(get_config()->max_boards, 1);
  T_ASSERT_EQ_INT(get_config()->min_boards, 0);

  WamblePlayer *p = create_new_player();
  T_ASSERT(p != NULL);
  T_ASSERT(db_create_session(p->token, 0) > 0);
  WambleTreatmentAction actions[1];
  int action_count = 0;
  T_ASSERT_STATUS(db_resolve_treatment_actions(p->token, "", "board.read", NULL,
                                               NULL, 0, actions, 1,
                                               &action_count),
                  DB_OK);
  WambleTreatmentAssignment assignment = {0};
  T_ASSERT_STATUS(db_get_session_treatment_assignment(p->token, &assignment),
                  DB_OK);
  T_ASSERT_STREQ(assignment.group_key, "control");
  T_ASSERT_EQ_INT(import_prior_move_boards_at_capacity(NULL), 0);
  WambleBoard *imported = get_board_by_id(200);
  T_ASSERT(imported != NULL);
  T_ASSERT_EQ_INT(imported->state, BOARD_STATE_ACTIVE);
  T_ASSERT(imported->last_move_time > 0);
  T_ASSERT_EQ_INT(imported->last_mover_treatment_group[0], '\0');

  WambleBoard *chosen = find_board_for_player(p);
  if (chosen)
    T_ASSERT((int)chosen->id != 200);
  T_ASSERT(!board_is_reserved_for_player(200, p->token));
  return 0;
}

WAMBLE_TEST(board_pairing_uses_persistent_treatment_without_live_network) {
  if (board_manager_db_prepare() != 0)
    T_FAIL_SIMPLE("board_manager_db_prepare failed");
  const char *cfg_path = "build/test_board_pairing_persistent_treatment.conf";
  const char *cfg = "(def max-players 2)\n"
                    "(def max-boards 2)\n"
                    "(def min-boards 0)\n"
                    "(def experiment-enabled 1)\n"
                    "(treatment-group \"control\" 10)\n"
                    "(treatment-group \"vip\" 20)\n"
                    "(treatment-default \"control\")\n"
                    "(treatment-assign \"*\" \"*\" \"control\" 50)\n"
                    "(treatment-edge \"vip\" \"control\")\n";
  T_ASSERT_EQ_INT(wamble_test_write_optional_db_config_file(cfg_path, cfg), 0);
  T_ASSERT_STATUS(config_load(cfg_path, NULL, NULL, 0), CONFIG_LOAD_OK);
  T_ASSERT_STATUS_OK(db_apply_config_treatment_rules("__default__"));

  player_manager_init();
  board_manager_init();
  WamblePlayer *p = create_new_player();
  T_ASSERT(p != NULL);
  T_ASSERT(db_create_session(p->token, 0) > 0);
  WambleTreatmentAction actions[1];
  int action_count = 0;
  T_ASSERT_STATUS(db_resolve_treatment_actions(p->token, "", "board.read", NULL,
                                               NULL, 0, actions, 1,
                                               &action_count),
                  DB_OK);
  WambleTreatmentAssignment assignment = {0};
  T_ASSERT_STATUS(db_get_session_treatment_assignment(p->token, &assignment),
                  DB_OK);
  T_ASSERT_STREQ(assignment.group_key, "control");

  WambleBoard boards[2];
  memset(boards, 0, sizeof(boards));
  boards[0].id = 100;
  snprintf(boards[0].fen, sizeof(boards[0].fen), "%s",
           "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1");
  boards[0].state = BOARD_STATE_ACTIVE;
  boards[0].result = GAME_RESULT_IN_PROGRESS;
  snprintf(boards[0].last_mover_treatment_group,
           sizeof(boards[0].last_mover_treatment_group), "%s", "vip");
  boards[1] = boards[0];
  boards[1].id = 101;
  boards[1].state = BOARD_STATE_DORMANT;
  boards[1].last_mover_treatment_group[0] = '\0';
  T_ASSERT_EQ_INT(board_manager_import(boards, 2, 102), 0);

  WambleBoard *chosen = find_board_for_player(p);
  T_ASSERT(chosen != NULL);
  T_ASSERT((int)chosen->id != 100);
  T_ASSERT(board_is_reserved_for_player(chosen->id, p->token));
  return 0;
}

WAMBLE_TESTS_BEGIN_NAMED(board_manager_tests) {
  WAMBLE_TESTS_ADD_FM(board_reservation_flow, "board_manager");
  WAMBLE_TESTS_ADD_FM(board_move_transitions_to_active, "board_manager");
  WAMBLE_TESTS_ADD_FM(board_release_cancels_reservation, "board_manager");
  WAMBLE_TESTS_ADD_FM(board_repeat_assignment_reuses_existing_reservation,
                      "board_manager");
  WAMBLE_TESTS_ADD_FM(
      board_fill_active_reservation_for_token_reports_live_reservation,
      "board_manager");
  WAMBLE_TESTS_ADD_FM(board_complete_archives, "board_manager");
  WAMBLE_TESTS_ADD_FM(board_reservation_timeout_transitions_to_dormant,
                      "board_manager");
  WAMBLE_TESTS_ADD_FM(board_inactivity_timeout_transitions_to_dormant,
                      "board_manager");
  WAMBLE_TESTS_ADD_FM(board_inactivity_dormant_enqueues_release_for_last_mover,
                      "board_manager");
  WAMBLE_TESTS_ADD_DB_FM(
      board_pairing_fails_closed_when_current_assignment_missing,
      "board_manager");
  WAMBLE_TESTS_ADD_DB_FM(
      board_pairing_fails_closed_when_prior_mover_group_missing,
      "board_manager");
  WAMBLE_TESTS_ADD_DB_FM(
      board_pairing_uses_persistent_treatment_without_live_network,
      "board_manager");
}
WAMBLE_TESTS_END()
