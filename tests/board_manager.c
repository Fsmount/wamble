#include "common/wamble_test.h"
#include "common/wamble_test_helpers.h"
#include "wamble/wamble.h"

static int setup_managers(void) {
  char msg[128];
  (void)config_load(NULL, NULL, msg, sizeof(msg));
  player_manager_init();
  board_manager_init();
  return 0;
}

WAMBLE_TEST(board_reservation_flow) {
  T_ASSERT_EQ_INT(setup_managers(), 0);

  WamblePlayer *p = create_new_player();
  T_ASSERT(p != NULL);

  WambleBoard *b = find_board_for_player(p);
  T_ASSERT(b != NULL);
  T_ASSERT(board_is_reserved_for_player(b->id, p->token));

  return 0;
}

WAMBLE_TEST(board_move_transitions_to_active) {
  T_ASSERT_EQ_INT(setup_managers(), 0);

  WamblePlayer *p = create_new_player();
  T_ASSERT(p != NULL);
  WambleBoard *b = find_board_for_player(p);
  T_ASSERT(b != NULL);

  board_move_played(b->id);
  WambleBoard *b2 = get_board_by_id(b->id);
  T_ASSERT(b2 != NULL);
  T_ASSERT_EQ_INT(b2->state, BOARD_STATE_ACTIVE);
  return 0;
}

WAMBLE_TEST(board_release_cancels_reservation) {
  T_ASSERT_EQ_INT(setup_managers(), 0);

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

WAMBLE_TEST(board_complete_archives) {
  T_ASSERT_EQ_INT(setup_managers(), 0);

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
  T_ASSERT_EQ_INT(setup_managers(), 0);
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
  T_ASSERT_EQ_INT(setup_managers(), 0);
  WamblePlayer *p = create_new_player();
  T_ASSERT(p != NULL);
  WambleBoard *b = find_board_for_player(p);
  T_ASSERT(b != NULL);
  board_move_played(b->id);
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

WAMBLE_TESTS_BEGIN_NAMED(board_manager_tests) {
  WAMBLE_TESTS_ADD_FM(board_reservation_flow, "board_manager");
  WAMBLE_TESTS_ADD_FM(board_move_transitions_to_active, "board_manager");
  WAMBLE_TESTS_ADD_FM(board_release_cancels_reservation, "board_manager");
  WAMBLE_TESTS_ADD_FM(board_complete_archives, "board_manager");
  WAMBLE_TESTS_ADD_FM(board_reservation_timeout_transitions_to_dormant,
                      "board_manager");
  WAMBLE_TESTS_ADD_FM(board_inactivity_timeout_transitions_to_dormant,
                      "board_manager");
}
WAMBLE_TESTS_END()
