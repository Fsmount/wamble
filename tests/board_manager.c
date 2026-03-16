#include "common/wamble_test.h"
#include "wamble/wamble.h"

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
