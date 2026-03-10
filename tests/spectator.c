#include "common/wamble_test.h"
#include "wamble/wamble.h"

WAMBLE_TEST(spectator_summary_and_focus_flow) {
  char msg[128];
  T_ASSERT_STATUS(config_load(NULL, NULL, msg, sizeof(msg)),
                  CONFIG_LOAD_DEFAULTS);
  spectator_manager_init();
  board_manager_init();
  player_manager_init();

  WamblePlayer *player = create_new_player();
  T_ASSERT(player != NULL);
  WambleBoard *board = find_board_for_player(player);
  T_ASSERT(board != NULL);
  uint64_t active_id = board->id;
  board_move_played(board->id);

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)get_config()->port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  uint8_t summary_token[TOKEN_LENGTH] = {1};
  uint8_t focus_token[TOKEN_LENGTH] = {2};

  struct WambleMsg summary = {0};
  summary.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  memcpy(summary.token, summary_token, TOKEN_LENGTH);

  SpectatorState state = SPECTATOR_STATE_IDLE;
  uint64_t focus = 0;
  T_ASSERT_EQ_INT(
      spectator_handle_request(&summary, &addr, 0, 0, &state, &focus),
      SPECTATOR_OK_SUMMARY);
  T_ASSERT_EQ_INT(state, SPECTATOR_STATE_SUMMARY);

  struct WambleMsg game = {0};
  game.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  memcpy(game.token, focus_token, TOKEN_LENGTH);
  game.board_id = active_id;
  state = SPECTATOR_STATE_IDLE;
  focus = 0;
  T_ASSERT_EQ_INT(spectator_handle_request(&game, &addr, 0, 0, &state, &focus),
                  SPECTATOR_OK_FOCUS);
  T_ASSERT_EQ_INT(state, SPECTATOR_STATE_FOCUS);
  T_ASSERT_EQ_INT((int)focus, (int)active_id);

  SpectatorUpdate updates[16];
  int count = spectator_collect_updates(updates, 16);
  int saw_summary = 0;
  int saw_focus = 0;
  for (int i = 0; i < count; i++) {
    if (tokens_equal(updates[i].token, summary_token))
      saw_summary = 1;
    if (tokens_equal(updates[i].token, focus_token) &&
        updates[i].board_id == active_id) {
      saw_focus = 1;
    }
  }
  T_ASSERT(saw_summary);
  T_ASSERT(saw_focus);

  spectator_manager_shutdown();
  return 0;
}

WAMBLE_TEST(spectator_visibility_and_capacity) {
  char msg[128];
  T_ASSERT_STATUS(config_load(NULL, NULL, msg, sizeof(msg)),
                  CONFIG_LOAD_DEFAULTS);
  spectator_manager_init();
  board_manager_init();
  player_manager_init();

  WamblePlayer *player = create_new_player();
  T_ASSERT(player != NULL);
  WambleBoard *board = find_board_for_player(player);
  T_ASSERT(board != NULL);
  uint64_t active_id = board->id;
  board_move_played(board->id);

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)get_config()->port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  WambleConfig cfg = *get_config();
  cfg.spectator_visibility = 1;
  wamble_config_push(&cfg);

  uint8_t denied_token[TOKEN_LENGTH] = {3};
  struct WambleMsg denied = {0};
  denied.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  memcpy(denied.token, denied_token, TOKEN_LENGTH);
  SpectatorState state = SPECTATOR_STATE_IDLE;
  uint64_t focus = 0;
  T_ASSERT_EQ_INT(
      spectator_handle_request(&denied, &addr, 0, 0, &state, &focus),
      SPECTATOR_ERR_VISIBILITY);
  denied.ctrl = WAMBLE_CTRL_SPECTATE_STOP;
  T_ASSERT_EQ_INT(
      spectator_handle_request(&denied, &addr, 0, 0, &state, &focus),
      SPECTATOR_OK_STOP);
  T_ASSERT_EQ_INT(state, SPECTATOR_STATE_IDLE);
  T_ASSERT_EQ_INT((int)focus, 0);

  wamble_config_pop();

  cfg = *get_config();
  cfg.spectator_visibility = 0;
  cfg.max_spectators = 1;
  wamble_config_push(&cfg);

  uint8_t first_token[TOKEN_LENGTH] = {4};
  uint8_t second_token[TOKEN_LENGTH] = {5};
  uint8_t third_token[TOKEN_LENGTH] = {6};
  struct WambleMsg first = {0};
  struct WambleMsg second = {0};
  struct WambleMsg third = {0};
  first.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  first.board_id = active_id;
  memcpy(first.token, first_token, TOKEN_LENGTH);
  second.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  second.board_id = active_id;
  memcpy(second.token, second_token, TOKEN_LENGTH);
  third.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  memcpy(third.token, third_token, TOKEN_LENGTH);

  state = SPECTATOR_STATE_IDLE;
  focus = 0;
  T_ASSERT_EQ_INT(spectator_handle_request(&first, &addr, 0, 0, &state, &focus),
                  SPECTATOR_OK_FOCUS);

  state = SPECTATOR_STATE_IDLE;
  focus = 0;
  T_ASSERT_EQ_INT(spectator_handle_request(&third, &addr, 0, 0, &state, &focus),
                  SPECTATOR_ERR_FULL);
  T_ASSERT_EQ_INT(
      spectator_handle_request(&second, &addr, 0, 1, &state, &focus),
      SPECTATOR_OK_FOCUS);
  T_ASSERT_EQ_INT(spectator_handle_request(&third, &addr, 0, 0, &state, &focus),
                  SPECTATOR_ERR_FULL);

  struct WambleMsg stop = {0};
  stop.ctrl = WAMBLE_CTRL_SPECTATE_STOP;
  memcpy(stop.token, first_token, TOKEN_LENGTH);
  state = SPECTATOR_STATE_FOCUS;
  focus = active_id;
  T_ASSERT_EQ_INT(spectator_handle_request(&stop, &addr, 0, 0, &state, &focus),
                  SPECTATOR_OK_STOP);

  state = SPECTATOR_STATE_IDLE;
  focus = 0;
  T_ASSERT_EQ_INT(spectator_handle_request(&first, &addr, 0, 0, &state, &focus),
                  SPECTATOR_OK_FOCUS);

  spectator_manager_shutdown();
  wamble_config_pop();
  return 0;
}

WAMBLE_TESTS_BEGIN_NAMED(spectator_tests) {
  WAMBLE_TESTS_ADD_FM(spectator_summary_and_focus_flow, "spectator");
  WAMBLE_TESTS_ADD_FM(spectator_visibility_and_capacity, "spectator");
}
WAMBLE_TESTS_END()
