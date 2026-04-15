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
  board_move_played(board->id, NULL, NULL);

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
      spectator_handle_request(&summary, &addr, 0, 0, 1, &state, &focus),
      SPECTATOR_OK_SUMMARY);
  T_ASSERT_EQ_INT(state, SPECTATOR_STATE_SUMMARY);

  struct WambleMsg game = {0};
  game.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  memcpy(game.token, focus_token, TOKEN_LENGTH);
  game.board_id = active_id;
  state = SPECTATOR_STATE_IDLE;
  focus = 0;
  T_ASSERT_EQ_INT(
      spectator_handle_request(&game, &addr, 0, 0, 1, &state, &focus),
      SPECTATOR_OK_FOCUS);
  T_ASSERT_EQ_INT(state, SPECTATOR_STATE_FOCUS);
  T_ASSERT_EQ_INT((int)focus, (int)active_id);

  SpectatorUpdate updates[16];
  int count = spectator_collect_updates(updates, 16);
  int saw_summary = 0;
  int saw_summary_generation = 0;
  int saw_focus = 0;
  for (int i = 0; i < count; i++) {
    if (tokens_equal(updates[i].token, summary_token) &&
        updates[i].summary_generation > 0)
      saw_summary_generation = 1;
    if (tokens_equal(updates[i].token, summary_token) &&
        updates[i].board_id > 0)
      saw_summary = 1;
    if (tokens_equal(updates[i].token, focus_token) &&
        updates[i].board_id == active_id) {
      saw_focus = 1;
    }
  }
  T_ASSERT(saw_summary);
  T_ASSERT(saw_summary_generation);
  T_ASSERT(saw_focus);

  spectator_manager_shutdown();
  return 0;
}

WAMBLE_TEST(spectator_summary_updates_emit_full_snapshots) {
  char msg[128];
  T_ASSERT_STATUS(config_load(NULL, NULL, msg, sizeof(msg)),
                  CONFIG_LOAD_DEFAULTS);
  spectator_manager_init();
  board_manager_init();
  player_manager_init();

  WamblePlayer *player_a = create_new_player();
  WamblePlayer *player_b = create_new_player();
  T_ASSERT(player_a != NULL);
  T_ASSERT(player_b != NULL);
  WambleBoard *board_a = find_board_for_player(player_a);
  WambleBoard *board_b = find_board_for_player(player_b);
  T_ASSERT(board_a != NULL);
  T_ASSERT(board_b != NULL);
  board_move_played(board_a->id, NULL, NULL);

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)get_config()->port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  uint8_t token[TOKEN_LENGTH] = {9};
  struct WambleMsg summary = {0};
  SpectatorState state = SPECTATOR_STATE_IDLE;
  uint64_t focus = 0;
  summary.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  memcpy(summary.token, token, TOKEN_LENGTH);
  T_ASSERT_EQ_INT(
      spectator_handle_request(&summary, &addr, 0, 0, 1, &state, &focus),
      SPECTATOR_OK_SUMMARY);

  SpectatorUpdate updates[32];
  int count = spectator_collect_updates(updates, 32);
  uint64_t gen0 = 0;
  int board_count0 = 0;
  for (int i = 0; i < count; i++) {
    if (!tokens_equal(updates[i].token, token))
      continue;
    if (updates[i].summary_generation > 0)
      gen0 = updates[i].summary_generation;
    if (updates[i].board_id > 0)
      board_count0++;
  }
  T_ASSERT(gen0 > 0);
  T_ASSERT(board_count0 >= 2);

  board_release_reservation(board_b->id);
  spectator_manager_tick();
  wamble_sleep_ms(2);

  WambleConfig cfg = *get_config();
  cfg.spectator_summary_hz = 1000;
  wamble_config_push(&cfg);
  count = spectator_collect_updates(updates, 32);
  wamble_config_pop();

  uint64_t gen1 = 0;
  int saw_reset_marker = 0;
  int board_count1 = 0;
  int saw_board_a = 0;
  int saw_board_b = 0;
  for (int i = 0; i < count; i++) {
    if (!tokens_equal(updates[i].token, token))
      continue;
    if (updates[i].summary_generation > 0)
      gen1 = updates[i].summary_generation;
    if (updates[i].summary_generation > 0 && updates[i].board_id == 0 &&
        updates[i].fen[0] == '\0')
      saw_reset_marker = 1;
    if (updates[i].board_id == board_a->id)
      saw_board_a = 1;
    if (updates[i].board_id == board_b->id)
      saw_board_b = 1;
    if (updates[i].board_id > 0)
      board_count1++;
  }
  T_ASSERT(gen1 > gen0);
  T_ASSERT(saw_reset_marker);
  T_ASSERT(board_count1 >= 1);
  T_ASSERT(saw_board_a);
  T_ASSERT(!saw_board_b);

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
  board_move_played(board->id, NULL, NULL);

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
      spectator_handle_request(&denied, &addr, 0, 0, 1, &state, &focus),
      SPECTATOR_ERR_VISIBILITY);
  denied.ctrl = WAMBLE_CTRL_SPECTATE_STOP;
  T_ASSERT_EQ_INT(
      spectator_handle_request(&denied, &addr, 0, 0, 0, &state, &focus),
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
  T_ASSERT_EQ_INT(
      spectator_handle_request(&first, &addr, 0, 0, 1, &state, &focus),
      SPECTATOR_OK_FOCUS);

  state = SPECTATOR_STATE_IDLE;
  focus = 0;
  T_ASSERT_EQ_INT(
      spectator_handle_request(&third, &addr, 0, 0, 1, &state, &focus),
      SPECTATOR_ERR_FULL);
  T_ASSERT_EQ_INT(
      spectator_handle_request(&second, &addr, 0, 1, 1, &state, &focus),
      SPECTATOR_OK_FOCUS);
  T_ASSERT_EQ_INT(
      spectator_handle_request(&third, &addr, 0, 0, 1, &state, &focus),
      SPECTATOR_ERR_FULL);

  struct WambleMsg stop = {0};
  stop.ctrl = WAMBLE_CTRL_SPECTATE_STOP;
  memcpy(stop.token, first_token, TOKEN_LENGTH);
  state = SPECTATOR_STATE_FOCUS;
  focus = active_id;
  T_ASSERT_EQ_INT(
      spectator_handle_request(&stop, &addr, 0, 0, 0, &state, &focus),
      SPECTATOR_OK_STOP);

  state = SPECTATOR_STATE_IDLE;
  focus = 0;
  T_ASSERT_EQ_INT(
      spectator_handle_request(&first, &addr, 0, 0, 1, &state, &focus),
      SPECTATOR_OK_FOCUS);

  spectator_manager_shutdown();
  wamble_config_pop();
  return 0;
}

WAMBLE_TEST(spectator_notifications_use_structured_flags) {
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
  board_move_played(board->id, NULL, NULL);

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)get_config()->port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  uint8_t token[TOKEN_LENGTH] = {7};
  struct WambleMsg focus = {0};
  focus.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  focus.board_id = active_id;
  memcpy(focus.token, token, TOKEN_LENGTH);

  SpectatorState state = SPECTATOR_STATE_IDLE;
  uint64_t focus_id = 0;
  T_ASSERT_EQ_INT(
      spectator_handle_request(&focus, &addr, 0, 0, 1, &state, &focus_id),
      SPECTATOR_OK_FOCUS);

  WambleConfig cfg = *get_config();
  cfg.spectator_max_focus_per_session = 0;
  wamble_config_push(&cfg);
  spectator_manager_tick();

  SpectatorUpdate notices[4];
  int count = spectator_collect_notifications(notices, 4);
  T_ASSERT_EQ_INT(count, 1);
  T_ASSERT(tokens_equal(notices[0].token, token));
  T_ASSERT_EQ_INT((int)notices[0].board_id, (int)active_id);
  T_ASSERT((notices[0].flags & WAMBLE_FLAG_SPECTATE_NOTICE_SUMMARY_FALLBACK) !=
           0);
  T_ASSERT((notices[0].flags & WAMBLE_FLAG_SPECTATE_NOTICE_STOPPED) == 0);

  wamble_config_pop();

  cfg = *get_config();
  cfg.max_spectators = 0;
  wamble_config_push(&cfg);
  spectator_manager_tick();

  count = spectator_collect_notifications(notices, 4);
  T_ASSERT_EQ_INT(count, 1);
  T_ASSERT(tokens_equal(notices[0].token, token));
  T_ASSERT_EQ_INT((int)notices[0].board_id, 0);
  T_ASSERT((notices[0].flags & WAMBLE_FLAG_SPECTATE_NOTICE_STOPPED) != 0);
  T_ASSERT((notices[0].flags & WAMBLE_FLAG_SPECTATE_NOTICE_SUMMARY_FALLBACK) ==
           0);

  spectator_manager_shutdown();
  wamble_config_pop();
  return 0;
}

WAMBLE_TEST(spectator_game_mode_flag_respects_visibility) {
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
  board->board.game_mode = GAME_MODE_CHESS960;
  uint64_t active_id = board->id;

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)get_config()->port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  uint8_t hidden_token[TOKEN_LENGTH] = {8};
  uint8_t visible_token[TOKEN_LENGTH] = {9};
  struct WambleMsg hidden = {0};
  struct WambleMsg visible = {0};
  SpectatorState state = SPECTATOR_STATE_IDLE;
  uint64_t focus_id = 0;

  hidden.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  hidden.board_id = active_id;
  memcpy(hidden.token, hidden_token, TOKEN_LENGTH);
  T_ASSERT_EQ_INT(
      spectator_handle_request(&hidden, &addr, 0, 0, 0, &state, &focus_id),
      SPECTATOR_OK_FOCUS);

  visible.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  visible.board_id = active_id;
  memcpy(visible.token, visible_token, TOKEN_LENGTH);
  T_ASSERT_EQ_INT(
      spectator_handle_request(&visible, &addr, 0, 0, 1, &state, &focus_id),
      SPECTATOR_OK_FOCUS);

  SpectatorUpdate updates[16];
  int count = spectator_collect_updates(updates, 16);
  int saw_hidden = 0;
  int saw_visible = 0;
  for (int i = 0; i < count; i++) {
    if (tokens_equal(updates[i].token, hidden_token) &&
        updates[i].board_id == active_id) {
      saw_hidden = 1;
      T_ASSERT((updates[i].flags & WAMBLE_FLAG_BOARD_IS_960) == 0);
    }
    if (tokens_equal(updates[i].token, visible_token) &&
        updates[i].board_id == active_id) {
      saw_visible = 1;
      T_ASSERT((updates[i].flags & WAMBLE_FLAG_BOARD_IS_960) != 0);
    }
  }
  T_ASSERT(saw_hidden);
  T_ASSERT(saw_visible);

  spectator_manager_shutdown();
  return 0;
}

WAMBLE_TEST(spectator_mode_filters_ignored_without_game_mode_visibility) {
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
  board->board.game_mode = GAME_MODE_CHESS960;
  uint64_t board_id = board->id;

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)get_config()->port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  uint8_t token[TOKEN_LENGTH] = {10};
  struct WambleMsg req = {0};
  req.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  req.board_id = 0;
  req.flags = WAMBLE_FLAG_MODE_FILTER_STANDARD;
  memcpy(req.token, token, TOKEN_LENGTH);

  SpectatorState state = SPECTATOR_STATE_IDLE;
  uint64_t focus_id = 0;
  T_ASSERT_EQ_INT(
      spectator_handle_request(&req, &addr, 0, 0, 0, &state, &focus_id),
      SPECTATOR_OK_SUMMARY);

  SpectatorUpdate updates[32];
  int count = spectator_collect_updates(updates, 32);
  int saw_board = 0;
  for (int i = 0; i < count; i++) {
    if (tokens_equal(updates[i].token, token) &&
        updates[i].board_id == board_id)
      saw_board = 1;
  }
  T_ASSERT(saw_board);

  spectator_manager_shutdown();
  return 0;
}

WAMBLE_TESTS_BEGIN_NAMED(spectator_tests) {
  WAMBLE_TESTS_ADD_FM(spectator_summary_and_focus_flow, "spectator");
  WAMBLE_TESTS_ADD_FM(spectator_summary_updates_emit_full_snapshots,
                      "spectator");
  WAMBLE_TESTS_ADD_FM(spectator_visibility_and_capacity, "spectator");
  WAMBLE_TESTS_ADD_FM(spectator_notifications_use_structured_flags,
                      "spectator");
  WAMBLE_TESTS_ADD_FM(spectator_game_mode_flag_respects_visibility,
                      "spectator");
  WAMBLE_TESTS_ADD_FM(
      spectator_mode_filters_ignored_without_game_mode_visibility, "spectator");
}
WAMBLE_TESTS_END()
