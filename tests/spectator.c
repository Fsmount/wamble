#include "common/wamble_test.h"
#include "common/wamble_test_helpers.h"
#include "wamble/wamble.h"

static void setup_default(void) {
  char msg[128];
  (void)config_load(NULL, NULL, msg, sizeof(msg));
  spectator_manager_init();
  board_manager_init();
  player_manager_init();
}

static void teardown_default(void) { spectator_manager_shutdown(); }

static void make_addr(struct sockaddr_in *out) {
  memset(out, 0, sizeof(*out));
  out->sin_family = AF_INET;
  out->sin_port = htons((uint16_t)get_config()->port);
  out->sin_addr.s_addr = htonl(0x7F000001);
}

static int ensure_active_and_reserved(uint64_t *out_active_id,
                                      uint64_t *out_reserved_id) {
  WamblePlayer *p1 = create_new_player();
  if (!p1)
    return -1;
  WambleBoard *b1 = find_board_for_player(p1);
  if (!b1)
    return -1;
  if (out_reserved_id)
    *out_reserved_id = b1->id;
  board_move_played(b1->id);
  if (out_active_id)
    *out_active_id = b1->id;
  return 0;
}

WAMBLE_TEST(spectator_summary_and_focus_flow) {
  setup_default();

  uint64_t active_id = 0, reserved_id = 0;
  T_ASSERT_EQ_INT(ensure_active_and_reserved(&active_id, &reserved_id), 0);
  T_ASSERT(active_id != 0);

  struct sockaddr_in addr;
  make_addr(&addr);
  uint8_t tok_sum[TOKEN_LENGTH] = {1};
  uint8_t tok_foc[TOKEN_LENGTH] = {2};

  struct WambleMsg msum = {0};
  msum.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  memcpy(msum.token, tok_sum, TOKEN_LENGTH);
  msum.board_id = 0;
  SpectatorState st = SPECTATOR_STATE_IDLE;
  uint64_t focus = 0;
  SpectatorRequestStatus rs =
      spectator_handle_request(&msum, &addr, 0, &st, &focus);
  T_ASSERT_EQ_INT(rs, SPECTATOR_OK_SUMMARY);
  T_ASSERT_EQ_INT(st, SPECTATOR_STATE_SUMMARY);

  struct WambleMsg mfoc = {0};
  mfoc.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  memcpy(mfoc.token, tok_foc, TOKEN_LENGTH);
  mfoc.board_id = active_id;
  st = SPECTATOR_STATE_IDLE;
  focus = 0;
  rs = spectator_handle_request(&mfoc, &addr, 0, &st, &focus);
  T_ASSERT_EQ_INT(rs, SPECTATOR_OK_FOCUS);
  T_ASSERT_EQ_INT(st, SPECTATOR_STATE_FOCUS);
  T_ASSERT_EQ_INT((int)focus, (int)active_id);

  SpectatorUpdate upds[16];
  int n = spectator_collect_updates(upds, 16);
  T_ASSERT(n > 0);
  int saw_sum = 0, saw_focus = 0;
  for (int i = 0; i < n; i++) {
    if (tokens_equal(upds[i].token, tok_sum))
      saw_sum = 1;
    if (tokens_equal(upds[i].token, tok_foc) && upds[i].board_id == active_id)
      saw_focus = 1;
  }
  T_ASSERT(saw_sum && saw_focus);

  teardown_default();
  return 0;
}

WAMBLE_TEST(spectator_visibility_and_capacity) {
  setup_default();

  uint64_t active_id = 0;
  uint64_t reserved_id = 0;
  T_ASSERT_EQ_INT(ensure_active_and_reserved(&active_id, &reserved_id), 0);

  WambleConfig cfg = *get_config();
  cfg.spectator_visibility = 1;
  set_thread_config(&cfg);

  struct sockaddr_in addr;
  make_addr(&addr);
  uint8_t tok[TOKEN_LENGTH] = {3};
  struct WambleMsg m = {0};
  m.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  memcpy(m.token, tok, TOKEN_LENGTH);
  m.board_id = 0;
  SpectatorState st = SPECTATOR_STATE_IDLE;
  uint64_t focus = 0;
  SpectatorRequestStatus rs =
      spectator_handle_request(&m, &addr, 0, &st, &focus);
  T_ASSERT_EQ_INT(rs, SPECTATOR_ERR_VISIBILITY);

  cfg = *get_config();
  cfg.spectator_visibility = 0;
  cfg.max_spectators = 1;
  set_thread_config(&cfg);

  uint8_t t1[TOKEN_LENGTH] = {4};
  uint8_t t2[TOKEN_LENGTH] = {5};
  struct WambleMsg mf1 = {0}, mf2 = {0};
  mf1.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  mf1.board_id = active_id;
  memcpy(mf1.token, t1, TOKEN_LENGTH);
  st = SPECTATOR_STATE_IDLE;
  focus = 0;
  rs = spectator_handle_request(&mf1, &addr, 0, &st, &focus);
  T_ASSERT_EQ_INT(rs, SPECTATOR_OK_FOCUS);

  mf2.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  mf2.board_id = active_id;
  memcpy(mf2.token, t2, TOKEN_LENGTH);
  st = SPECTATOR_STATE_IDLE;
  focus = 0;
  rs = spectator_handle_request(&mf2, &addr, 0, &st, &focus);
  T_ASSERT_EQ_INT(rs, SPECTATOR_ERR_FULL);

  teardown_default();
  return 0;
}

WAMBLE_TESTS_BEGIN_NAMED(spectator_tests) {
  WAMBLE_TESTS_ADD_FM(spectator_summary_and_focus_flow, "spectator");
  WAMBLE_TESTS_ADD_FM(spectator_visibility_and_capacity, "spectator");
}
WAMBLE_TESTS_END()
