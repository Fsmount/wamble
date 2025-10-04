#include "common/wamble_test.h"
#include "wamble/wamble.h"

WAMBLE_TEST(player_pool_capacity_limit) {
  config_load(NULL, NULL, NULL, 0);
  player_manager_init();
  for (int i = 0; i < get_config()->max_players; i++) {
    WamblePlayer *p = create_new_player();
    T_ASSERT(p != NULL);
  }
  WamblePlayer *extra = create_new_player();
  T_ASSERT(extra == NULL);
  return 0;
}

WAMBLE_TEST(player_token_expiration_removes_entry) {
  config_load(NULL, NULL, NULL, 0);
  player_manager_init();
  WamblePlayer *p = create_new_player();
  T_ASSERT(p != NULL);
  uint8_t tok[TOKEN_LENGTH];
  memcpy(tok, p->token, TOKEN_LENGTH);
  p->last_seen_time = wamble_now_wall() - get_config()->token_expiration - 1;
  player_manager_tick();
  T_ASSERT(get_player_by_token(tok) == NULL);
  return 0;
}

WAMBLE_TESTS_BEGIN_NAMED(wamble_register_tests_player_manager)
WAMBLE_TESTS_ADD_EX(player_pool_capacity_limit,
                    "suite=functional module=player_manager type=unit", NULL,
                    NULL, 0);
WAMBLE_TESTS_ADD_EX(player_token_expiration_removes_entry,
                    "suite=functional module=player_manager type=unit", NULL,
                    NULL, 0);
WAMBLE_TESTS_END()
