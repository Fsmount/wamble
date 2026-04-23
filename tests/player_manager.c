#include "common/wamble_test.h"
#include "common/wamble_test_helpers.h"
#include "wamble/wamble.h"
#include "wamble/wamble_db.h"

WAMBLE_TEST(player_pool_capacity_limit) {
  config_load(NULL, NULL, NULL, 0);
  player_manager_init();
  for (int i = 0; i < get_config()->max_players; i++) {
    WamblePlayer *p = create_new_player();
    T_ASSERT(p != NULL);
  }
  T_ASSERT(create_new_player() == NULL);
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

WAMBLE_TEST(login_rehydrates_cached_player_from_persistent_stats) {
  const char *cfg_path = "build/test_player_manager_db.conf";
  const char *sql_path = "build/test_player_manager_seed.sql";
  char db_cfg[1024];
  uint8_t public_key[32];

  if (test_db_apply_migrations(NULL) != 0)
    T_FAIL_SIMPLE("test_db_apply_migrations failed");
  if (test_db_reset(NULL) != 0)
    T_FAIL_SIMPLE("test_db_reset failed");
  if (wamble_test_db_config_lines(db_cfg, sizeof(db_cfg)) != 0)
    T_FAIL_SIMPLE("wamble_test_db_config_lines failed");

  FILE *f = fopen(cfg_path, "wb");
  T_ASSERT(f != NULL);
  fwrite(db_cfg, 1, strlen(db_cfg), f);
  fclose(f);

  T_ASSERT_STATUS(config_load(cfg_path, NULL, NULL, 0), CONFIG_LOAD_OK);
  T_ASSERT_EQ_INT(db_init(NULL), 0);
  wamble_set_query_service(wamble_get_db_query_service());
  player_manager_init();

  f = fopen(sql_path, "wb");
  T_ASSERT(f != NULL);
  fputs("INSERT INTO global_identities (public_key)\n"
        "VALUES (decode('808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f', 'hex'))\n"
        "ON CONFLICT (public_key) DO NOTHING;\n"
        "INSERT INTO players (public_key, rating)\n"
        "VALUES (decode('808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f', 'hex'), 1530.0);\n"
        "INSERT INTO sessions (token, player_id, global_identity_id, "
        "total_score,\n"
        "                      total_prediction_score, games_played)\n"
        "VALUES (\n"
        "  decode('fedcba98765432100123456789abcdef', 'hex'),\n"
        "  (SELECT id FROM players\n"
        "   WHERE public_key = decode('808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f', 'hex')),\n"
        "  (SELECT id FROM global_identities\n"
        "   WHERE public_key = decode('808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f', 'hex')),\n"
        "  42.5, 7.25, 18);\n"
        "INSERT INTO boards (id, fen, status)\n"
        "VALUES (777, '8/8/8/8/8/8/8/8 w - - 0 1', 'ARCHIVED')\n"
        "ON CONFLICT DO NOTHING;\n"
        "INSERT INTO payouts (board_id, session_id, points_awarded, "
        "points_canonical)\n"
        "VALUES (777,\n"
        "  (SELECT id FROM sessions WHERE token = "
        "decode('fedcba98765432100123456789abcdef', 'hex')),\n"
        "  42.5, 42.5)\n"
        "ON CONFLICT DO NOTHING;\n",
        f);
  fclose(f);
  T_ASSERT_EQ_INT(test_db_apply_sql_file(sql_path), 0);

  for (int i = 0; i < 32; i++)
    public_key[i] = (uint8_t)(0x80 + i);

  WamblePlayer *player = create_new_player();
  T_ASSERT(player != NULL);
  T_ASSERT(player->score == 0.0);
  T_ASSERT(player->prediction_score == 0.0);
  T_ASSERT_EQ_INT((int)player->rating, get_config()->default_rating);
  T_ASSERT_EQ_INT(player->games_played, 0);

  player = attach_persistent_identity(player->token, public_key);
  T_ASSERT(player != NULL);
  T_ASSERT(player->has_persistent_identity);
  T_ASSERT(memcmp(player->public_key, public_key, sizeof(public_key)) == 0);
  T_ASSERT(player->score == 42.5);
  T_ASSERT(player->prediction_score == 7.25);
  T_ASSERT(player->rating == 1530.0);
  T_ASSERT_EQ_INT(player->games_played, 18);
  return 0;
}

WAMBLE_TEST(logout_clears_persistent_identity_and_emits_unlink_intent) {
  const char *cfg_path = "build/test_player_manager_logout.conf";
  char db_cfg[1024];
  uint8_t public_key[32];
  WambleIntentBuffer intents = {0};

  if (test_db_apply_migrations(NULL) != 0)
    T_FAIL_SIMPLE("test_db_apply_migrations failed");
  if (test_db_reset(NULL) != 0)
    T_FAIL_SIMPLE("test_db_reset failed");
  if (wamble_test_db_config_lines(db_cfg, sizeof(db_cfg)) != 0)
    T_FAIL_SIMPLE("wamble_test_db_config_lines failed");

  FILE *f = fopen(cfg_path, "wb");
  T_ASSERT(f != NULL);
  fwrite(db_cfg, 1, strlen(db_cfg), f);
  fclose(f);

  T_ASSERT_STATUS(config_load(cfg_path, NULL, NULL, 0), CONFIG_LOAD_OK);
  T_ASSERT_EQ_INT(db_init(NULL), 0);
  wamble_set_query_service(wamble_get_db_query_service());
  player_manager_init();

  wamble_intents_init(&intents);
  wamble_set_intent_buffer(&intents);

  for (int i = 0; i < 32; i++)
    public_key[i] = (uint8_t)(0x20 + i);

  WamblePlayer *player = create_new_player();
  T_ASSERT(player != NULL);
  T_ASSERT(attach_persistent_identity(player->token, public_key) != NULL);
  wamble_intents_clear(&intents);

  T_ASSERT_EQ_INT(detach_persistent_identity(player->token), 0);
  T_ASSERT(!player->has_persistent_identity);
  for (int i = 0; i < 32; i++)
    T_ASSERT_EQ_INT(player->public_key[i], 0);
  T_ASSERT_EQ_INT(intents.count, 1);
  T_ASSERT_EQ_INT(intents.items[0].type, WAMBLE_INTENT_UNLINK_SESSION_IDENTITY);
  T_ASSERT(tokens_equal(intents.items[0].as.unlink_session_identity.token,
                        player->token));

  wamble_set_intent_buffer(NULL);
  wamble_intents_free(&intents);
  return 0;
}

WAMBLE_TEST(persistent_login_emits_reservation_for_existing_reserved_board) {
  const char *cfg_path = "build/test_player_manager_attach_reservation.conf";
  char db_cfg[1024];
  uint8_t public_key[32];
  WambleIntentBuffer intents = {0};

  if (test_db_apply_migrations(NULL) != 0)
    T_FAIL_SIMPLE("test_db_apply_migrations failed");
  if (test_db_reset(NULL) != 0)
    T_FAIL_SIMPLE("test_db_reset failed");
  if (wamble_test_db_config_lines(db_cfg, sizeof(db_cfg)) != 0)
    T_FAIL_SIMPLE("wamble_test_db_config_lines failed");

  FILE *f = fopen(cfg_path, "wb");
  T_ASSERT(f != NULL);
  fwrite(db_cfg, 1, strlen(db_cfg), f);
  fclose(f);

  T_ASSERT_STATUS(config_load(cfg_path, NULL, NULL, 0), CONFIG_LOAD_OK);
  T_ASSERT_EQ_INT(db_init(NULL), 0);
  wamble_set_query_service(wamble_get_db_query_service());
  player_manager_init();
  board_manager_init();

  wamble_intents_init(&intents);
  wamble_set_intent_buffer(&intents);

  for (int i = 0; i < 32; i++)
    public_key[i] = (uint8_t)(0x60 + i);

  WamblePlayer *player = create_new_player();
  T_ASSERT(player != NULL);
  WambleBoard *board = find_board_for_player(player);
  T_ASSERT(board != NULL);
  T_ASSERT(board_is_reserved_for_player(board->id, player->token));

  wamble_intents_clear(&intents);
  T_ASSERT(attach_persistent_identity(player->token, public_key) != NULL);
  T_ASSERT_EQ_INT(intents.count, 2);
  T_ASSERT_EQ_INT(intents.items[0].type, WAMBLE_INTENT_LINK_SESSION_TO_PUBKEY);
  T_ASSERT_EQ_INT(intents.items[1].type, WAMBLE_INTENT_CREATE_RESERVATION);
  T_ASSERT_EQ_INT((int)intents.items[1].as.create_reservation.board_id,
                  (int)board->id);
  T_ASSERT(tokens_equal(intents.items[1].as.create_reservation.token,
                        player->token));

  wamble_set_intent_buffer(NULL);
  wamble_intents_free(&intents);
  return 0;
}

WAMBLE_TESTS_BEGIN_NAMED(wamble_register_tests_player_manager)
WAMBLE_TESTS_ADD_FM(player_pool_capacity_limit, "player_manager");
WAMBLE_TESTS_ADD_FM(player_token_expiration_removes_entry, "player_manager");
WAMBLE_TESTS_ADD_DB_FM(login_rehydrates_cached_player_from_persistent_stats,
                       "player_manager");
WAMBLE_TESTS_ADD_DB_FM(
    logout_clears_persistent_identity_and_emits_unlink_intent,
    "player_manager");
WAMBLE_TESTS_ADD_DB_FM(
    persistent_login_emits_reservation_for_existing_reserved_board,
    "player_manager");
WAMBLE_TESTS_END()
