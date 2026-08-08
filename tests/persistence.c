// I hate that this suite tries to hardcode everything as a "prove"
// for some behaviour.
#include "common/wamble_test_helpers.h"
#include "wamble/wamble_db.h"
#include "wamble_test.h"
#include <inttypes.h>

static int g_db_lock_boundary_violations = 0;

int server_protocol_enqueue_reliable_board_state_sync(
    const uint8_t *token, const struct sockaddr_in *cliaddr);
int wamble_intents_replace_flushed_prefix(WambleIntentBuffer *dst,
                                          WambleIntentBuffer *remaining,
                                          int copied_count);
int wamble_intents_append_buffer(WambleIntentBuffer *dst,
                                 WambleIntentBuffer *src);

static const char *ARCHITECTURE_DB_SNAPSHOT_SQL =
    "DROP TABLE IF EXISTS _wamble_architecture_snapshot; "
    "CREATE TABLE _wamble_architecture_snapshot("
    "  table_name text PRIMARY KEY, row_count bigint NOT NULL, "
    "  digest text NOT NULL); "
    "DO $$ "
    "DECLARE r record; c bigint; d text; "
    "BEGIN "
    "  FOR r IN "
    "    SELECT table_schema, table_name FROM information_schema.tables "
    "    WHERE table_schema = current_schema() "
    "      AND table_type = 'BASE TABLE' "
    "      AND table_name NOT LIKE '_wamble_architecture_%' "
    "      AND table_name NOT IN ('schema_migrations') "
    "    ORDER BY table_name "
    "  LOOP "
    "    EXECUTE format('SELECT count(*), "
    "md5(COALESCE(string_agg(t::text, E''\\n'' ORDER BY t::text), "
    "'''')) FROM (SELECT * FROM %I.%I) t', "
    "                   r.table_schema, r.table_name) "
    "      INTO c, d; "
    "    INSERT INTO _wamble_architecture_snapshot VALUES "
    "      (r.table_name, c, d); "
    "  END LOOP; "
    "END $$;";

static const char *ARCHITECTURE_DB_AFTER_SQL =
    "DROP TABLE IF EXISTS _wamble_architecture_after; "
    "CREATE TABLE _wamble_architecture_after("
    "  table_name text PRIMARY KEY, row_count bigint NOT NULL, "
    "  digest text NOT NULL); "
    "DO $$ "
    "DECLARE r record; c bigint; d text; "
    "BEGIN "
    "  FOR r IN "
    "    SELECT table_schema, table_name FROM information_schema.tables "
    "    WHERE table_schema = current_schema() "
    "      AND table_type = 'BASE TABLE' "
    "      AND table_name NOT LIKE '_wamble_architecture_%' "
    "      AND table_name NOT IN ('schema_migrations') "
    "    ORDER BY table_name "
    "  LOOP "
    "    EXECUTE format('SELECT count(*), "
    "md5(COALESCE(string_agg(t::text, E''\\n'' ORDER BY t::text), "
    "'''')) FROM (SELECT * FROM %I.%I) t', "
    "                   r.table_schema, r.table_name) "
    "      INTO c, d; "
    "    INSERT INTO _wamble_architecture_after VALUES "
    "      (r.table_name, c, d); "
    "  END LOOP; "
    "END $$;";

static int db_snapshot_application_state(void) {
  return test_db_apply_sql(ARCHITECTURE_DB_SNAPSHOT_SQL);
}

static int db_count_snapshot_differences(long *out_differences) {
  if (test_db_apply_sql(ARCHITECTURE_DB_AFTER_SQL) != 0)
    return -1;
  return test_db_query_int(
      "SELECT COUNT(*) "
      "FROM _wamble_architecture_snapshot b "
      "FULL OUTER JOIN _wamble_architecture_after a USING(table_name) "
      "WHERE b.table_name IS NULL OR a.table_name IS NULL "
      "   OR b.row_count <> a.row_count OR b.digest <> a.digest",
      out_differences);
}

static int db_boundary_rejects_manager_locks(const char *operation) {
  (void)operation;
  if (wamble_architecture_board_lock_held() ||
      wamble_architecture_player_lock_held() ||
      wamble_architecture_spectator_lock_held() ||
      wamble_architecture_prediction_lock_held()) {
    g_db_lock_boundary_violations++;
    return -1;
  }
  return 0;
}

static uint8_t g_read_case_token[TOKEN_LENGTH];
static uint8_t g_read_case_hash[WAMBLE_FRAGMENT_HASH_LENGTH];
static uint8_t g_read_case_public_key[WAMBLE_PUBLIC_KEY_LENGTH];
static uint64_t g_read_case_session_id = 0;
static uint64_t g_read_case_identity_id = 0;
static int g_read_case_write_sql_attempts = 0;
static char g_read_case_write_sql[512];

static int persistence_sql_keyword_equals(const char *sql, size_t start,
                                          size_t len, const char *word) {
  size_t word_len = strlen(word);
  if (len != word_len)
    return 0;
  for (size_t i = 0; i < len; i++) {
    unsigned char a = (unsigned char)sql[start + i];
    unsigned char b = (unsigned char)word[i];
    if (a >= 'A' && a <= 'Z')
      a = (unsigned char)(a - 'A' + 'a');
    if (b >= 'A' && b <= 'Z')
      b = (unsigned char)(b - 'A' + 'a');
    if (a != b)
      return 0;
  }
  return 1;
}

static int persistence_sql_is_write_class(const char *sql) {
  const char *prev = "";
  const char *prev2 = "";
  size_t i = 0;
  while (sql && sql[i]) {
    if (sql[i] == '\'') {
      i++;
      while (sql[i]) {
        if (sql[i] == '\'' && sql[i + 1] == '\'')
          i += 2;
        else if (sql[i++] == '\'')
          break;
      }
      continue;
    }
    if (sql[i] == '-' && sql[i + 1] == '-') {
      while (sql[i] && sql[i] != '\n')
        i++;
      continue;
    }
    if (sql[i] == '/' && sql[i + 1] == '*') {
      i += 2;
      while (sql[i] && !(sql[i] == '*' && sql[i + 1] == '/'))
        i++;
      if (sql[i])
        i += 2;
      continue;
    }
    unsigned char ch = (unsigned char)sql[i];
    if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
          (ch >= '0' && ch <= '9') || ch == '_')) {
      i++;
      continue;
    }
    size_t start = i;
    do {
      i++;
      ch = (unsigned char)sql[i];
    } while ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
             (ch >= '0' && ch <= '9') || ch == '_');
    size_t len = i - start;
    const char *token = NULL;
    if (persistence_sql_keyword_equals(sql, start, len, "insert"))
      token = "insert";
    else if (persistence_sql_keyword_equals(sql, start, len, "update"))
      token = "update";
    else if (persistence_sql_keyword_equals(sql, start, len, "delete"))
      token = "delete";
    else if (persistence_sql_keyword_equals(sql, start, len, "merge"))
      token = "merge";
    else if (persistence_sql_keyword_equals(sql, start, len, "truncate"))
      token = "truncate";
    else if (persistence_sql_keyword_equals(sql, start, len, "create"))
      token = "create";
    else if (persistence_sql_keyword_equals(sql, start, len, "alter"))
      token = "alter";
    else if (persistence_sql_keyword_equals(sql, start, len, "drop"))
      token = "drop";
    else if (persistence_sql_keyword_equals(sql, start, len, "lock"))
      token = "lock";
    else if (persistence_sql_keyword_equals(sql, start, len, "for"))
      token = "for";
    else if (persistence_sql_keyword_equals(sql, start, len, "no"))
      token = "no";
    else if (persistence_sql_keyword_equals(sql, start, len, "key"))
      token = "key";

    if (!token)
      continue;
    if (strcmp(prev, "for") == 0 && strcmp(token, "update") == 0)
      return 1;
    if (strcmp(prev2, "for") == 0 && strcmp(prev, "no") == 0 &&
        strcmp(token, "key") == 0)
      return 1;
    if (strcmp(token, "for") != 0 && strcmp(token, "no") != 0 &&
        strcmp(token, "key") != 0)
      return 1;
    prev2 = prev;
    prev = token;
  }
  return 0;
}

static void read_case_audit_sink(const WambleAuditEvent *event,
                                 void *userdata) {
  (void)userdata;
  if (!event || event->kind != WAMBLE_AUDIT_EVENT_DB_SQL ||
      !persistence_sql_is_write_class(event->detail))
    return;
  g_read_case_write_sql_attempts++;
  snprintf(g_read_case_write_sql, sizeof(g_read_case_write_sql), "%s",
           event->detail ? event->detail : "");
}

typedef int (*PersistenceReadCaseRun)(const WambleQueryService *qs);

typedef struct PersistenceReadCase {
  const char *name;
  PersistenceReadCaseRun run;
} PersistenceReadCase;

WAMBLE_TEST(persistence_intent_capture_contract_is_buffered_not_applied) {
  WambleIntentBuffer intents = {0};
  uint8_t token[TOKEN_LENGTH];
  for (int i = 0; i < TOKEN_LENGTH; i++)
    token[i] = (uint8_t)(1 + i);

  wamble_intents_init(&intents);
  wamble_set_intent_buffer(&intents);
  wamble_emit_update_session_last_seen(token);
  wamble_set_intent_buffer(NULL);

  T_ASSERT_EQ_INT(intents.count, 1);
  T_ASSERT_EQ_INT(intents.items[0].type,
                  WAMBLE_INTENT_UPDATE_SESSION_LAST_SEEN);
  T_ASSERT_EQ_INT(memcmp(intents.items[0].as.update_session_last_seen.token,
                         token, TOKEN_LENGTH),
                  0);
  wamble_intents_free(&intents);
  return 0;
}

WAMBLE_TEST(persistence_board_reservation_contract_emits_one_domain_bundle) {
  WambleIntentBuffer intents = {0};
  uint8_t token[TOKEN_LENGTH];
  for (int i = 0; i < TOKEN_LENGTH; i++)
    token[i] = (uint8_t)(0xa0 + i);

  wamble_intents_init(&intents);
  wamble_set_intent_buffer(&intents);
  wamble_persist_board_reserved(42, "fen reserved", token, 17, true, 1234,
                                true);
  wamble_set_intent_buffer(NULL);

  T_ASSERT_EQ_INT(intents.count, 4);
  T_ASSERT_EQ_INT(intents.items[0].type, WAMBLE_INTENT_UPDATE_BOARD);
  T_ASSERT_EQ_INT(intents.items[0].as.update_board.board_id, 42);
  T_ASSERT_STREQ(intents.items[0].as.update_board.status, "RESERVED");
  T_ASSERT_EQ_INT(intents.items[1].type,
                  WAMBLE_INTENT_UPDATE_BOARD_ASSIGNMENT_TIME);
  T_ASSERT_EQ_INT(intents.items[2].type,
                  WAMBLE_INTENT_UPDATE_BOARD_RESERVATION_META);
  T_ASSERT_EQ_INT(
      (int)intents.items[2].as.update_board_reservation_meta.reservation_time,
      1234);
  T_ASSERT_EQ_INT(intents.items[3].type, WAMBLE_INTENT_CREATE_RESERVATION);
  T_ASSERT_EQ_INT(intents.items[3].as.create_reservation.board_id, 42);
  T_ASSERT_EQ_INT(intents.items[3].as.create_reservation.timeout_seconds, 17);
  T_ASSERT_EQ_INT(
      memcmp(intents.items[3].as.create_reservation.token, token, TOKEN_LENGTH),
      0);
  wamble_intents_free(&intents);
  return 0;
}

WAMBLE_TEST(persistence_write_intents_apply_only_when_flushed) {
  uint8_t token[TOKEN_LENGTH];
  for (int i = 0; i < TOKEN_LENGTH; i++)
    token[i] = (uint8_t)(0xe0 + i);
  T_ASSERT_EQ_INT(
      wamble_test_prepare_db("build/test_persistence_write_intent_flow.conf",
                             "", NULL),
      0);

  WambleIntentBuffer intents = {0};
  wamble_intents_init(&intents);
  wamble_set_intent_buffer(&intents);
  wamble_emit_create_session(token, 0);
  wamble_set_intent_buffer(NULL);

  uint64_t session_id = 0;
  T_ASSERT_STATUS(wamble_query_get_session_by_token(token, &session_id),
                  DB_NOT_FOUND);
  T_ASSERT_EQ_INT(wamble_persistence_flush_buffer(
                      &intents, wamble_get_db_query_service(), 1, 16, 4096),
                  1);
  T_ASSERT_STATUS(wamble_query_get_session_by_token(token, &session_id), DB_OK);
  T_ASSERT(session_id > 0);
  wamble_intents_free(&intents);
  return 0;
}

static int read_case_list_boards(const WambleQueryService *qs) {
  DbBoardIdList r = qs->list_boards_by_status("DORMANT");
  T_ASSERT_STATUS(r.status, DB_OK);
  free((void *)r.ids);
  return 0;
}

static int read_case_board_lookup(const WambleQueryService *qs) {
  T_ASSERT_STATUS(qs->get_board(4242).status, DB_OK);
  return 0;
}

static int read_case_longest_game_moves(const WambleQueryService *qs) {
  int out = -1;
  T_ASSERT_STATUS(qs->get_longest_game_moves(&out), DB_OK);
  return 0;
}

static int read_case_active_session_count(const WambleQueryService *qs) {
  int out = -1;
  T_ASSERT_STATUS(qs->get_active_session_count(&out), DB_OK);
  return 0;
}

static int read_case_max_board_id(const WambleQueryService *qs) {
  uint64_t out = 0;
  T_ASSERT_STATUS(qs->get_max_board_id(&out), DB_OK);
  return 0;
}

static int read_case_session_by_token(const WambleQueryService *qs) {
  uint64_t out = 0;
  T_ASSERT_STATUS(qs->get_session_by_token(g_read_case_token, &out), DB_OK);
  return 0;
}

static int read_case_terms_acceptance_check(const WambleQueryService *qs) {
  int accepted = -1;
  T_ASSERT_STATUS(qs->has_profile_terms_acceptance(g_read_case_token, "alpha",
                                                   g_read_case_hash, &accepted),
                  DB_OK);
  return 0;
}

static int
read_case_terms_acceptance_check_for_config(const WambleQueryService *qs) {
  int accepted = -1;
  T_ASSERT_STATUS(qs->has_profile_terms_acceptance_for_config(
                      get_config(), g_read_case_token, "alpha",
                      g_read_case_hash, &accepted),
                  DB_OK);
  return 0;
}

static int read_case_latest_terms_acceptance(const WambleQueryService *qs) {
  WambleProfileTermsAcceptance out = {0};
  T_ASSERT_STATUS(
      qs->get_latest_profile_terms_acceptance(g_read_case_token, "alpha", &out),
      DB_OK);
  wamble_profile_terms_acceptance_clear(&out);
  return 0;
}

static int read_case_persistent_session_by_token(const WambleQueryService *qs) {
  uint64_t out = 0;
  T_ASSERT_STATUS(qs->get_persistent_session_by_token(g_read_case_token, &out),
                  DB_OK);
  return 0;
}

static int read_case_player_total_score(const WambleQueryService *qs) {
  double out = -1;
  T_ASSERT_STATUS(qs->get_player_total_score(g_read_case_session_id, &out),
                  DB_OK);
  return 0;
}

static int read_case_player_prediction_score(const WambleQueryService *qs) {
  double out = -1;
  T_ASSERT_STATUS(qs->get_player_prediction_score(g_read_case_session_id, &out),
                  DB_OK);
  return 0;
}

static int read_case_player_rating(const WambleQueryService *qs) {
  double out = -1;
  T_ASSERT_STATUS(qs->get_player_rating(g_read_case_session_id, &out), DB_OK);
  return 0;
}

static int read_case_session_games_played(const WambleQueryService *qs) {
  int out = -1;
  T_ASSERT_STATUS(qs->get_session_games_played(g_read_case_session_id, &out),
                  DB_OK);
  return 0;
}

static int
read_case_session_chess960_games_played(const WambleQueryService *qs) {
  int out = -1;
  T_ASSERT_STATUS(
      qs->get_session_chess960_games_played(g_read_case_session_id, &out),
      DB_OK);
  return 0;
}

static int read_case_session_player_stats(const WambleQueryService *qs) {
  WamblePersistentPlayerStats out = {0};
  T_ASSERT_STATUS(qs->get_session_player_stats(g_read_case_session_id, &out),
                  DB_OK);
  return 0;
}

static int read_case_identity_total_score(const WambleQueryService *qs) {
  double out = -1;
  T_ASSERT_STATUS(qs->get_identity_total_score(g_read_case_identity_id, &out),
                  DB_OK);
  return 0;
}

static int read_case_identity_games_played(const WambleQueryService *qs) {
  int out = -1;
  T_ASSERT_STATUS(qs->get_identity_games_played(g_read_case_identity_id, &out),
                  DB_OK);
  return 0;
}

static int
read_case_identity_chess960_games_played(const WambleQueryService *qs) {
  int out = -1;
  T_ASSERT_STATUS(
      qs->get_identity_chess960_games_played(g_read_case_identity_id, &out),
      DB_OK);
  return 0;
}

static int read_case_identity_player_stats(const WambleQueryService *qs) {
  WamblePersistentPlayerStats out = {0};
  T_ASSERT_STATUS(qs->get_identity_player_stats(g_read_case_identity_id, &out),
                  DB_OK);
  return 0;
}

static int read_case_session_global_identity_id(const WambleQueryService *qs) {
  uint64_t out = 0;
  T_ASSERT_STATUS(
      qs->get_session_global_identity_id(g_read_case_session_id, &out), DB_OK);
  return 0;
}

static int read_case_identity_tags_csv(const WambleQueryService *qs) {
  char out[256];
  T_ASSERT_STATUS(
      qs->get_identity_tags_csv(g_read_case_identity_id, out, sizeof out),
      DB_OK);
  return 0;
}

static int read_case_identity_handle(const WambleQueryService *qs) {
  char out[256];
  T_ASSERT_STATUS(
      qs->get_identity_handle(g_read_case_identity_id, out, sizeof out), DB_OK);
  return 0;
}

static int read_case_identity_id_by_handle(const WambleQueryService *qs) {
  uint64_t out = 0;
  T_ASSERT_STATUS(qs->get_global_identity_id_by_handle("reader", &out), DB_OK);
  return 0;
}

static int read_case_session_public_key(const WambleQueryService *qs) {
  uint8_t out_key[WAMBLE_PUBLIC_KEY_LENGTH];
  int has_identity = -1;
  T_ASSERT_STATUS(qs->get_session_public_key(g_read_case_session_id, out_key,
                                             &has_identity),
                  DB_OK);
  return 0;
}

static int read_case_session_public_key_by_token(const WambleQueryService *qs) {
  uint8_t out_key[WAMBLE_PUBLIC_KEY_LENGTH];
  int has_identity = -1;
  T_ASSERT_STATUS(qs->get_session_public_key_by_token(g_read_case_token,
                                                      out_key, &has_identity),
                  DB_OK);
  return 0;
}

static int read_case_latest_session_by_identity(const WambleQueryService *qs) {
  uint64_t out = 0;
  T_ASSERT_STATUS(qs->get_latest_session_by_global_identity_id(
                      g_read_case_identity_id, &out),
                  DB_OK);
  return 0;
}

static int
read_case_latest_session_by_public_key(const WambleQueryService *qs) {
  uint64_t out = 0;
  T_ASSERT_STATUS(
      qs->get_latest_session_by_public_key(g_read_case_public_key, &out),
      DB_OK);
  return 0;
}

static int read_case_session_token_by_id(const WambleQueryService *qs) {
  uint8_t out[TOKEN_LENGTH];
  T_ASSERT_STATUS(qs->get_session_token_by_id(g_read_case_session_id, out),
                  DB_OK);
  return 0;
}

static int read_case_session_treatment_group(const WambleQueryService *qs) {
  char out[128];
  T_ASSERT_STATUS(
      qs->get_session_treatment_group(g_read_case_session_id, out, sizeof out),
      DB_OK);
  return 0;
}

static int
read_case_active_reservations_by_public_key(const WambleQueryService *qs) {
  DbActiveReservationsResult r =
      qs->get_active_reservations_by_public_key(g_read_case_public_key);
  T_ASSERT_STATUS(r.status, DB_OK);
  free((void *)r.rows);
  return 0;
}

static int read_case_active_reservations_by_public_key_for_config(
    const WambleQueryService *qs) {
  DbActiveReservationsResult r =
      qs->get_active_reservations_by_public_key_for_config(
          get_config(), g_read_case_public_key);
  T_ASSERT_STATUS(r.status, DB_OK);
  free((void *)r.rows);
  return 0;
}

static int read_case_persistent_player_stats(const WambleQueryService *qs) {
  WamblePersistentPlayerStats out = {0};
  T_ASSERT_STATUS(qs->get_persistent_player_stats(g_read_case_public_key, &out),
                  DB_OK);
  return 0;
}

static int read_case_leaderboard(const WambleQueryService *qs) {
  DbLeaderboardResult r = qs->get_leaderboard(g_read_case_session_id, 0, 10, 0);
  T_ASSERT_STATUS(r.status, DB_OK);
  return 0;
}

static int read_case_moves_for_board(const WambleQueryService *qs) {
  DbMovesResult r = qs->get_moves_for_board(4242);
  T_ASSERT_STATUS(r.status, DB_OK);
  free((void *)r.rows);
  return 0;
}

static int read_case_pending_predictions(const WambleQueryService *qs) {
  DbPredictionsResult r = qs->get_pending_predictions();
  T_ASSERT_STATUS(r.status, DB_OK);
  free((void *)r.rows);
  return 0;
}

static int
read_case_session_treatment_assignment(const WambleQueryService *qs) {
  WambleTreatmentAssignment out = {0};
  T_ASSERT_STATUS(qs->get_session_treatment_assignment(g_read_case_token, &out),
                  DB_OK);
  return 0;
}

static int read_case_policy_decision(const WambleQueryService *qs) {
  WamblePolicyDecision decision;
  T_ASSERT_STATUS(qs->resolve_policy_decision(g_read_case_token, "", "play",
                                              "board", NULL, NULL, &decision),
                  DB_OK);
  return 0;
}

static int read_case_treatment_actions(const WambleQueryService *qs) {
  WambleFact facts[1] = {0};
  snprintf(facts[0].key, sizeof(facts[0].key), "%s", "session.games");
  facts[0].value_type = WAMBLE_TREATMENT_VALUE_INT;
  facts[0].int_value = 3;
  WambleTreatmentAction actions[4];
  int action_count = 0;
  T_ASSERT_STATUS(qs->resolve_treatment_actions(g_read_case_token, "",
                                                "board.read", NULL, facts, 1,
                                                actions, 4, &action_count),
                  DB_OK);
  return 0;
}

static int read_case_treatment_edge_allows(const WambleQueryService *qs) {
  (void)qs->treatment_edge_allows("", "vip", "vip");
  return 0;
}

WAMBLE_TEST(persistence_db_query_service_read_contract) {
  const char *write_sql_examples[] = {
      "INSERT INTO sessions DEFAULT VALUES",
      "UPDATE sessions SET last_seen_at = NOW()",
      "DELETE FROM sessions",
      "MERGE INTO sessions s USING sessions x ON false WHEN NOT MATCHED THEN "
      "INSERT DEFAULT VALUES",
      "TRUNCATE sessions",
      "CREATE TABLE audit_probe(id bigint)",
      "ALTER TABLE sessions ADD COLUMN audit_probe bigint",
      "DROP TABLE sessions",
      "LOCK TABLE sessions",
      "SELECT * FROM sessions FOR UPDATE",
      "SELECT * FROM sessions FOR NO KEY UPDATE",
      "WITH changed AS (UPDATE sessions SET last_seen_at = NOW() RETURNING id) "
      "SELECT * FROM changed",
      "WITH ins AS (INSERT INTO sessions(token, global_identity_id) VALUES "
      "(decode('00112233445566778899aabbccddeeff','hex'), 1) RETURNING id) "
      "SELECT id FROM ins",
      "WITH gone AS (DELETE FROM sessions RETURNING id) SELECT id FROM gone",
      "WITH merged AS (MERGE INTO sessions s USING sessions x ON false WHEN "
      "NOT MATCHED THEN INSERT DEFAULT VALUES) SELECT 1",
  };
  for (size_t i = 0;
       i < sizeof(write_sql_examples) / sizeof(write_sql_examples[0]); i++)
    T_ASSERT(persistence_sql_is_write_class(write_sql_examples[i]));

  for (int i = 0; i < TOKEN_LENGTH; i++)
    g_read_case_token[i] = (uint8_t)(0x10 + i);
  for (int i = 0; i < WAMBLE_FRAGMENT_HASH_LENGTH; i++)
    g_read_case_hash[i] = (uint8_t)(0x40 + i);
  for (int i = 0; i < WAMBLE_PUBLIC_KEY_LENGTH; i++)
    g_read_case_public_key[i] = (uint8_t)(0x70 + i);

  T_ASSERT_EQ_INT(wamble_test_prepare_db(
                      "build/test_persistence_read_contract.conf", "", NULL),
                  0);
  char seed_sql[2048];
  snprintf(seed_sql, sizeof(seed_sql),
           "INSERT INTO players(id, public_key, rating) VALUES "
           "(424242, "
           "decode('"
           "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f','"
           "hex'), 1500); "
           "SELECT setval(pg_get_serial_sequence('players','id'), "
           "GREATEST((SELECT MAX(id) FROM players), 1)); ");
  T_ASSERT_EQ_INT(test_db_apply_sql(seed_sql), 0);
  g_read_case_session_id = db_create_session(g_read_case_token, 424242);
  T_ASSERT(g_read_case_session_id > 0);
  T_ASSERT_STATUS(wamble_get_db_query_service()->get_session_global_identity_id(
                      g_read_case_session_id, &g_read_case_identity_id),
                  DB_OK);
  T_ASSERT(g_read_case_identity_id > 0);
  snprintf(seed_sql, sizeof(seed_sql),
           "INSERT INTO global_identity_handles(global_identity_id, handle) "
           "VALUES (%" PRIu64 ", 'reader') ON CONFLICT DO NOTHING; ",
           g_read_case_identity_id);
  T_ASSERT_EQ_INT(test_db_apply_sql(seed_sql), 0);
  T_ASSERT_EQ_INT(db_insert_board(4242, "8/8/8/8/8/8/8/8 w - - 0 1", "DORMANT"),
                  0);
  uint64_t acceptance_id = 0;
  T_ASSERT_STATUS(db_record_profile_terms_acceptance(
                      g_read_case_token, "alpha", g_read_case_hash,
                      "terms alpha", &acceptance_id),
                  DB_OK);
  const char *cfg_path = "build/test_persistence_read_contract_treatment.conf";
  const char *cfg = "(def experiment-enabled 1)\n"
                    "(treatment-group \"vip\" 20)\n"
                    "(treatment-default \"vip\")\n"
                    "(treatment-visible-fen \"vip\" \"board.read\" "
                    "\"8/8/8/8/8/8/8/8 w - - 0 1\")\n";
  T_ASSERT_EQ_INT(wamble_test_write_optional_db_config_file(cfg_path, cfg), 0);
  T_ASSERT_STATUS(config_load(cfg_path, NULL, NULL, 0), CONFIG_LOAD_OK);
  T_ASSERT_STATUS_OK(db_apply_config_treatment_rules("__default__"));
  T_ASSERT_STATUS(
      db_assign_session_treatment(g_read_case_token, "", NULL, 0, NULL), DB_OK);

  const PersistenceReadCase cases[] = {
      {"list_boards_by_status", read_case_list_boards},
      {"get_board", read_case_board_lookup},
      {"get_longest_game_moves", read_case_longest_game_moves},
      {"get_active_session_count", read_case_active_session_count},
      {"get_max_board_id", read_case_max_board_id},
      {"get_session_by_token", read_case_session_by_token},
      {"has_profile_terms_acceptance", read_case_terms_acceptance_check},
      {"has_profile_terms_acceptance_for_config",
       read_case_terms_acceptance_check_for_config},
      {"get_latest_profile_terms_acceptance",
       read_case_latest_terms_acceptance},
      {"get_persistent_session_by_token",
       read_case_persistent_session_by_token},
      {"get_player_total_score", read_case_player_total_score},
      {"get_player_prediction_score", read_case_player_prediction_score},
      {"get_player_rating", read_case_player_rating},
      {"get_session_games_played", read_case_session_games_played},
      {"get_session_chess960_games_played",
       read_case_session_chess960_games_played},
      {"get_session_player_stats", read_case_session_player_stats},
      {"get_identity_total_score", read_case_identity_total_score},
      {"get_identity_games_played", read_case_identity_games_played},
      {"get_identity_chess960_games_played",
       read_case_identity_chess960_games_played},
      {"get_identity_player_stats", read_case_identity_player_stats},
      {"get_session_global_identity_id", read_case_session_global_identity_id},
      {"get_identity_tags_csv", read_case_identity_tags_csv},
      {"get_identity_handle", read_case_identity_handle},
      {"get_global_identity_id_by_handle", read_case_identity_id_by_handle},
      {"get_session_public_key", read_case_session_public_key},
      {"get_session_public_key_by_token",
       read_case_session_public_key_by_token},
      {"get_latest_session_by_global_identity_id",
       read_case_latest_session_by_identity},
      {"get_latest_session_by_public_key",
       read_case_latest_session_by_public_key},
      {"get_session_token_by_id", read_case_session_token_by_id},
      {"get_session_treatment_group", read_case_session_treatment_group},
      {"get_active_reservations_by_public_key",
       read_case_active_reservations_by_public_key},
      {"get_active_reservations_by_public_key_for_config",
       read_case_active_reservations_by_public_key_for_config},
      {"get_persistent_player_stats", read_case_persistent_player_stats},
      {"get_leaderboard", read_case_leaderboard},
      {"get_moves_for_board", read_case_moves_for_board},
      {"get_pending_predictions", read_case_pending_predictions},
      {"get_session_treatment_assignment",
       read_case_session_treatment_assignment},
      {"resolve_policy_decision", read_case_policy_decision},
      {"resolve_treatment_actions", read_case_treatment_actions},
      {"treatment_edge_allows", read_case_treatment_edge_allows},
  };
  const WambleQueryService *qs = wamble_get_db_query_service();
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    T_ASSERT_EQ_INT(db_snapshot_application_state(), 0);
    g_read_case_write_sql_attempts = 0;
    g_read_case_write_sql[0] = '\0';
    wamble_audit_set_sink(read_case_audit_sink, NULL);
    int case_rc = cases[i].run(qs);
    int write_attempts = g_read_case_write_sql_attempts;
    char write_sql[512];
    snprintf(write_sql, sizeof(write_sql), "%s", g_read_case_write_sql);
    wamble_audit_set_sink(NULL, NULL);
    if (write_attempts != 0)
      T_FAIL("query service read case attempted write SQL: %s: %s",
             cases[i].name, write_sql);
    if (case_rc != 0)
      T_FAIL("query service read case failed: %s rc=%d", cases[i].name,
             case_rc);
    long changed_tables = -1;
    T_ASSERT_EQ_INT(db_count_snapshot_differences(&changed_tables), 0);
    if (changed_tables != 0)
      T_FAIL("query service read case mutated durable state: %s",
             cases[i].name);
  }
  return 0;
}

WAMBLE_TEST(persistence_profile_terms_acceptance_is_profile_and_hash_scoped) {
  uint8_t token[TOKEN_LENGTH];
  uint8_t hash_a[WAMBLE_FRAGMENT_HASH_LENGTH];
  uint8_t hash_b[WAMBLE_FRAGMENT_HASH_LENGTH];
  uint64_t acceptance_id = 0;
  int accepted = -1;
  for (int i = 0; i < TOKEN_LENGTH; i++)
    token[i] = (uint8_t)(0x30 + i);
  for (int i = 0; i < WAMBLE_FRAGMENT_HASH_LENGTH; i++) {
    hash_a[i] = (uint8_t)(0x40 + i);
    hash_b[i] = (uint8_t)(0x80 + i);
  }
  T_ASSERT_EQ_INT(wamble_test_prepare_db(
                      "build/test_persistence_terms_scope.conf", "", NULL),
                  0);
  T_ASSERT(db_create_session(token, 0) > 0);

  T_ASSERT_STATUS(db_record_profile_terms_acceptance(
                      token, "alpha", hash_a, "terms alpha", &acceptance_id),
                  DB_OK);
  T_ASSERT(acceptance_id > 0);

  T_ASSERT_STATUS(wamble_query_has_profile_terms_acceptance(token, "alpha",
                                                            hash_a, &accepted),
                  DB_OK);
  T_ASSERT_EQ_INT(accepted, 1);
  T_ASSERT_STATUS(wamble_query_has_profile_terms_acceptance(token, "beta",
                                                            hash_a, &accepted),
                  DB_OK);
  T_ASSERT_EQ_INT(accepted, 0);
  T_ASSERT_STATUS(wamble_query_has_profile_terms_acceptance(token, "alpha",
                                                            hash_b, &accepted),
                  DB_OK);
  T_ASSERT_EQ_INT(accepted, 0);
  return 0;
}

WAMBLE_TEST(persistence_session_treatment_assignments_are_profile_scoped_rows) {
  uint8_t token[TOKEN_LENGTH];
  for (int i = 0; i < TOKEN_LENGTH; i++)
    token[i] = (uint8_t)(0x50 + i);
  T_ASSERT_EQ_INT(wamble_test_prepare_db(
                      "build/test_persistence_treatment_scope.conf", "", NULL),
                  0);
  uint64_t session_id = db_create_session(token, 0);
  T_ASSERT(session_id > 0);

  char sql[1024];
  snprintf(sql, sizeof(sql),
           "INSERT INTO session_treatment_assignments "
           "(session_id, profile_name, treatment_group_key) VALUES "
           "(%llu, 'alpha', 'control'), (%llu, 'beta', 'vip')",
           (unsigned long long)session_id, (unsigned long long)session_id);
  T_ASSERT_EQ_INT(test_db_apply_sql(sql), 0);
  long assignment_rows = -1;
  T_ASSERT_EQ_INT(
      test_db_query_int("SELECT COUNT(*) FROM session_treatment_assignments",
                        &assignment_rows),
      0);
  T_ASSERT_EQ_INT(assignment_rows, 2);

  snprintf(sql, sizeof(sql),
           "UPDATE session_treatment_assignments SET treatment_group_key = "
           "'experiment' WHERE session_id = %llu AND profile_name = 'alpha'",
           (unsigned long long)session_id);
  T_ASSERT_EQ_INT(test_db_apply_sql(sql), 0);

  long alpha_rows = -1;
  long beta_rows = -1;
  T_ASSERT_EQ_INT(
      test_db_query_int("SELECT COUNT(*) FROM session_treatment_assignments "
                        "WHERE profile_name = 'alpha' AND "
                        "treatment_group_key = 'experiment'",
                        &alpha_rows),
      0);
  T_ASSERT_EQ_INT(
      test_db_query_int("SELECT COUNT(*) FROM session_treatment_assignments "
                        "WHERE profile_name = 'beta' AND "
                        "treatment_group_key = 'vip'",
                        &beta_rows),
      0);
  T_ASSERT_EQ_INT(alpha_rows, 1);
  T_ASSERT_EQ_INT(beta_rows, 1);

  WambleTreatmentAssignment assignment = {0};
  T_ASSERT_STATUS(
      wamble_query_get_session_treatment_assignment(token, &assignment),
      DB_NOT_FOUND);
  return 0;
}

WAMBLE_TEST(persistence_create_session_materializes_identity_once) {
  uint8_t token[TOKEN_LENGTH];
  for (int i = 0; i < TOKEN_LENGTH; i++)
    token[i] = (uint8_t)(0x70 + i);
  T_ASSERT_EQ_INT(
      wamble_test_prepare_db("build/test_persistence_session_materialize.conf",
                             "", NULL),
      0);

  long sessions_before = -1;
  long identities_before = -1;
  long sessions_after = -1;
  long identities_after = -1;
  T_ASSERT_EQ_INT(
      test_db_query_int("SELECT COUNT(*) FROM sessions", &sessions_before), 0);
  T_ASSERT_EQ_INT(test_db_query_int("SELECT COUNT(*) FROM global_identities",
                                    &identities_before),
                  0);
  T_ASSERT(db_create_session(token, 0) > 0);
  T_ASSERT_EQ_INT(
      test_db_query_int("SELECT COUNT(*) FROM sessions", &sessions_after), 0);
  T_ASSERT_EQ_INT(test_db_query_int("SELECT COUNT(*) FROM global_identities",
                                    &identities_after),
                  0);
  T_ASSERT_EQ_INT(sessions_after, sessions_before + 1);
  T_ASSERT_EQ_INT(identities_after, identities_before + 1);
  T_ASSERT(db_create_session(token, 0) > 0);
  T_ASSERT_EQ_INT(
      test_db_query_int("SELECT COUNT(*) FROM sessions", &sessions_after), 0);
  T_ASSERT_EQ_INT(test_db_query_int("SELECT COUNT(*) FROM global_identities",
                                    &identities_after),
                  0);
  T_ASSERT_EQ_INT(sessions_after, sessions_before + 1);
  T_ASSERT_EQ_INT(identities_after, identities_before + 1);
  return 0;
}

WAMBLE_TEST(persistence_board_roundtrip_uses_real_db_query_service) {
  T_ASSERT_EQ_INT(wamble_test_prepare_db(
                      "build/test_persistence_board_roundtrip.conf", "", NULL),
                  0);
  T_ASSERT_EQ_INT(db_insert_board(4242, "8/8/8/8/8/8/8/8 w - - 0 1", "DORMANT"),
                  0);
  DbBoardResult result = wamble_query_get_board(4242);
  T_ASSERT_STATUS(result.status, DB_OK);
  T_ASSERT_STREQ(result.fen, "8/8/8/8/8/8/8/8 w - - 0 1");
  T_ASSERT_STREQ(result.status_text, "DORMANT");
  return 0;
}

WAMBLE_TEST(persistence_treatment_action_query_cache_returns_snapshot) {
  uint8_t token[TOKEN_LENGTH];
  for (int i = 0; i < TOKEN_LENGTH; i++)
    token[i] = (uint8_t)(0x90 + i);
  T_ASSERT_EQ_INT(
      wamble_test_prepare_db("build/test_persistence_treatment_cache_base.conf",
                             "", NULL),
      0);

  const char *cfg_path = "build/test_persistence_treatment_cache.conf";
  const char *cfg = "(def experiment-enabled 1)\n"
                    "(treatment-group \"vip\" 20)\n"
                    "(treatment-default \"vip\")\n"
                    "(treatment-visible-fen \"vip\" \"board.read\" "
                    "\"8/8/8/8/8/8/8/8 w - - 0 1\")\n";
  T_ASSERT_EQ_INT(wamble_test_write_optional_db_config_file(cfg_path, cfg), 0);
  T_ASSERT_STATUS(config_load(cfg_path, NULL, NULL, 0), CONFIG_LOAD_OK);
  T_ASSERT_STATUS_OK(db_apply_config_treatment_rules("__default__"));
  T_ASSERT(db_create_session(token, 0) > 0);
  T_ASSERT_STATUS(db_assign_session_treatment(token, "", NULL, 0, NULL), DB_OK);

  WambleTreatmentAction actions[4];
  int action_count = 0;
  T_ASSERT_STATUS(
      wamble_query_resolve_treatment_actions(
          token, "", "board.read", NULL, NULL, 0, actions, 4, &action_count),
      DB_OK);
  T_ASSERT_EQ_INT(action_count, 1);
  T_ASSERT_STREQ(actions[0].string_value, "8/8/8/8/8/8/8/8 w - - 0 1");

  T_ASSERT_EQ_INT(test_db_apply_sql(
                      "UPDATE global_treatment_group_outputs SET value_text = "
                      "'7/8/8/8/8/8/8/8 w - - 0 1' WHERE group_key = 'vip' "
                      "AND hook_name = 'board.read'"),
                  0);

  memset(actions, 0, sizeof(actions));
  action_count = 0;
  T_ASSERT_STATUS(db_resolve_treatment_actions(token, "", "board.read", NULL,
                                               NULL, 0, actions, 4,
                                               &action_count),
                  DB_OK);
  T_ASSERT_EQ_INT(action_count, 1);
  T_ASSERT_STREQ(actions[0].string_value, "7/8/8/8/8/8/8/8 w - - 0 1");

  memset(actions, 0, sizeof(actions));
  action_count = 0;
  T_ASSERT_STATUS(
      wamble_query_resolve_treatment_actions(
          token, "", "board.read", NULL, NULL, 0, actions, 4, &action_count),
      DB_OK);
  T_ASSERT_EQ_INT(action_count, 1);
  T_ASSERT_STREQ(actions[0].string_value, "8/8/8/8/8/8/8/8 w - - 0 1");
  return 0;
}

WAMBLE_TEST(persistence_db_boundaries_reject_held_manager_locks) {
  uint8_t player_token[TOKEN_LENGTH];
  uint8_t prediction_token[TOKEN_LENGTH];
  uint8_t spectator_token[TOKEN_LENGTH];
  for (int i = 0; i < TOKEN_LENGTH; i++)
    player_token[i] = (uint8_t)(0xb0 + i);
  for (int i = 0; i < TOKEN_LENGTH; i++)
    prediction_token[i] = (uint8_t)(0xc0 + i);
  for (int i = 0; i < TOKEN_LENGTH; i++)
    spectator_token[i] = (uint8_t)(0xd0 + i);
  T_ASSERT_EQ_INT(wamble_test_prepare_db(
                      "build/test_persistence_lock_boundaries.conf", "", NULL),
                  0);
  player_manager_init();
  board_manager_init();
  spectator_manager_init();
  T_ASSERT_STATUS(prediction_manager_init(), PREDICTION_MANAGER_OK);

  g_db_lock_boundary_violations = 0;
  wamble_set_db_boundary_check_for_tests(db_boundary_rejects_manager_locks);

  T_ASSERT_EQ_INT(db_insert_board(6001, "8/8/8/8/8/8/8/8 w - - 0 1", "DORMANT"),
                  0);
  WambleBoard *loaded = get_board_by_id(6001);
  T_ASSERT(loaded != NULL);
  T_ASSERT_EQ_INT(g_db_lock_boundary_violations, 0);

  T_ASSERT(db_create_session(player_token, 0) > 0);
  (void)get_player_by_token(player_token);
  T_ASSERT_EQ_INT(g_db_lock_boundary_violations, 0);

  T_ASSERT(db_create_session(prediction_token, 0) > 0);
  T_ASSERT_EQ_INT(db_insert_board(6002,
                                  "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/"
                                  "RNBQKBNR w KQkq - 0 1",
                                  "ACTIVE"),
                  0);
  WambleBoard prediction_board;
  memset(&prediction_board, 0, sizeof(prediction_board));
  prediction_board.id = 6002;
  snprintf(prediction_board.fen, sizeof(prediction_board.fen), "%s",
           "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1");
  prediction_board.state = BOARD_STATE_ACTIVE;
  prediction_board.result = GAME_RESULT_IN_PROGRESS;
  T_ASSERT_EQ_INT(
      parse_fen_to_bitboard(prediction_board.fen, &prediction_board.board), 0);
  uint64_t prediction_id = 0;
  (void)prediction_submit_with_parent(&prediction_board, prediction_token,
                                      "e2e4", 0, 0, &prediction_id);
  T_ASSERT_EQ_INT(g_db_lock_boundary_violations, 0);

  T_ASSERT_EQ_INT(db_insert_board(6003,
                                  "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/"
                                  "RNBQKBNR w KQkq - 0 1",
                                  "ACTIVE"),
                  0);
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)get_config()->port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  struct WambleMsg msg = {0};
  msg.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  msg.board_id = 6003;
  memcpy(msg.token, spectator_token, TOKEN_LENGTH);
  SpectatorState state = SPECTATOR_STATE_IDLE;
  uint64_t focus = 0;
  (void)spectator_handle_request(&msg, &addr, 0, 0, 1, &state, &focus);
  T_ASSERT_EQ_INT(g_db_lock_boundary_violations, 0);

  wamble_set_db_boundary_check_for_tests(NULL);
  spectator_manager_shutdown();
  return 0;
}

WAMBLE_TEST(
    persistence_board_completion_scoring_returns_before_worker_finishes) {
  T_ASSERT_EQ_INT(wamble_test_prepare_db(
                      "build/test_persistence_async_scoring.conf", "", NULL),
                  0);
  player_manager_init();
  board_manager_init();
  WamblePlayer *p = create_new_player();
  T_ASSERT(p != NULL);
  WambleBoard *b = find_board_for_player(p);
  T_ASSERT(b != NULL);
  WambleIntentBuffer intents;
  wamble_intents_init(&intents);
  wamble_set_intent_buffer(&intents);
  board_move_played(b->id, p->token, "e2e4");
  wamble_emit_record_move(b->id, p->token, "e2e4", 1);
  uint64_t board_id = b->id;
  uint64_t session_id = (uint64_t)db_create_session(p->token, 0);
  T_ASSERT(session_id > 0);
  T_ASSERT_EQ_INT(db_insert_board(board_id, b->fen, "ACTIVE"), 0);
  T_ASSERT_EQ_INT(wamble_persistence_flush_buffer(
                      &intents, wamble_get_db_query_service(), 4, 64, 65536),
                  1);

  int started_before = 0;
  int completed_before = 0;
  wamble_architecture_board_scoring_counters_for_tests(&started_before,
                                                       &completed_before);
  wamble_architecture_board_scoring_pause_for_tests(1);
  board_game_completed(board_id, GAME_RESULT_WHITE_WINS);

  int started = started_before;
  int completed = completed_before;
  for (int i = 0; i < 200 && started == started_before; i++) {
    wamble_sleep_ms(1);
    wamble_architecture_board_scoring_counters_for_tests(&started, &completed);
  }
  T_ASSERT(started > started_before);
  T_ASSERT_EQ_INT(completed, completed_before);

  wamble_architecture_board_scoring_pause_for_tests(0);
  for (int i = 0; i < 200 && completed == completed_before; i++) {
    wamble_sleep_ms(1);
    wamble_architecture_board_scoring_counters_for_tests(&started, &completed);
  }
  T_ASSERT(completed > completed_before);
  board_manager_tick();

  {
    char sql[128];
    long payout_count = 0;
    snprintf(sql, sizeof(sql),
             "SELECT COUNT(*) FROM payouts WHERE board_id = %" PRIu64,
             board_id);
    T_ASSERT_EQ_INT(test_db_query_int(sql, &payout_count), 0);
    T_ASSERT(payout_count > 0);
  }

  wamble_emit_create_reservation(7998, p->token, 120, true);
  wamble_architecture_board_scoring_counters_for_tests(&started_before,
                                                       &completed_before);
  wamble_architecture_board_scoring_pause_for_tests(1);
  T_ASSERT_EQ_INT(
      board_game_completion_defer(board_id, GAME_RESULT_WHITE_WINS, p->token),
      0);
  board_manager_tick();
  wamble_architecture_board_scoring_counters_for_tests(&started, &completed);
  T_ASSERT_EQ_INT(started, started_before);
  wamble_intents_clear(&intents);
  board_manager_tick();
  for (int i = 0; i < 200 && started == started_before; i++) {
    wamble_sleep_ms(1);
    wamble_architecture_board_scoring_counters_for_tests(&started, &completed);
  }
  T_ASSERT(started > started_before);
  wamble_architecture_board_scoring_pause_for_tests(0);
  for (int i = 0; i < 200 && completed == completed_before; i++) {
    wamble_sleep_ms(1);
    wamble_architecture_board_scoring_counters_for_tests(&started, &completed);
  }
  T_ASSERT(completed > completed_before);
  board_manager_tick();
  wamble_set_intent_buffer(NULL);
  wamble_intents_free(&intents);
  return 0;
}

WAMBLE_TEST(persistence_fifo_preserves_reservation_lifecycle) {
  T_ASSERT_EQ_INT(wamble_test_prepare_db(
                      "build/test_persistence_fifo_reservation.conf", "", NULL),
                  0);
  const uint64_t board_id = 7001;
  uint8_t token[TOKEN_LENGTH] = {0};
  token[0] = 0x71;
  T_ASSERT_EQ_INT(
      db_insert_board(board_id, "8/8/8/8/8/8/8/8 w - - 0 1", "DORMANT"), 0);

  WambleIntentBuffer intents;
  wamble_intents_init(&intents);
  wamble_set_intent_buffer(&intents);
  wamble_emit_create_session(token, 0);
  wamble_emit_create_reservation(board_id, token, 120, true);
  wamble_emit_remove_reservation(board_id);
  T_ASSERT_EQ_INT(wamble_persistence_flush_buffer(
                      &intents, wamble_get_db_query_service(), 1, 16, 4096),
                  1);
  T_ASSERT_EQ_INT(intents.count, 0);
  T_ASSERT_EQ_INT(test_db_apply_sql(
                      "DO $$ BEGIN IF EXISTS (SELECT 1 FROM reservations WHERE "
                      "board_id = 7001) THEN RAISE EXCEPTION 'reservation was "
                      "recreated'; END IF; END $$;"),
                  0);
  wamble_set_intent_buffer(NULL);
  wamble_intents_free(&intents);
  return 0;
}

WAMBLE_TEST(persistence_unresolved_session_intent_is_retained) {
  T_ASSERT_EQ_INT(
      wamble_test_prepare_db("build/test_persistence_unresolved_session.conf",
                             "", NULL),
      0);
  uint8_t token[TOKEN_LENGTH] = {0};
  token[0] = 0x72;
  WambleIntentBuffer intents;
  wamble_intents_init(&intents);
  wamble_set_intent_buffer(&intents);
  wamble_emit_create_reservation(7999, token, 120, true);
  wamble_emit_create_session(token, 0);
  T_ASSERT_EQ_INT(wamble_persistence_flush_buffer(
                      &intents, wamble_get_db_query_service(), 1, 16, 4096),
                  0);
  T_ASSERT_EQ_INT(intents.count, 2);
  uint64_t session_id = 0;
  T_ASSERT_STATUS(wamble_query_get_session_by_token(token, &session_id),
                  DB_NOT_FOUND);
  wamble_set_intent_buffer(NULL);
  wamble_intents_free(&intents);
  return 0;
}

WAMBLE_TEST(persistence_prefix_reconciliation_preserves_retry_and_suffix) {
  WambleIntentBuffer captured;
  WambleIntentBuffer remaining;
  wamble_intents_init(&captured);
  wamble_intents_init(&remaining);
  wamble_set_intent_buffer(&captured);
  wamble_emit_update_board_assignment_time(1);
  wamble_emit_update_board_assignment_time(2);
  wamble_emit_update_board_assignment_time(3);
  wamble_set_intent_buffer(&remaining);
  wamble_emit_update_board_assignment_time(2);

  T_ASSERT_EQ_INT(
      wamble_intents_replace_flushed_prefix(&captured, &remaining, 2), 0);
  T_ASSERT_EQ_INT(captured.count, 2);
  T_ASSERT_EQ_INT(remaining.count, 0);
  T_ASSERT_EQ_INT(
      (int)captured.items[0].as.update_board_assignment_time.board_id, 2);
  T_ASSERT_EQ_INT(
      (int)captured.items[1].as.update_board_assignment_time.board_id, 3);
  wamble_set_intent_buffer(&remaining);
  wamble_emit_update_board_assignment_time(4);
  T_ASSERT_EQ_INT(wamble_intents_append_buffer(&captured, &remaining), 0);
  T_ASSERT_EQ_INT(captured.count, 3);
  T_ASSERT_EQ_INT(remaining.count, 0);
  T_ASSERT_EQ_INT(
      (int)captured.items[2].as.update_board_assignment_time.board_id, 4);
  wamble_set_intent_buffer(NULL);
  wamble_intents_free(&remaining);
  wamble_intents_free(&captured);
  return 0;
}

WAMBLE_TEST(persistence_board_move_meta_sql_executes) {
  T_ASSERT_EQ_INT(wamble_test_prepare_db(
                      "build/test_persistence_board_move_meta.conf", "", NULL),
                  0);
  T_ASSERT_EQ_INT(db_insert_board(7002, "8/8/8/8/8/8/8/8 w - - 0 1", "ACTIVE"),
                  0);
  T_ASSERT_EQ_INT(db_apply_update_board_move_meta(7002, "control"), 0);
  T_ASSERT_EQ_INT(
      test_db_apply_sql("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM boards WHERE "
                        "id = 7002 AND last_move_time IS NOT NULL AND "
                        "last_mover_treatment_group = 'control') THEN RAISE "
                        "EXCEPTION 'move metadata was not updated'; END IF; "
                        "END $$;"),
      0);
  return 0;
}

WAMBLE_TESTS_BEGIN_NAMED(persistence_architecture_tests) {
  WAMBLE_TESTS_ADD_FM(
      persistence_intent_capture_contract_is_buffered_not_applied,
      "persistence_architecture");
  WAMBLE_TESTS_ADD_FM(
      persistence_board_reservation_contract_emits_one_domain_bundle,
      "persistence_architecture");
  WAMBLE_TESTS_ADD_DB_FM(persistence_write_intents_apply_only_when_flushed,
                         "persistence_architecture");
  WAMBLE_TESTS_ADD_DB_FM(persistence_db_query_service_read_contract,
                         "persistence_architecture");
  WAMBLE_TESTS_ADD_DB_FM(
      persistence_profile_terms_acceptance_is_profile_and_hash_scoped,
      "persistence_architecture");
  WAMBLE_TESTS_ADD_DB_FM(
      persistence_session_treatment_assignments_are_profile_scoped_rows,
      "persistence_architecture");
  WAMBLE_TESTS_ADD_DB_FM(persistence_create_session_materializes_identity_once,
                         "persistence_architecture");
  WAMBLE_TESTS_ADD_DB_FM(persistence_board_roundtrip_uses_real_db_query_service,
                         "persistence_architecture");
  WAMBLE_TESTS_ADD_DB_FM(
      persistence_treatment_action_query_cache_returns_snapshot,
      "persistence_architecture");
  WAMBLE_TESTS_ADD_DB_FM(persistence_db_boundaries_reject_held_manager_locks,
                         "persistence_architecture");
  WAMBLE_TESTS_ADD_DB_FM(
      persistence_board_completion_scoring_returns_before_worker_finishes,
      "persistence_architecture");
  WAMBLE_TESTS_ADD_DB_FM(persistence_fifo_preserves_reservation_lifecycle,
                         "persistence_architecture");
  WAMBLE_TESTS_ADD_DB_FM(persistence_unresolved_session_intent_is_retained,
                         "persistence_architecture");
  WAMBLE_TESTS_ADD_FM(
      persistence_prefix_reconciliation_preserves_retry_and_suffix,
      "persistence_architecture");
  WAMBLE_TESTS_ADD_DB_FM(persistence_board_move_meta_sql_executes,
                         "persistence_architecture");
}
WAMBLE_TESTS_END()
