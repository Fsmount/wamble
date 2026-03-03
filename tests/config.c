#include "common/wamble_test.h"
#include "wamble/wamble.h"
#include "wamble/wamble_db.h"

#if defined(WAMBLE_PLATFORM_POSIX)
int setenv(const char *name, const char *value, int overwrite);
int unsetenv(const char *name);
#endif

static const char *conf_path = "build/test_config.conf";

static void write_config_file(void) {
  const char *cfg = "(def log-level 3)\n"
                    "(defn add2 (a b) (+ a b))\n"
                    "(def timeout-ms (add2 40 2))\n"
                    "(defmacro inc (x) (do (+ x 1)))\n"
                    "(def max-retries (inc 3))\n"
                    "(defprofile base ((def port 8888) (def advertise 1) (def "
                    "visibility 1)))\n"
                    "(defprofile canary :inherits base ((def port 8891) (def "
                    "visibility 2)))\n";
  FILE *f = fopen(conf_path, "w");
  if (!f)
    return;
  fwrite(cfg, 1, strlen(cfg), f);
  fclose(f);
}

WAMBLE_TEST(config_basic_eval) {
  write_config_file();
  T_ASSERT_STATUS(config_load(conf_path, NULL, NULL, 0), CONFIG_LOAD_OK);

  T_ASSERT_EQ_INT(get_config()->timeout_ms, 42);
  T_ASSERT_EQ_INT(get_config()->max_retries, 4);
  T_ASSERT_EQ_INT(get_config()->log_level, 3);

  int n = config_profile_count();
  T_ASSERT(n >= 2);
  const WambleProfile *base = config_find_profile("base");
  const WambleProfile *canary = config_find_profile("canary");
  T_ASSERT(base && canary);
  T_ASSERT_EQ_INT(base->advertise, 1);
  T_ASSERT_EQ_INT(base->visibility, 1);
  T_ASSERT_EQ_INT(base->config.port, 8888);
  T_ASSERT_EQ_INT(canary->config.port, 8891);
  T_ASSERT_EQ_INT(canary->visibility, 2);
  T_ASSERT_EQ_INT(canary->advertise, 1);
  return 0;
}

WAMBLE_TEST(config_defaults_no_file) {
  char status[128];
  ConfigLoadStatus s = config_load(NULL, NULL, status, sizeof status);
  T_ASSERT_STATUS(s, CONFIG_LOAD_DEFAULTS);
  T_ASSERT_EQ_INT(get_config()->port, 8888);
  T_ASSERT_EQ_INT(get_config()->timeout_ms, 100);
  T_ASSERT_EQ_INT(get_config()->rate_limit_requests_per_sec, 120);
  T_ASSERT_EQ_INT(get_config()->experiment_enabled, 0);
  T_ASSERT_EQ_INT(get_config()->experiment_seed, 0);
  T_ASSERT_EQ_INT(get_config()->log_level, LOG_LEVEL_INFO);
  return 0;
}

WAMBLE_TEST(config_env_getenv) {
  const char *p = "build/test_config_env.conf";
#if defined(WAMBLE_PLATFORM_POSIX)
  setenv("WAMBLE_ENV", "production", 1);
#elif defined(WAMBLE_PLATFORM_WINDOWS)
  _putenv("WAMBLE_ENV=production");
#endif
  const char *cfg = "(def db-host (if (= (getenv \"WAMBLE_ENV\") "
                    "\"production\") \"prod.db\" \"localhost\"))\n";
  FILE *f = fopen(p, "w");
  T_ASSERT(f != NULL);
  fwrite(cfg, 1, strlen(cfg), f);
  fclose(f);
  T_ASSERT_STATUS(config_load(p, NULL, NULL, 0), CONFIG_LOAD_OK);
  T_ASSERT_STREQ(get_config()->db_host, "prod.db");
  return 0;
}

WAMBLE_TEST(config_push_pop_stack) {
  int prev = get_config()->log_level;
  WambleConfig tmp = *get_config();
  tmp.log_level = 4;
  wamble_config_push(&tmp);
  T_ASSERT_EQ_INT(get_config()->log_level, 4);
  wamble_config_pop();
  T_ASSERT_EQ_INT(get_config()->log_level, prev);
  return 0;
}

WAMBLE_TEST(config_profile_inheritance) {
  write_config_file();
  T_ASSERT_STATUS(config_load(conf_path, NULL, NULL, 0), CONFIG_LOAD_OK);
  const WambleProfile *base = config_find_profile("base");
  const WambleProfile *canary = config_find_profile("canary");
  T_ASSERT(base && canary);
  T_ASSERT_EQ_INT(base->config.port, 8888);
  T_ASSERT_EQ_INT(canary->config.port, 8891);
  T_ASSERT_EQ_INT(canary->visibility, 2);
  T_ASSERT_EQ_INT(canary->advertise, 1);
  return 0;
}

WAMBLE_TEST(config_speed_parse_minimal) {
  const char *p = "build/test_config_speed.conf";
  const char *cfg = "(def log-level 3)\n";
  FILE *f = fopen(p, "w");
  T_ASSERT(f != NULL);
  fwrite(cfg, 1, strlen(cfg), f);
  fclose(f);
  for (int i = 0; i < 200; i++)
    T_ASSERT_STATUS(config_load(p, NULL, NULL, 0), CONFIG_LOAD_OK);
  return 0;
}

WAMBLE_TEST(config_perf_parse_medium) {
  const char *p = "build/test_config_perf.conf";
  FILE *f = fopen(p, "w");
  T_ASSERT(f != NULL);
  fputs("(def log-level 2)\n", f);
  int base_port = 9000;
  for (int i = 0; i < 50; i++) {
    char line[256];
    snprintf(line, sizeof line,
             "(defprofile p%d ((def port %d) (def advertise 1) (def visibility "
             "0)))\n",
             i, base_port + i);
    fputs(line, f);
  }
  fclose(f);
  T_ASSERT_STATUS(config_load(p, NULL, NULL, 0), CONFIG_LOAD_OK);
  T_ASSERT_EQ_INT(config_profile_count(), 50);
  return 0;
}

WAMBLE_TEST(config_stress_many_profiles) {
  const char *p = "build/test_config_stress.conf";
  FILE *f = fopen(p, "w");
  T_ASSERT(f != NULL);
  fputs("(def log-level 2)\n", f);
  int base_port = 10000;
  int n = 100;
  for (int i = 0; i < n; i++) {
    char line[256];
    snprintf(line, sizeof line,
             "(defprofile s%d ((def port %d) (def advertise 1) (def visibility "
             "1)))\n",
             i, base_port + i);
    fputs(line, f);
  }
  fclose(f);
  T_ASSERT_STATUS(config_load(p, NULL, NULL, 0), CONFIG_LOAD_OK);
  T_ASSERT_EQ_INT(config_profile_count(), n);
  return 0;
}

WAMBLE_TEST(config_parse_doubles_and_strings) {
  const char *p = "build/test_config_more.conf";
  const char *cfg = "(def max-pot 33.5)\n"
                    "(def new-player-early-phase-mult 1.75)\n"
                    "(def experienced-player-end-phase-mult 1.5)\n"
                    "(def experiment-enabled 1)\n"
                    "(def experiment-seed 42)\n"
                    "(def rate-limit-requests-per-sec 33)\n"
                    "(def select-timeout-usec 250000)\n"
                    "(def state-dir \"/var/tmp/wamble\")\n";
  FILE *f = fopen(p, "w");
  T_ASSERT(f != NULL);
  fwrite(cfg, 1, strlen(cfg), f);
  fclose(f);
  T_ASSERT_STATUS(config_load(p, NULL, NULL, 0), CONFIG_LOAD_OK);
  T_ASSERT_EQ_INT(get_config()->select_timeout_usec, 250000);
  T_ASSERT(fabs(get_config()->max_pot - 33.5) < 1e-9);
  T_ASSERT(fabs(get_config()->new_player_early_phase_mult - 1.75) < 1e-9);
  T_ASSERT(fabs(get_config()->experienced_player_end_phase_mult - 1.5) < 1e-9);
  T_ASSERT_EQ_INT(get_config()->experiment_enabled, 1);
  T_ASSERT_EQ_INT(get_config()->experiment_seed, 42);
  T_ASSERT_EQ_INT(get_config()->rate_limit_requests_per_sec, 33);
  T_ASSERT_STREQ(get_config()->state_dir, "/var/tmp/wamble");
  return 0;
}

WAMBLE_TEST(config_treatment_groups_parse) {
  const char *p = "build/test_config_treatments.conf";
  const char *cfg =
      "(def experiment-enabled 1)\n"
      "(treatment-group \"control\" 10)\n"
      "(treatment-group \"fast-lane\" 20)\n"
      "(treatment-default \"control\")\n"
      "(treatment-assign \"*\" \"*\" \"fast-lane\" 50 (match \"session.games\" "
      "\"gte\" 3))\n"
      "(treatment-edge \"control\" \"*\")\n"
      "(treatment-edge \"fast-lane\" \"control\")\n"
      "(treatment-tag \"fast-lane\" \"vip\")\n"
      "(treatment-feature \"fast-lane\" \"prediction.gated\" 1)\n"
      "(treatment-context \"fast-lane\" \"prediction.submit\" "
      "\"previous.rating\" (fact \"previous_player.rating\"))\n"
      "(treatment-behavior \"fast-lane\" \"prediction.submit\" "
      "\"prediction.mode\" 2)\n"
      "(treatment-visible-fen \"fast-lane\" \"board.read\" "
      "\"8/8/8/8/8/8/8/8 w - - 0 1\")\n"
      "(treatment-predictions-from-moves \"fast-lane\" \"prediction.read\")\n"
      "(treatment-meta \"fast-lane\" \"prediction.submit\" \"note\" "
      "\"boosted\")\n";
  FILE *f = fopen(p, "w");
  T_ASSERT(f != NULL);
  fwrite(cfg, 1, strlen(cfg), f);
  fclose(f);
  T_ASSERT_STATUS(config_load(p, NULL, NULL, 0), CONFIG_LOAD_OK);
  T_ASSERT_EQ_INT(get_config()->experiment_enabled, 1);
  T_ASSERT_EQ_INT(config_treatment_group_count(), 2);
  T_ASSERT_EQ_INT(config_treatment_rule_count(), 1);
  T_ASSERT_EQ_INT(config_treatment_edge_count(), 2);
  T_ASSERT_EQ_INT(config_treatment_output_count(), 7);
  {
    const WambleTreatmentGroupSpec *g = config_treatment_group_get(0);
    T_ASSERT(g != NULL);
    T_ASSERT(g->group_key != NULL);
  }
  {
    const WambleTreatmentRuleSpec *r = config_treatment_rule_get(0);
    T_ASSERT(r != NULL);
    T_ASSERT_STREQ(r->group_key, "fast-lane");
    T_ASSERT_EQ_INT(r->predicate_count, 1);
    T_ASSERT_STREQ(r->predicates[0].fact_key, "session.games");
    T_ASSERT_STREQ(r->predicates[0].op, "gte");
  }
  {
    const WambleTreatmentOutputSpec *o = config_treatment_output_get(1);
    T_ASSERT(o != NULL);
    T_ASSERT(o->output_kind != NULL);
  }
  {
    int found_visible_fen = 0;
    int found_move_projection = 0;
    int found_wildcard_feature = 0;
    for (int i = 0; i < config_treatment_output_count(); i++) {
      const WambleTreatmentOutputSpec *o = config_treatment_output_get(i);
      if (!o)
        continue;
      if (o->output_kind && o->output_key && o->hook_name &&
          strcmp(o->output_kind, "feature") == 0 &&
          strcmp(o->output_key, "prediction.gated") == 0 &&
          strcmp(o->hook_name, "*") == 0) {
        found_wildcard_feature = 1;
      }
      if (o->output_kind && o->output_key &&
          strcmp(o->output_kind, "view") == 0 &&
          strcmp(o->output_key, "board.fen") == 0) {
        found_visible_fen = 1;
      }
      if (o->output_kind && o->output_key &&
          strcmp(o->output_kind, "view") == 0 &&
          strcmp(o->output_key, "prediction.source") == 0) {
        found_move_projection = 1;
      }
    }
    T_ASSERT(found_wildcard_feature);
    T_ASSERT(found_visible_fen);
    T_ASSERT(found_move_projection);
  }
  return 0;
}

WAMBLE_TEST(config_profile_select_and_not_found) {
  const char *p = "build/test_config_profiles.conf";
  const char *cfg = "(def log-level 2)\n"
                    "(defprofile base ((def port 8810) (def advertise 1) (def "
                    "visibility 0)))\n"
                    "(defprofile canary :inherits base ((def port 8811)))\n";
  char status[256];
  FILE *f = fopen(p, "w");
  T_ASSERT(f != NULL);
  fwrite(cfg, 1, strlen(cfg), f);
  fclose(f);
  T_ASSERT_STATUS(config_load(p, "canary", status, sizeof status),
                  CONFIG_LOAD_OK);
  T_ASSERT_EQ_INT(get_config()->port, 8811);
  ConfigLoadStatus s = config_load(p, "missing", status, sizeof status);
  T_ASSERT_STATUS(s, CONFIG_LOAD_PROFILE_NOT_FOUND);
  T_ASSERT(strstr(status, "profile 'missing' not found") != NULL);
  return 0;
}

WAMBLE_TEST(config_profile_inheritance_variants) {
  const char *p = "build/test_config_inherits.conf";
  const char *cfg = "(defprofile base ((def port 8800) (def advertise 1) (def "
                    "visibility 1)))\n"
                    "(defprofile childA :inherits base ((def port 8801)))\n"
                    "(defprofile childB :inherits childA ((def port 8802) (def "
                    "log-level 4)))\n";
  FILE *f = fopen(p, "w");
  T_ASSERT(f != NULL);
  fwrite(cfg, 1, strlen(cfg), f);
  fclose(f);
  T_ASSERT_STATUS(config_load(p, NULL, NULL, 0), CONFIG_LOAD_OK);
  const WambleProfile *a = config_find_profile("childA");
  const WambleProfile *b = config_find_profile("childB");
  const WambleProfile *base = config_find_profile("base");
  T_ASSERT(base && a && b);
  T_ASSERT_EQ_INT(a->config.port, 8801);
  T_ASSERT_EQ_INT(b->config.port, 8802);
  T_ASSERT_EQ_INT(b->advertise, base->advertise);
  T_ASSERT_EQ_INT(b->visibility, base->visibility);
  T_ASSERT_EQ_INT(b->config.log_level, 4);
  return 0;
}

WAMBLE_TEST(config_profile_missing_base_skipped) {
  const char *p = "build/test_config_missing_base.conf";
  const char *cfg = "(defprofile orphan :inherits nosuch ((def port 9900)))\n";
  FILE *f = fopen(p, "w");
  T_ASSERT(f != NULL);
  fwrite(cfg, 1, strlen(cfg), f);
  fclose(f);
  T_ASSERT_STATUS(config_load(p, NULL, NULL, 0), CONFIG_LOAD_OK);
  T_ASSERT_EQ_INT(config_profile_count(), 0);
  T_ASSERT(config_find_profile("orphan") == NULL);
  return 0;
}

WAMBLE_TEST(config_env_getenv_unset) {
  const char *p = "build/test_config_env_unset.conf";
  const char *cfg = "(def db-host (getenv \"WAMBLE_ENV_UNSET\"))\n";
  FILE *f = fopen(p, "w");
  T_ASSERT(f != NULL);
  fwrite(cfg, 1, strlen(cfg), f);
  fclose(f);
#if defined(WAMBLE_PLATFORM_POSIX)
  unsetenv("WAMBLE_ENV_UNSET");
#elif defined(WAMBLE_PLATFORM_WINDOWS)
  _putenv("WAMBLE_ENV_UNSET=");
#endif
  T_ASSERT_STATUS(config_load(p, NULL, NULL, 0), CONFIG_LOAD_OK);
  T_ASSERT_STREQ(get_config()->db_host, "");
  return 0;
}

WAMBLE_TEST(config_snapshot_restore_rebuilds_policy_eval) {
  const char *p = "build/test_config_policy_eval.conf";
  const char *cfg =
      "(defn policy-eval (identity action resource profile group context-key "
      "context-value now)\n"
      "  (if (= action \"protocol.ctrl\") (quote (allow 7 \"restored\" "
      "\"t1\")) "
      "(quote deny)))\n";
  FILE *f = fopen(p, "w");
  T_ASSERT(f != NULL);
  fwrite(cfg, 1, strlen(cfg), f);
  fclose(f);

  T_ASSERT_STATUS(config_load(p, NULL, NULL, 0), CONFIG_LOAD_OK);
  T_ASSERT_EQ_INT(config_has_policy_eval(), 1);
  void *snap = config_create_snapshot();
  T_ASSERT(snap != NULL);

  T_ASSERT_STATUS(config_load("build/does_not_exist.conf", NULL, NULL, 0),
                  CONFIG_LOAD_DEFAULTS);
  T_ASSERT_EQ_INT(config_has_policy_eval(), 0);

  T_ASSERT_STATUS_OK(config_restore_snapshot(snap));
  T_ASSERT_EQ_INT(config_has_policy_eval(), 1);

  WamblePolicyDecision out;
  memset(&out, 0, sizeof(out));
  int rc = config_policy_eval("pubkey:00", "protocol.ctrl", "list_profiles", "",
                              "", "", "", 0, &out);
  T_ASSERT_EQ_INT(rc, 1);
  T_ASSERT_EQ_INT(out.allowed, 1);
  T_ASSERT_EQ_INT(out.permission_level, 7);
  T_ASSERT_STREQ(out.reason, "restored");
  T_ASSERT_STREQ(out.policy_version, "t1");

  config_free_snapshot(snap);
  return 0;
}

static int config_db_exec_sql(const char *sql) {
  char path[128];
  static unsigned long seq = 0;
  snprintf(path, sizeof(path), "build/test_config_db_sql_%lu.sql", ++seq);
  FILE *f = fopen(path, "wb");
  if (!f)
    return -1;
  fwrite(sql, 1, strlen(sql), f);
  fclose(f);
  return test_db_apply_sql_file(path);
}

static int config_db_prepare(void) {
  if (!wamble_db_available())
    return -1;
  if (test_db_apply_migrations(NULL) != 0)
    return -1;
  if (config_db_exec_sql(
          "TRUNCATE TABLE predictions, payouts, game_results, reservations, "
          "moves, boards, sessions, players, global_policy_rules, "
          "global_treatment_assignment_predicates, "
          "global_treatment_assignment_rules, global_treatment_group_outputs, "
          "global_treatment_group_edges, global_treatment_groups, "
          "global_runtime_config_revisions, global_runtime_config_blobs, "
          "global_identities, global_identity_tags RESTART IDENTITY "
          "CASCADE;") != 0)
    return -1;
  if (config_load(NULL, NULL, NULL, 0) < 0)
    return -1;
  if (db_set_global_store_connection(wamble_test_dsn()) != 0)
    return -1;
  if (db_init(wamble_test_dsn()) != 0)
    return -1;
  return 0;
}

static int config_network_seed_session(const uint8_t *token) {
  struct WambleMsg out = {0};
  struct WambleMsg in = {0};
  struct sockaddr_in dst;
  struct sockaddr_in from;
  wamble_socklen_t dst_len = (wamble_socklen_t)sizeof(dst);
  wamble_socket_t srv = create_and_bind_socket(0);
  if (srv == WAMBLE_INVALID_SOCKET)
    return -1;
  wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
  if (cli == WAMBLE_INVALID_SOCKET) {
    wamble_close_socket(srv);
    return -1;
  }
  if (getsockname(srv, (struct sockaddr *)&dst, &dst_len) != 0) {
    wamble_close_socket(cli);
    wamble_close_socket(srv);
    return -1;
  }
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  memcpy(out.token, token, TOKEN_LENGTH);
  out.ctrl = WAMBLE_CTRL_CLIENT_HELLO;
  if (send_unreliable_packet(cli, &out, &dst) != NET_OK) {
    wamble_close_socket(cli);
    wamble_close_socket(srv);
    return -1;
  }
  int received = -1;
  for (int i = 0; i < 100; i++) {
    received = receive_message(srv, &in, &from);
    if (received > 0)
      break;
  }
  wamble_close_socket(cli);
  wamble_close_socket(srv);
  return received > 0 ? 0 : -1;
}

WAMBLE_TEST(config_db_policy_validation_requires_trust_tier_rule) {
  if (config_db_prepare() != 0)
    T_FAIL_SIMPLE("config_db_prepare failed");
  T_ASSERT(db_validate_global_policy() != 0);
  T_ASSERT_STATUS_OK(config_db_exec_sql(
      "INSERT INTO global_policy_rules "
      "(global_identity_id, action, resource, scope, effect, permission_level, "
      " reason, source) "
      "VALUES (0, 'trust.tier', 'tier', '*', 'allow', 1, 'seed', 'manual');"));
  T_ASSERT_STATUS_OK(db_validate_global_policy());
  return 0;
}

WAMBLE_TEST(config_db_policy_precedence_exact_deny_over_group_and_global) {
  uint8_t token[TOKEN_LENGTH] = {0x10, 0x32, 0x54, 0x76, 0x98, 0xba,
                                 0xdc, 0xfe, 0x12, 0x34, 0x56, 0x78,
                                 0x9a, 0xbc, 0xde, 0xf0};
  if (config_db_prepare() != 0)
    T_FAIL_SIMPLE("config_db_prepare failed");
  const char *cfg_path = "build/test_policy_precedence.conf";
  const char *cfg = "(defprofile alpha ((def advertise 1) (def profile-group "
                    "\"trusted\")))\n";
  FILE *f = fopen(cfg_path, "wb");
  T_ASSERT(f != NULL);
  fwrite(cfg, 1, strlen(cfg), f);
  fclose(f);
  T_ASSERT_STATUS(config_load(cfg_path, NULL, NULL, 0), CONFIG_LOAD_OK);

  uint64_t sid = db_create_session(token, 0);
  T_ASSERT(sid > 0);

  WamblePolicyDecision out = {0};
  T_ASSERT_STATUS(db_resolve_policy_decision(token, "alpha", "trust.tier",
                                             "tier", NULL, NULL, &out),
                  DB_OK);
  T_ASSERT(out.global_identity_id > 0);

  char sql[1024];
  snprintf(sql, sizeof(sql),
           "INSERT INTO global_policy_rules "
           "(global_identity_id, action, resource, scope, effect, "
           " permission_level, reason, source) VALUES "
           "(0, 'trust.tier', 'tier', '*', 'allow', 1, 'global_allow', "
           "'manual'), "
           "(0, 'trust.tier', 'tier', 'profile_group:trusted', 'allow', 5, "
           "'group_allow', 'manual'), "
           "(%llu, 'trust.tier', 'tier', 'profile:alpha', 'deny', 0, "
           "'exact_deny', 'manual');",
           (unsigned long long)out.global_identity_id);
  T_ASSERT_STATUS_OK(config_db_exec_sql(sql));

  memset(&out, 0, sizeof(out));
  T_ASSERT_STATUS(db_resolve_policy_decision(token, "alpha", "trust.tier",
                                             "tier", NULL, NULL, &out),
                  DB_OK);
  T_ASSERT_EQ_INT(out.allowed, 0);
  T_ASSERT_STREQ(out.scope, "profile:alpha");
  T_ASSERT_STREQ(out.effect, "deny");
  return 0;
}

WAMBLE_TEST(config_db_policy_default_deny_can_be_overridden_by_treatment) {
  uint8_t token[TOKEN_LENGTH] = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
                                 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c,
                                 0x4d, 0x4e, 0x4f, 0x50};
  if (config_db_prepare() != 0)
    T_FAIL_SIMPLE("config_db_prepare failed");
  const char *cfg_path = "build/test_policy_default_deny_override.conf";
  const char *cfg =
      "(def experiment-enabled 1)\n"
      "(treatment-group \"vip\" 20)\n"
      "(treatment-default \"vip\")\n"
      "(treatment-behavior \"vip\" \"policy.resolve\" \"policy.allow\" 1)\n"
      "(treatment-behavior \"vip\" \"policy.resolve\" "
      "\"policy.permission_level.set\" 7)\n"
      "(treatment-behavior \"vip\" \"policy.resolve\" "
      "\"policy.reason\" \"experiment_allow\")\n";
  FILE *f = fopen(cfg_path, "wb");
  T_ASSERT(f != NULL);
  fwrite(cfg, 1, strlen(cfg), f);
  fclose(f);
  T_ASSERT_STATUS(config_load(cfg_path, NULL, NULL, 0), CONFIG_LOAD_OK);
  T_ASSERT_STATUS_OK(db_apply_config_treatment_rules("__default__"));

  T_ASSERT(db_create_session(token, 0) > 0);

  WamblePolicyDecision out = {0};
  T_ASSERT_STATUS(db_resolve_policy_decision(token, "", "game.move", "play",
                                             NULL, NULL, &out),
                  DB_OK);
  T_ASSERT_EQ_INT(out.allowed, 1);
  T_ASSERT_EQ_INT(out.permission_level, 7);
  T_ASSERT_STREQ(out.effect, "allow");
  T_ASSERT_STREQ(out.reason, "experiment_allow");
  return 0;
}

WAMBLE_TEST(config_db_policy_explicit_deny_can_be_overridden_by_treatment) {
  uint8_t token[TOKEN_LENGTH] = {0x51, 0x52, 0x53, 0x54, 0x55, 0x56,
                                 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c,
                                 0x5d, 0x5e, 0x5f, 0x60};
  if (config_db_prepare() != 0)
    T_FAIL_SIMPLE("config_db_prepare failed");
  const char *cfg_path = "build/test_policy_explicit_deny_override.conf";
  const char *cfg =
      "(def experiment-enabled 1)\n"
      "(treatment-group \"vip\" 20)\n"
      "(treatment-default \"vip\")\n"
      "(treatment-behavior \"vip\" \"policy.resolve\" \"policy.allow\" 1)\n"
      "(treatment-behavior \"vip\" \"policy.resolve\" "
      "\"policy.reason\" \"experiment_override\")\n";
  FILE *f = fopen(cfg_path, "wb");
  T_ASSERT(f != NULL);
  fwrite(cfg, 1, strlen(cfg), f);
  fclose(f);
  T_ASSERT_STATUS(config_load(cfg_path, NULL, NULL, 0), CONFIG_LOAD_OK);
  T_ASSERT_STATUS_OK(db_apply_config_treatment_rules("__default__"));

  T_ASSERT(db_create_session(token, 0) > 0);
  T_ASSERT_STATUS_OK(config_db_exec_sql(
      "INSERT INTO global_policy_rules "
      "(global_identity_id, action, resource, scope, effect, permission_level, "
      " reason, source) "
      "VALUES (0, 'spectate.access', 'view', '*', 'deny', 0, "
      "'policy_deny', 'manual');"));

  WamblePolicyDecision out = {0};
  T_ASSERT_STATUS(db_resolve_policy_decision(token, "", "spectate.access",
                                             "view", "mode", "focus", &out),
                  DB_OK);
  T_ASSERT_EQ_INT(out.allowed, 1);
  T_ASSERT_STREQ(out.effect, "allow");
  T_ASSERT_STREQ(out.reason, "experiment_override");
  return 0;
}

WAMBLE_TEST(config_db_resolve_assigns_identity_when_session_identity_missing) {
  uint8_t token[TOKEN_LENGTH] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                                 0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
                                 0x70, 0x80, 0x90, 0xa0};
  if (config_db_prepare() != 0)
    T_FAIL_SIMPLE("config_db_prepare failed");
  T_ASSERT_STATUS_OK(config_db_exec_sql(
      "INSERT INTO global_policy_rules "
      "(global_identity_id, action, resource, scope, effect, permission_level, "
      " reason, source) "
      "VALUES (0, 'trust.tier', 'tier', '*', 'allow', 1, 'seed', 'manual');"));
  T_ASSERT(db_create_session(token, 0) > 0);
  WamblePolicyDecision out = {0};
  T_ASSERT_STATUS(db_resolve_policy_decision(token, "", "trust.tier", "tier",
                                             NULL, NULL, &out),
                  DB_OK);
  T_ASSERT(out.global_identity_id > 0);
  T_ASSERT_EQ_INT(out.allowed, 1);
  return 0;
}

WAMBLE_TEST(config_db_apply_policy_rule_with_identity_selector) {
  if (config_db_prepare() != 0)
    T_FAIL_SIMPLE("config_db_prepare failed");
  T_ASSERT_STATUS_OK(config_db_exec_sql(
      "INSERT INTO global_identities (public_key) "
      "VALUES (decode('00112233445566778899aabbccddeeff00112233445566778899"
      "aabbccddeeff', 'hex'));"));

  const char *cfg_path = "build/test_policy_identity_selector.conf";
  const char *cfg =
      "(policy-allow \"identity:1\" \"trust.tier\" \"profile:alpha\" 7 "
      "\"seed\")\n";
  FILE *f = fopen(cfg_path, "wb");
  T_ASSERT(f != NULL);
  fwrite(cfg, 1, strlen(cfg), f);
  fclose(f);
  T_ASSERT_STATUS(config_load(cfg_path, NULL, NULL, 0), CONFIG_LOAD_OK);
  T_ASSERT_STATUS_OK(db_apply_config_policy_rules("__default__"));

  T_ASSERT_STATUS_OK(config_db_exec_sql(
      "DO $$ BEGIN "
      "IF NOT EXISTS ("
      "  SELECT 1 FROM global_policy_rules "
      "  WHERE global_identity_id = 1 "
      "    AND action = 'trust.tier' "
      "    AND resource = 'tier' "
      "    AND scope = 'profile:alpha' "
      "    AND effect = 'allow' "
      "    AND permission_level = 7"
      ") THEN RAISE EXCEPTION 'missing identity selector rule'; "
      "END IF; END $$;"));
  return 0;
}

WAMBLE_TEST(config_db_apply_policy_rule_with_tag_selector) {
  if (config_db_prepare() != 0)
    T_FAIL_SIMPLE("config_db_prepare failed");
  T_ASSERT_STATUS_OK(config_db_exec_sql(
      "INSERT INTO global_identities (public_key) VALUES "
      "(decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaa', 'hex')), "
      "(decode('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      "bbbb', 'hex'));"
      "INSERT INTO global_identity_tags (global_identity_id, tag) "
      "VALUES (1, 'ops'), (2, 'ops');"));

  const char *cfg_path = "build/test_policy_tag_selector.conf";
  const char *cfg =
      "(policy-deny \"tag:ops\" \"profile.discover\" \"profile_selector:"
      "internal\" \"seed\")\n";
  FILE *f = fopen(cfg_path, "wb");
  T_ASSERT(f != NULL);
  fwrite(cfg, 1, strlen(cfg), f);
  fclose(f);
  T_ASSERT_STATUS(config_load(cfg_path, NULL, NULL, 0), CONFIG_LOAD_OK);
  T_ASSERT_STATUS_OK(db_apply_config_policy_rules("__default__"));

  T_ASSERT_STATUS_OK(config_db_exec_sql(
      "DO $$ DECLARE c INT; BEGIN "
      "SELECT COUNT(*) INTO c FROM global_policy_rules "
      "WHERE action = 'profile.discover' "
      "  AND resource = 'profile_selector:internal' "
      "  AND scope = '*' "
      "  AND effect = 'deny' "
      "  AND global_identity_id IN (1,2); "
      "IF c <> 2 THEN RAISE EXCEPTION 'expected two tag-expanded rules'; "
      "END IF; END $$;"));
  return 0;
}

WAMBLE_TEST(config_db_reapply_policy_rules_reexpands_tag_selectors) {
  if (config_db_prepare() != 0)
    T_FAIL_SIMPLE("config_db_prepare failed");
  T_ASSERT_STATUS_OK(config_db_exec_sql(
      "INSERT INTO global_identities (public_key) VALUES "
      "(decode('111111111111111111111111111111111111111111111111111111111111"
      "1111', 'hex')), "
      "(decode('222222222222222222222222222222222222222222222222222222222222"
      "2222', 'hex'));"
      "INSERT INTO global_identity_tags (global_identity_id, tag) "
      "VALUES (1, 'ops');"));

  const char *cfg_path = "build/test_policy_tag_reapply.conf";
  const char *cfg =
      "(policy-deny \"tag:ops\" \"profile.discover\" \"profile_selector:"
      "internal\" \"seed\")\n";
  FILE *f = fopen(cfg_path, "wb");
  T_ASSERT(f != NULL);
  fwrite(cfg, 1, strlen(cfg), f);
  fclose(f);
  T_ASSERT_STATUS(config_load(cfg_path, NULL, NULL, 0), CONFIG_LOAD_OK);

  T_ASSERT_STATUS_OK(db_apply_config_policy_rules("__default__"));
  T_ASSERT_STATUS_OK(config_db_exec_sql(
      "DO $$ DECLARE c INT; BEGIN "
      "SELECT COUNT(*) INTO c FROM global_policy_rules "
      "WHERE action = 'profile.discover' "
      "  AND resource = 'profile_selector:internal' "
      "  AND effect = 'deny'; "
      "IF c <> 1 THEN RAISE EXCEPTION 'expected one expanded rule'; "
      "END IF; END $$;"));

  T_ASSERT_STATUS_OK(config_db_exec_sql(
      "INSERT INTO global_identity_tags (global_identity_id, tag) "
      "VALUES (2, 'ops');"));
  T_ASSERT_STATUS_OK(db_apply_config_policy_rules("__default__"));

  T_ASSERT_STATUS_OK(config_db_exec_sql(
      "DO $$ DECLARE c INT; BEGIN "
      "SELECT COUNT(*) INTO c FROM global_policy_rules "
      "WHERE action = 'profile.discover' "
      "  AND resource = 'profile_selector:internal' "
      "  AND effect = 'deny' "
      "  AND global_identity_id IN (1, 2); "
      "IF c <> 2 THEN RAISE EXCEPTION 'expected refreshed expanded rules'; "
      "END IF; END $$;"));
  return 0;
}

WAMBLE_TEST(config_db_apply_treatment_rules_and_assign_session) {
  uint8_t token[TOKEN_LENGTH] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                                 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76,
                                 0x98, 0xba, 0xdc, 0xfe};
  if (config_db_prepare() != 0)
    T_FAIL_SIMPLE("config_db_prepare failed");
  const char *cfg_path = "build/test_treatment_assign.conf";
  const char *cfg =
      "(def experiment-enabled 1)\n"
      "(treatment-group \"control\" 10)\n"
      "(treatment-group \"vip\" 20)\n"
      "(treatment-default \"control\")\n"
      "(treatment-assign \"*\" \"*\" \"vip\" 50)\n"
      "(treatment-edge \"vip\" \"control\")\n"
      "(treatment-tag \"vip\" \"ops\")\n"
      "(treatment-feature \"vip\" \"prediction.gated\" 1)\n"
      "(treatment-meta \"vip\" \"prediction.submit\" \"note\" \"boosted\")\n";
  FILE *f = fopen(cfg_path, "wb");
  T_ASSERT(f != NULL);
  fwrite(cfg, 1, strlen(cfg), f);
  fclose(f);
  T_ASSERT_STATUS(config_load(cfg_path, NULL, NULL, 0), CONFIG_LOAD_OK);
  T_ASSERT_STATUS_OK(db_apply_config_treatment_rules("__default__"));
  T_ASSERT_STATUS_OK(db_validate_global_treatments());

  uint64_t session_id = db_create_session(token, 0);
  T_ASSERT(session_id > 0);

  WambleTreatmentAction out[8];
  int out_count = 0;
  T_ASSERT_STATUS(db_resolve_treatment_actions(token, "", "prediction.submit",
                                               "control", NULL, 0, out, 8,
                                               &out_count),
                  DB_OK);
  T_ASSERT(out_count >= 2);

  WambleTreatmentAssignment assignment = {0};
  T_ASSERT_STATUS(db_get_session_treatment_assignment(token, &assignment),
                  DB_OK);
  T_ASSERT_STREQ(assignment.group_key, "vip");

  T_ASSERT_STATUS_OK(config_db_exec_sql(
      "DO $$ DECLARE c INT; BEGIN "
      "SELECT COUNT(*) INTO c FROM global_identity_tags WHERE tag = 'ops'; "
      "IF c <> 1 THEN RAISE EXCEPTION 'expected treatment tag'; "
      "END IF; END $$;"));
  return 0;
}

WAMBLE_TEST(config_db_apply_treatment_view_rules) {
  uint8_t token[TOKEN_LENGTH] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
                                 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
                                 0x3d, 0x3e, 0x3f, 0x40};
  if (config_db_prepare() != 0)
    T_FAIL_SIMPLE("config_db_prepare failed");
  const char *cfg_path = "build/test_treatment_view_rules.conf";
  const char *cfg =
      "(def experiment-enabled 1)\n"
      "(treatment-group \"vip\" 20)\n"
      "(treatment-default \"vip\")\n"
      "(treatment-visible-fen \"vip\" \"board.read\" "
      "\"8/8/8/8/8/8/8/8 w - - 0 1\")\n"
      "(treatment-predictions-from-moves \"vip\" \"prediction.read\")\n";
  FILE *f = fopen(cfg_path, "wb");
  T_ASSERT(f != NULL);
  fwrite(cfg, 1, strlen(cfg), f);
  fclose(f);
  T_ASSERT_STATUS(config_load(cfg_path, NULL, NULL, 0), CONFIG_LOAD_OK);
  T_ASSERT_STATUS_OK(db_apply_config_treatment_rules("__default__"));

  T_ASSERT(db_create_session(token, 0) > 0);

  WambleFact facts[2] = {0};
  snprintf(facts[0].key, sizeof(facts[0].key), "%s", "board.id");
  facts[0].value_type = WAMBLE_TREATMENT_VALUE_INT;
  facts[0].int_value = 1;
  snprintf(facts[1].key, sizeof(facts[1].key), "%s", "board.fen");
  facts[1].value_type = WAMBLE_TREATMENT_VALUE_STRING;
  snprintf(facts[1].string_value, sizeof(facts[1].string_value), "%s",
           "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1");

  WambleTreatmentAction actions[8];
  int action_count = 0;
  T_ASSERT_STATUS(db_resolve_treatment_actions(token, "", "board.read", NULL,
                                               facts, 2, actions, 8,
                                               &action_count),
                  DB_OK);
  T_ASSERT_EQ_INT(action_count, 1);
  T_ASSERT_STREQ(actions[0].output_kind, "view");
  T_ASSERT_STREQ(actions[0].output_key, "board.fen");
  T_ASSERT_STREQ(actions[0].string_value, "8/8/8/8/8/8/8/8 w - - 0 1");

  memset(actions, 0, sizeof(actions));
  action_count = 0;
  T_ASSERT_STATUS(db_resolve_treatment_actions(token, "", "prediction.read",
                                               NULL, facts, 2, actions, 8,
                                               &action_count),
                  DB_OK);
  T_ASSERT_EQ_INT(action_count, 1);
  T_ASSERT_STREQ(actions[0].output_kind, "view");
  T_ASSERT_STREQ(actions[0].output_key, "prediction.source");
  T_ASSERT_STREQ(actions[0].string_value, "moves");
  return 0;
}

WAMBLE_TEST(config_db_apply_treatment_edges_without_snapshot_revision) {
  if (config_db_prepare() != 0)
    T_FAIL_SIMPLE("config_db_prepare failed");
  const char *cfg_path = "build/test_treatment_edges_without_snapshot.conf";
  const char *cfg = "(def experiment-enabled 1)\n"
                    "(treatment-group \"control\" 10)\n"
                    "(treatment-group \"vip\" 20)\n"
                    "(treatment-default \"control\")\n"
                    "(treatment-edge \"vip\" \"control\")\n";
  FILE *f = fopen(cfg_path, "wb");
  T_ASSERT(f != NULL);
  fwrite(cfg, 1, strlen(cfg), f);
  fclose(f);
  T_ASSERT_STATUS(config_load(cfg_path, NULL, NULL, 0), CONFIG_LOAD_OK);
  T_ASSERT_STATUS_OK(db_apply_config_treatment_rules("__default__"));
  T_ASSERT_EQ_INT(db_treatment_edge_allows("__default__", "vip", "control"), 1);
  T_ASSERT_STATUS_OK(config_db_exec_sql(
      "DO $$ DECLARE c INT; BEGIN "
      "SELECT COUNT(*) INTO c FROM global_treatment_group_edges "
      "WHERE source_group_key = 'vip' AND target_group_key = 'control' "
      "  AND snapshot_revision_id = 0; "
      "IF c <> 1 THEN RAISE EXCEPTION 'expected edge without snapshot'; "
      "END IF; END $$;"));
  return 0;
}

WAMBLE_TEST(config_db_treatment_reassigns_when_runtime_facts_arrive) {
  uint8_t token[TOKEN_LENGTH] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                                 0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
                                 0x70, 0x80, 0x90, 0xa0};
  if (config_db_prepare() != 0)
    T_FAIL_SIMPLE("config_db_prepare failed");
  const char *cfg_path = "build/test_treatment_predicate_reassign.conf";
  const char *cfg = "(def experiment-enabled 1)\n"
                    "(treatment-group \"control\" 10)\n"
                    "(treatment-group \"vip\" 20)\n"
                    "(treatment-default \"control\")\n"
                    "(treatment-assign \"*\" \"*\" \"vip\" 50 "
                    "(match \"session.games\" \"gte\" 3))\n"
                    "(treatment-feature \"control\" \"prediction.gated\" 0)\n"
                    "(treatment-feature \"vip\" \"prediction.gated\" 1)\n";
  FILE *f = fopen(cfg_path, "wb");
  T_ASSERT(f != NULL);
  fwrite(cfg, 1, strlen(cfg), f);
  fclose(f);
  T_ASSERT_STATUS(config_load(cfg_path, NULL, NULL, 0), CONFIG_LOAD_OK);
  T_ASSERT_STATUS_OK(db_apply_config_treatment_rules("__default__"));
  T_ASSERT_STATUS_OK(db_validate_global_treatments());

  uint64_t session_id = db_create_session(token, 0);
  T_ASSERT(session_id > 0);

  WambleTreatmentAssignment assignment = {0};
  T_ASSERT_STATUS(db_get_session_treatment_assignment(token, &assignment),
                  DB_NOT_FOUND);

  WambleTreatmentAction actions[8];
  int action_count = 0;
  T_ASSERT_STATUS(db_resolve_treatment_actions(token, "", "prediction.submit",
                                               NULL, NULL, 0, actions, 8,
                                               &action_count),
                  DB_OK);
  T_ASSERT_STATUS(db_get_session_treatment_assignment(token, &assignment),
                  DB_OK);
  T_ASSERT_STREQ(assignment.group_key, "control");

  WambleFact facts[1];
  memset(facts, 0, sizeof(facts));
  snprintf(facts[0].key, sizeof(facts[0].key), "%s", "session.games");
  facts[0].value_type = WAMBLE_TREATMENT_VALUE_INT;
  facts[0].int_value = 3;
  T_ASSERT_STATUS(db_resolve_treatment_actions(token, "", "prediction.submit",
                                               NULL, facts, 1, actions, 8,
                                               &action_count),
                  DB_OK);
  T_ASSERT_STATUS(db_get_session_treatment_assignment(token, &assignment),
                  DB_OK);
  T_ASSERT_STREQ(assignment.group_key, "vip");
  return 0;
}

WAMBLE_TEST(config_network_treatment_group_refreshes_after_reassignment) {
  uint8_t token[TOKEN_LENGTH] = {0xde, 0xad, 0xbe, 0xef, 0x10, 0x20,
                                 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
                                 0x90, 0xa0, 0xb0, 0xc0};
  if (config_db_prepare() != 0)
    T_FAIL_SIMPLE("config_db_prepare failed");
  const char *cfg_path = "build/test_network_treatment_refresh.conf";
  const char *cfg = "(def experiment-enabled 1)\n"
                    "(treatment-group \"control\" 10)\n"
                    "(treatment-group \"vip\" 20)\n"
                    "(treatment-default \"control\")\n"
                    "(treatment-assign \"*\" \"*\" \"vip\" 50 "
                    "(match \"session.games\" \"gte\" 3))\n"
                    "(treatment-feature \"control\" \"prediction.gated\" 0)\n"
                    "(treatment-feature \"vip\" \"prediction.gated\" 1)\n";
  FILE *f = fopen(cfg_path, "wb");
  T_ASSERT(f != NULL);
  fwrite(cfg, 1, strlen(cfg), f);
  fclose(f);
  T_ASSERT_STATUS(config_load(cfg_path, NULL, NULL, 0), CONFIG_LOAD_OK);
  T_ASSERT_STATUS_OK(db_apply_config_treatment_rules("__default__"));
  T_ASSERT(db_create_session(token, 0) > 0);

  network_init_thread_state();
  T_ASSERT_STATUS_OK(config_network_seed_session(token));

  WambleTreatmentAction actions[8];
  int action_count = 0;
  T_ASSERT_STATUS(db_resolve_treatment_actions(token, "", "prediction.submit",
                                               NULL, NULL, 0, actions, 8,
                                               &action_count),
                  DB_OK);
  char current_group[128] = {0};
  T_ASSERT_STATUS_OK(network_get_session_treatment_group(
      token, current_group, sizeof(current_group)));
  T_ASSERT_STREQ(current_group, "control");

  WambleFact facts[1] = {0};
  snprintf(facts[0].key, sizeof(facts[0].key), "%s", "session.games");
  facts[0].value_type = WAMBLE_TREATMENT_VALUE_INT;
  facts[0].int_value = 3;
  T_ASSERT_STATUS(db_resolve_treatment_actions(token, "", "prediction.submit",
                                               NULL, facts, 1, actions, 8,
                                               &action_count),
                  DB_OK);
  memset(current_group, 0, sizeof(current_group));
  T_ASSERT_STATUS_OK(network_get_session_treatment_group(
      token, current_group, sizeof(current_group)));
  T_ASSERT_STREQ(current_group, "vip");
  return 0;
}

WAMBLE_TEST(config_db_treatment_scopes_by_profile_source) {
  uint8_t token_alpha[TOKEN_LENGTH] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                                       0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
                                       0x1d, 0x1e, 0x1f, 0x20};
  uint8_t token_beta[TOKEN_LENGTH] = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
                                      0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
                                      0x2d, 0x2e, 0x2f, 0x30};
  if (config_db_prepare() != 0)
    T_FAIL_SIMPLE("config_db_prepare failed");

  const char *alpha_path = "build/test_treatment_profile_alpha.conf";
  const char *alpha_cfg =
      "(def experiment-enabled 1)\n"
      "(treatment-group \"control\" 10)\n"
      "(treatment-default \"control\")\n"
      "(treatment-feature \"control\" \"prediction.gated\" 1)\n"
      "(treatment-edge \"control\" \"vip\")\n";
  FILE *f = fopen(alpha_path, "wb");
  T_ASSERT(f != NULL);
  fwrite(alpha_cfg, 1, strlen(alpha_cfg), f);
  fclose(f);
  T_ASSERT_STATUS(config_load(alpha_path, NULL, NULL, 0), CONFIG_LOAD_OK);
  T_ASSERT_STATUS_OK(db_apply_config_treatment_rules("alpha"));

  const char *beta_path = "build/test_treatment_profile_beta.conf";
  const char *beta_cfg =
      "(def experiment-enabled 1)\n"
      "(treatment-group \"control\" 10)\n"
      "(treatment-group \"vip\" 20)\n"
      "(treatment-default \"vip\")\n"
      "(treatment-feature \"control\" \"prediction.gated\" 0)\n";
  f = fopen(beta_path, "wb");
  T_ASSERT(f != NULL);
  fwrite(beta_cfg, 1, strlen(beta_cfg), f);
  fclose(f);
  T_ASSERT_STATUS(config_load(beta_path, NULL, NULL, 0), CONFIG_LOAD_OK);
  T_ASSERT_STATUS_OK(db_apply_config_treatment_rules("beta"));
  T_ASSERT_STATUS_OK(db_validate_global_treatments());

  T_ASSERT(db_create_session(token_alpha, 0) > 0);
  T_ASSERT(db_create_session(token_beta, 0) > 0);

  WambleTreatmentAction actions[8];
  int action_count = 0;
  T_ASSERT_STATUS(db_resolve_treatment_actions(token_alpha, "alpha",
                                               "prediction.submit", NULL, NULL,
                                               0, actions, 8, &action_count),
                  DB_OK);
  WambleTreatmentAssignment assignment = {0};
  T_ASSERT_STATUS(db_get_session_treatment_assignment(token_alpha, &assignment),
                  DB_OK);
  T_ASSERT_STREQ(assignment.group_key, "control");
  T_ASSERT_EQ_INT(action_count, 1);
  T_ASSERT_STREQ(actions[0].output_key, "prediction.gated");
  T_ASSERT(actions[0].value_type == WAMBLE_TREATMENT_VALUE_BOOL ||
           actions[0].value_type == WAMBLE_TREATMENT_VALUE_INT);
  T_ASSERT_EQ_INT(actions[0].value_type == WAMBLE_TREATMENT_VALUE_BOOL
                      ? actions[0].bool_value
                      : (actions[0].int_value != 0),
                  1);

  T_ASSERT_STATUS(db_resolve_treatment_actions(token_beta, "beta",
                                               "prediction.submit", NULL, NULL,
                                               0, actions, 8, &action_count),
                  DB_OK);
  T_ASSERT_STATUS(db_get_session_treatment_assignment(token_beta, &assignment),
                  DB_OK);
  T_ASSERT_STREQ(assignment.group_key, "vip");

  T_ASSERT_EQ_INT(db_treatment_edge_allows("alpha", "control", "vip"), 1);
  T_ASSERT_EQ_INT(db_treatment_edge_allows("beta", "control", "vip"), 0);
  return 0;
}

WAMBLE_TESTS_BEGIN_NAMED(wamble_register_tests_config)
WAMBLE_TESTS_ADD_FM(config_basic_eval, "config");
WAMBLE_TESTS_ADD_FM(config_defaults_no_file, "config");
WAMBLE_TESTS_ADD_FM(config_env_getenv, "config");
WAMBLE_TESTS_ADD_FM(config_push_pop_stack, "config");
WAMBLE_TESTS_ADD_FM(config_profile_inheritance, "config");
WAMBLE_TESTS_ADD_EX_SM(config_speed_parse_minimal, WAMBLE_SUITE_SPEED, "config",
                       NULL, NULL, 5000);
WAMBLE_TESTS_ADD_EX_SM(config_perf_parse_medium, WAMBLE_SUITE_PERFORMANCE,
                       "config", NULL, NULL, 10000);
WAMBLE_TESTS_ADD_EX_SM(config_stress_many_profiles, WAMBLE_SUITE_STRESS,
                       "config", NULL, NULL, 15000);
WAMBLE_TESTS_ADD_FM(config_parse_doubles_and_strings, "config");
WAMBLE_TESTS_ADD_FM(config_treatment_groups_parse, "config");
WAMBLE_TESTS_ADD_FM(config_profile_select_and_not_found, "config");
WAMBLE_TESTS_ADD_FM(config_profile_inheritance_variants, "config");
WAMBLE_TESTS_ADD_FM(config_profile_missing_base_skipped, "config");
WAMBLE_TESTS_ADD_FM(config_env_getenv_unset, "config");
WAMBLE_TESTS_ADD_FM(config_snapshot_restore_rebuilds_policy_eval, "config");
WAMBLE_TESTS_ADD_DB_FM(config_db_policy_validation_requires_trust_tier_rule,
                       "config");
WAMBLE_TESTS_ADD_DB_FM(
    config_db_policy_precedence_exact_deny_over_group_and_global, "config");
WAMBLE_TESTS_ADD_DB_FM(
    config_db_policy_default_deny_can_be_overridden_by_treatment, "config");
WAMBLE_TESTS_ADD_DB_FM(
    config_db_policy_explicit_deny_can_be_overridden_by_treatment, "config");
WAMBLE_TESTS_ADD_DB_FM(
    config_db_resolve_assigns_identity_when_session_identity_missing, "config");
WAMBLE_TESTS_ADD_DB_FM(config_db_apply_policy_rule_with_identity_selector,
                       "config");
WAMBLE_TESTS_ADD_DB_FM(config_db_apply_policy_rule_with_tag_selector, "config");
WAMBLE_TESTS_ADD_DB_FM(config_db_reapply_policy_rules_reexpands_tag_selectors,
                       "config");
WAMBLE_TESTS_ADD_DB_FM(config_db_apply_treatment_rules_and_assign_session,
                       "config");
WAMBLE_TESTS_ADD_DB_FM(config_db_apply_treatment_view_rules, "config");
WAMBLE_TESTS_ADD_DB_FM(
    config_db_apply_treatment_edges_without_snapshot_revision, "config");
WAMBLE_TESTS_ADD_DB_FM(config_db_treatment_reassigns_when_runtime_facts_arrive,
                       "config");
WAMBLE_TESTS_ADD_DB_FM(
    config_network_treatment_group_refreshes_after_reassignment, "config");
WAMBLE_TESTS_ADD_DB_FM(config_db_treatment_scopes_by_profile_source, "config");
WAMBLE_TESTS_END()
