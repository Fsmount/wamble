#include "common/wamble_test.h"
#include "wamble/wamble.h"

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
  T_ASSERT_EQ_INT(get_config()->experiment_enabled, 0);
  T_ASSERT_EQ_INT(get_config()->experiment_seed, 0);
  T_ASSERT_EQ_INT(get_config()->experiment_arms, 1);
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
                    "(def experiment-arms 7)\n"
                    "(def experiment-pairings \"0:0,0:1,1:*\")\n"
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
  T_ASSERT_EQ_INT(get_config()->experiment_arms, 7);
  T_ASSERT_STREQ(get_config()->experiment_pairings, "0:0,0:1,1:*");
  T_ASSERT_STREQ(get_config()->state_dir, "/var/tmp/wamble");
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
WAMBLE_TESTS_ADD_FM(config_profile_select_and_not_found, "config");
WAMBLE_TESTS_ADD_FM(config_profile_inheritance_variants, "config");
WAMBLE_TESTS_ADD_FM(config_profile_missing_base_skipped, "config");
WAMBLE_TESTS_ADD_FM(config_env_getenv_unset, "config");
WAMBLE_TESTS_END()
