#ifndef WAMBLE_TEST_HELPERS_H
#define WAMBLE_TEST_HELPERS_H

#include <stddef.h>
#include <stdint.h>

const char *wamble_test_dsn(void);
int wamble_db_available(void);
int wamble_should_skip_db_tests(void);
int wamble_test_ensure_dir(const char *path);
int wamble_test_path(char *out, size_t out_len, const char *subdir,
                     const char *name);
int wamble_test_mkstemp_file(char *out, size_t out_len, const char *subdir,
                             const char *prefix);

int wamble_test_write_config(const char *path, int port, int timeout_ms,
                             int inactivity_timeout, int reservation_timeout,
                             const char *db_host, const char *db_user,
                             const char *db_pass, const char *db_name,
                             int log_level);

int wamble_test_state_dir(char *out, size_t out_len);
int wamble_test_set_state_env(void);
int wamble_test_set_state_dir_env(void);

void wamble_metric(const char *name, const char *fmt, ...);

uint64_t wamble_now_nanos(void);

int test_db_create_schema_if_needed(const char *schema_name);
int test_db_set_search_path(const char *schema_name);
int test_db_apply_sql_file(const char *sql_path);
int test_db_apply_migrations(const char *schema_name);
int test_db_apply_fixture(const char *schema_name);
int test_db_reset(const char *schema_name);
int test_db_drop_schema(const char *schema_name);
int test_db_reset_schema(const char *schema_name);

#endif
