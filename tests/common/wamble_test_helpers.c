#define _XOPEN_SOURCE 700
#include "wamble_test_helpers.h"

#include "wamble/wamble.h"

#include <errno.h>
#ifdef WAMBLE_ENABLE_DB
#include <libpq-fe.h>
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#if defined(WAMBLE_PLATFORM_WINDOWS)
#include <direct.h>
#include <io.h>
#else
#include <unistd.h>
#endif

static int write_file(const char *path, const char *fmt, ...) {
  FILE *f = fopen(path, "w");
  if (!f)
    return -1;
  va_list ap;
  va_start(ap, fmt);
  vfprintf(f, fmt, ap);
  va_end(ap);
  fclose(f);
  return 0;
}

const char *wamble_test_dsn(void) {
  const char *dsn = getenv("WAMBLE_TEST_DSN");
  return (dsn && *dsn) ? dsn : NULL;
}

int wamble_db_available(void) {
#ifdef WAMBLE_ENABLE_DB
  const char *dsn = wamble_test_dsn();
  return (dsn && *dsn) ? 1 : 0;
#else
  return 0;
#endif
}

int wamble_should_skip_db_tests(void) {
  const char *skip = getenv("WAMBLE_SKIP_DB_TESTS");
  if (skip && (*skip == '1' || *skip == 'y' || *skip == 'Y'))
    return 1;
  return wamble_db_available() ? 0 : 1;
}

int wamble_test_ensure_dir(const char *path) {
  struct stat st;
  if (stat(path, &st) == 0) {
    if ((st.st_mode & S_IFMT) == S_IFDIR)
      return 0;
    return -1;
  }
#if defined(WAMBLE_PLATFORM_WINDOWS)
  if (_mkdir(path) != 0 && errno != EEXIST)
    return -1;
#else
  if (mkdir(path, 0777) != 0 && errno != EEXIST)
    return -1;
#endif
  return 0;
}

int wamble_test_path(char *out, size_t out_len, const char *subdir,
                     const char *name) {
  if (wamble_test_ensure_dir("build") != 0)
    return -1;
  if (wamble_test_ensure_dir("build/test-fixtures") != 0)
    return -1;
  char dir[512];
  if (subdir && *subdir) {
    snprintf(dir, sizeof dir, "build/test-fixtures/%s", subdir);
    if (wamble_test_ensure_dir(dir) != 0)
      return -1;
  } else {
    snprintf(dir, sizeof dir, "build/test-fixtures");
  }
  if (name && *name)
    snprintf(out, out_len, "%s/%s", dir, name);
  else
    snprintf(out, out_len, "%s", dir);
  return 0;
}

int wamble_test_write_config(const char *path, int port, int timeout_ms,
                             int inactivity_timeout, int reservation_timeout,
                             const char *db_host, const char *db_user,
                             const char *db_pass, const char *db_name,
                             int log_level) {
  return write_file(path,
                    "(def port %d)\n"
                    "(def timeout-ms %d)\n"
                    "(def inactivity-timeout %d)\n"
                    "(def reservation-timeout %d)\n"
                    "(def db-host \"%s\")\n"
                    "(def db-user \"%s\")\n"
                    "(def db-pass \"%s\")\n"
                    "(def db-name \"%s\")\n"
                    "(def log-level %d)\n",
                    port, timeout_ms, inactivity_timeout, reservation_timeout,
                    db_host ? db_host : "localhost",
                    db_user ? db_user : "wamble", db_pass ? db_pass : "wamble",
                    db_name ? db_name : "wamble_test", log_level);
}

int wamble_test_state_dir(char *out, size_t out_len) {
  return wamble_test_path(out, out_len, "state", NULL);
}

static void wamble_set_env_kv(const char *key, const char *val) {
#if defined(WAMBLE_PLATFORM_WINDOWS)
  _putenv_s(key, val ? val : "");
#else
  if (val)
    setenv(key, val, 1);
  else
    unsetenv(key);
#endif
}

void wamble_metric(const char *name, const char *fmt, ...) {
  if (!name)
    name = "metric";
  fprintf(stdout, "metric: %s ", name);
  va_list ap;
  va_start(ap, fmt);
  if (fmt && *fmt)
    vfprintf(stdout, fmt, ap);
  va_end(ap);
  fprintf(stdout, "\n");
}

uint64_t wamble_now_nanos(void) {
#if defined(WAMBLE_PLATFORM_WINDOWS)
  LARGE_INTEGER freq, counter;
  if (QueryPerformanceFrequency(&freq) && QueryPerformanceCounter(&counter)) {
    uint64_t f = (uint64_t)freq.QuadPart;
    uint64_t c = (uint64_t)counter.QuadPart;
    uint64_t sec = c / f;
    uint64_t rem = c % f;
    uint64_t nanos = sec * 1000000000ULL + (rem * 1000000000ULL) / f;
    return nanos;
  }
  return (uint64_t)GetTickCount64() * 1000000ULL;
#elif defined(WAMBLE_PLATFORM_POSIX)
  struct timespec ts;
#ifdef CLOCK_MONOTONIC
  if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
  if (clock_gettime(CLOCK_REALTIME, &ts) == 0)
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
  return (uint64_t)time(NULL) * 1000000000ULL;
#else
  return (uint64_t)time(NULL) * 1000000000ULL;
#endif
}

int wamble_test_mkstemp_file(char *out, size_t out_len, const char *subdir,
                             const char *prefix) {
  char dir[512];
  if (wamble_test_path(dir, sizeof dir, subdir, NULL) != 0)
    return -1;
  const char *pfx = (prefix && *prefix) ? prefix : "tmp_";
  size_t dir_len = strnlen(dir, sizeof dir);
  size_t pfx_len = strlen(pfx);
  const char suffix[] = "XXXXXX";
  size_t need = dir_len + 1 + pfx_len + sizeof(suffix);
  if (need > sizeof((char[512]){0}))
    return -1;
  char tmpl[512];
  size_t pos = 0;
  memcpy(tmpl + pos, dir, dir_len);
  pos += dir_len;
  tmpl[pos++] = '/';
  memcpy(tmpl + pos, pfx, pfx_len);
  pos += pfx_len;
  memcpy(tmpl + pos, suffix, sizeof(suffix));
  int fd = wamble_mkstemp(tmpl);
  if (fd < 0)
    return -1;
#if defined(WAMBLE_PLATFORM_WINDOWS)
  _close(fd);
#else
  close(fd);
#endif
  size_t need_out = strlen(tmpl) + 1;
  if (out_len < need_out)
    return -1;
  memcpy(out, tmpl, need_out);
  return 0;
}

int wamble_test_set_state_env(void) {
  char path[512];
  if (wamble_test_mkstemp_file(path, sizeof path, "state", "state_") != 0)
    return -1;
  wamble_set_env_kv("WAMBLE_STATE_FILE", path);
  return 0;
}

int wamble_test_set_state_dir_env(void) {
  char dir[512];
  if (wamble_test_state_dir(dir, sizeof dir) != 0)
    return -1;
  wamble_set_env_kv("WAMBLE_STATE_DIR", dir);
  return 0;
}

#ifdef WAMBLE_ENABLE_DB
static PGconn *db_connect(void) {
  const char *dsn = wamble_test_dsn();
  if (!dsn)
    return NULL;
  PGconn *c = PQconnectdb(dsn);
  if (PQstatus(c) != CONNECTION_OK) {
    PQfinish(c);
    return NULL;
  }
  return c;
}
#endif

#ifdef WAMBLE_ENABLE_DB
static int exec1(PGconn *c, const char *sql) {
  PGresult *r = PQexec(c, sql);
  if (!r)
    return -1;
  ExecStatusType st = PQresultStatus(r);
  PQclear(r);
  return (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK) ? 0 : -1;
}
#endif

int test_db_create_schema_if_needed(const char *schema_name) {
  if (!schema_name || !*schema_name)
    return 0;

#ifdef WAMBLE_ENABLE_DB
  PGconn *c = db_connect();
  if (!c)
    return -1;
  char sql[256];
  snprintf(sql, sizeof sql, "CREATE SCHEMA IF NOT EXISTS %s", schema_name);
  int rc = exec1(c, sql);
  PQfinish(c);
  return rc;
#else
  (void)schema_name;
  return -1;
#endif
}

int test_db_set_search_path(const char *schema_name) {
  if (!schema_name || !*schema_name)
    return 0;

#ifdef WAMBLE_ENABLE_DB
  PGconn *c = db_connect();
  if (!c)
    return -1;
  char sql[256];
  snprintf(sql, sizeof sql, "SET search_path TO %s", schema_name);
  int rc = exec1(c, sql);
  PQfinish(c);
  return rc;
#else
  (void)schema_name;
  return -1;
#endif
}

#ifdef WAMBLE_ENABLE_DB
static int apply_sql_stream(PGconn *c, const char *sql) {
  PGresult *r = PQexec(c, sql);
  if (!r)
    return -1;
  ExecStatusType st = PQresultStatus(r);
  PQclear(r);
  return (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK) ? 0 : -1;
}
#endif

int test_db_apply_sql_file(const char *sql_path) {
#ifdef WAMBLE_ENABLE_DB
  PGconn *c = db_connect();
  if (!c)
    return -1;
  FILE *f = fopen(sql_path, "rb");
  if (!f) {
    PQfinish(c);
    return -1;
  }
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *buf = (char *)malloc((size_t)n + 1);
  if (!buf) {
    fclose(f);
    PQfinish(c);
    return -1;
  }
  if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
    free(buf);
    fclose(f);
    PQfinish(c);
    return -1;
  }
  buf[n] = '\0';
  fclose(f);
  int rc = apply_sql_stream(c, buf);
  free(buf);
  PQfinish(c);
  return rc;
#else
  (void)sql_path;
  return -1;
#endif
}

int test_db_apply_migrations(const char *schema_name) {
#ifdef WAMBLE_ENABLE_DB
  if (test_db_create_schema_if_needed(schema_name) != 0)
    return -1;
  if (test_db_set_search_path(schema_name) != 0)
    return -1;
  return test_db_apply_sql_file("migrations/001_initial_schema.sql");
#else
  (void)schema_name;
  return -1;
#endif
}

int test_db_apply_fixture(const char *schema_name) {
#ifdef WAMBLE_ENABLE_DB
  if (test_db_set_search_path(schema_name) != 0)
    return -1;
  return test_db_apply_sql_file("tests/db/fixture.sql");
#else
  (void)schema_name;
  return -1;
#endif
}

int test_db_reset(const char *schema_name) {
#ifdef WAMBLE_ENABLE_DB
  PGconn *c = db_connect();
  if (!c)
    return -1;
  if (schema_name && *schema_name) {
    char sqlsp[256];
    snprintf(sqlsp, sizeof sqlsp, "SET search_path TO %s", schema_name);
    if (exec1(c, sqlsp) != 0) {
      PQfinish(c);
      return -1;
    }
  }
  if (exec1(c,
            "TRUNCATE TABLE predictions, payouts, game_results, reservations, "
            "moves, boards, sessions, players RESTART IDENTITY CASCADE") != 0) {
    PQfinish(c);
    return -1;
  }
  PQfinish(c);
  return test_db_apply_fixture(schema_name);
#else
  (void)schema_name;
  return -1;
#endif
}

#ifdef WAMBLE_ENABLE_DB
int test_db_drop_schema(const char *schema_name) {
  if (!schema_name || !*schema_name)
    return -1;
  PGconn *c = db_connect();
  if (!c)
    return -1;
  char sql[256];
  snprintf(sql, sizeof sql, "DROP SCHEMA IF EXISTS %s CASCADE", schema_name);
  int rc = exec1(c, sql);
  PQfinish(c);
  return rc;
}

int test_db_reset_schema(const char *schema_name) {
  if (!schema_name || !*schema_name)
    return -1;
  if (test_db_drop_schema(schema_name) != 0)
    return -1;
  if (test_db_apply_migrations(schema_name) != 0)
    return -1;
  return test_db_apply_fixture(schema_name);
}
#else
int test_db_drop_schema(const char *schema_name) {
  (void)schema_name;
  return -1;
}
int test_db_reset_schema(const char *schema_name) {
  (void)schema_name;
  return -1;
}
#endif
