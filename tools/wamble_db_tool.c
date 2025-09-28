#include <libpq-fe.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *msg) {
  fprintf(stderr, "%s\n", msg);
  exit(2);
}

static PGconn *connect_env(void) {
  const char *dsn = getenv("WAMBLE_TEST_DSN");
  if (!dsn || !*dsn)
    die("WAMBLE_TEST_DSN is not set");
  PGconn *c = PQconnectdb(dsn);
  if (PQstatus(c) != CONNECTION_OK) {
    fprintf(stderr, "failed to connect: %s\n", PQerrorMessage(c));
    PQfinish(c);
    exit(2);
  }
  return c;
}

static void exec_sql(PGconn *c, const char *sql) {
  PGresult *r = PQexec(c, sql);
  if (!r)
    die("PQexec failed");
  ExecStatusType st = PQresultStatus(r);
  if (!(st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK)) {
    fprintf(stderr, "SQL error: %s\n", PQerrorMessage(c));
    PQclear(r);
    exit(2);
  }
  PQclear(r);
}

static void exec_file(PGconn *c, const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    perror(path);
    exit(2);
  }
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *buf = malloc((size_t)n + 1);
  if (!buf)
    die("oom");
  if (fread(buf, 1, (size_t)n, f) != (size_t)n)
    die("read err");
  buf[n] = '\0';
  fclose(f);
  exec_sql(c, buf);
  free(buf);
}

int main(int argc, char **argv) {
  const char *schema = NULL;
  int do_migrate = 0;
  int do_fixture = 0;
  int do_reset = 0;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--schema") == 0 && i + 1 < argc) {
      schema = argv[++i];
    } else if (strcmp(argv[i], "--migrate") == 0) {
      do_migrate = 1;
    } else if (strcmp(argv[i], "--fixture") == 0) {
      do_fixture = 1;
    } else if (strcmp(argv[i], "--reset") == 0) {
      do_reset = 1;
    } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      printf("Usage: %s [--schema NAME] [--migrate] [--fixture] [--reset]\n",
             argv[0]);
      return 0;
    }
  }

  PGconn *c = connect_env();
  if (schema && *schema) {
    char buf[256];
    snprintf(buf, sizeof buf, "CREATE SCHEMA IF NOT EXISTS %s", schema);
    exec_sql(c, buf);
    snprintf(buf, sizeof buf, "SET search_path TO %s", schema);
    exec_sql(c, buf);
  }
  if (do_reset) {
    exec_sql(c,
             "TRUNCATE TABLE predictions, payouts, game_results, reservations, "
             "moves, boards, sessions, players RESTART IDENTITY CASCADE");
  }
  if (do_migrate) {
    exec_file(c, "migrations/001_initial_schema.sql");
  }
  if (do_fixture) {
    exec_file(c, "tests/db/fixture.sql");
  }
  PQfinish(c);
  return 0;
}
