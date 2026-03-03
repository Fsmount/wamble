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

static int schema_name_valid(const char *schema) {
  if (!schema || !schema[0])
    return 0;
  unsigned char c0 = (unsigned char)schema[0];
  if (!((c0 >= 'a' && c0 <= 'z') || (c0 >= 'A' && c0 <= 'Z') || c0 == '_'))
    return 0;
  for (int i = 1; schema[i]; i++) {
    unsigned char c = (unsigned char)schema[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '_')) {
      return 0;
    }
  }
  return 1;
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
  int do_migrate_profile = 0;
  int do_migrate_global = 0;
  int do_fixture = 0;
  int do_reset = 0;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--schema") == 0 && i + 1 < argc) {
      schema = argv[++i];
    } else if (strcmp(argv[i], "--migrate") == 0) {
      do_migrate_profile = 1;
    } else if (strcmp(argv[i], "--migrate-profile") == 0) {
      do_migrate_profile = 1;
    } else if (strcmp(argv[i], "--migrate-global") == 0) {
      do_migrate_global = 1;
    } else if (strcmp(argv[i], "--fixture") == 0) {
      do_fixture = 1;
    } else if (strcmp(argv[i], "--reset") == 0) {
      do_reset = 1;
    } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      printf("Usage: %s [--schema NAME] [--migrate|--migrate-profile] "
             "[--migrate-global] [--fixture] [--reset]\n",
             argv[0]);
      return 0;
    }
  }

  PGconn *c = connect_env();
  if (schema && *schema) {
    if (!schema_name_valid(schema))
      die("invalid schema name");
    char buf[256];
    snprintf(buf, sizeof buf, "CREATE SCHEMA IF NOT EXISTS \"%s\"", schema);
    exec_sql(c, buf);
    snprintf(buf, sizeof buf, "SET search_path TO \"%s\"", schema);
    exec_sql(c, buf);
  }
  if (do_reset) {
    exec_sql(c,
             "DO $$ "
             "BEGIN "
             "  IF to_regclass('predictions') IS NOT NULL THEN "
             "    EXECUTE 'TRUNCATE TABLE predictions, payouts, game_results, "
             "reservations, moves, boards, sessions, players RESTART IDENTITY "
             "CASCADE'; "
             "  END IF; "
             "  IF to_regclass('global_policy_rules') IS NOT NULL THEN "
             "    EXECUTE 'TRUNCATE TABLE global_policy_rules RESTART IDENTITY "
             "CASCADE'; "
             "  END IF; "
             "  IF to_regclass('global_runtime_config_revisions') IS NOT NULL "
             "THEN "
             "    EXECUTE 'TRUNCATE TABLE global_runtime_config_revisions, "
             "global_runtime_config_blobs RESTART IDENTITY CASCADE'; "
             "  END IF; "
             "  IF to_regclass('global_identities') IS NOT NULL THEN "
             "    EXECUTE 'TRUNCATE TABLE global_identities RESTART IDENTITY "
             "CASCADE'; "
             "  END IF; "
             "END $$");
  }
  if (do_migrate_profile) {
    exec_file(c, "migrations/001_profile_initial_schema.sql");
    exec_file(c, "migrations/002_profile_runtime_metadata.sql");
    exec_file(c, "migrations/003_profile_leaderboard_indexes.sql");
    exec_file(c, "migrations/004_profile_session_stats_counters.sql");
    exec_file(c, "migrations/008_profile_identity_sessions.sql");
    exec_file(c, "migrations/010_profile_prediction_resolution.sql");
    exec_file(c, "migrations/011_profile_treatment_groups.sql");
  }
  if (do_migrate_global) {
    exec_file(c, "migrations/005_global_identity_trust.sql");
    exec_file(c, "migrations/006_global_config_snapshots.sql");
    exec_file(c, "migrations/007_global_policy_runtime_expansion.sql");
    exec_file(c, "migrations/009_global_identity_tags.sql");
    exec_file(c, "migrations/011_global_treatment_groups.sql");
  }
  if (do_fixture) {
    exec_file(c, "tests/db/fixture.sql");
  }
  PQfinish(c);
  return 0;
}
