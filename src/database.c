#include "../include/wamble/wamble.h"
#include "../include/wamble/wamble_db.h"
#include <inttypes.h>
#include <libpq-fe.h>
#include <stdlib.h>
#include <string.h>

static WAMBLE_THREAD_LOCAL PGconn *db_conn_tls = NULL;
static WAMBLE_THREAD_LOCAL PGconn *db_global_conn_tls = NULL;
static bool db_initialized = false;
static char g_global_conn_str[512];
static int g_global_conn_configured = 0;
static DbBoardIdList db_list_boards_by_status(const char *status);
static DbBoardResult db_get_board(uint64_t board_id);
static DbMovesResult db_get_moves_for_board(uint64_t board_id);
static DbStatus db_get_longest_game_moves(int *out_max_moves);
static DbStatus db_get_active_session_count(int *out_count);
static DbStatus db_get_max_board_id(uint64_t *out_max_id);
static DbStatus db_get_session_by_token(const uint8_t *token,
                                        uint64_t *out_session);
static DbStatus db_get_persistent_session_by_token(const uint8_t *token,
                                                   uint64_t *out_session);
static DbStatus db_get_player_total_score(uint64_t session_id,
                                          double *out_total);
static DbStatus db_get_player_prediction_score(uint64_t session_id,
                                               double *out_total);
static DbStatus db_get_player_rating(uint64_t session_id, double *out_rating);
static DbStatus db_get_session_games_played(uint64_t session_id,
                                            int *out_games);
static DbStatus db_get_session_chess960_games_played(uint64_t session_id,
                                                     int *out_games);
static DbStatus
db_get_persistent_player_stats(const uint8_t *public_key,
                               WamblePersistentPlayerStats *out_stats);
static uint64_t db_create_player(const uint8_t *public_key);
static uint64_t db_get_player_by_public_key(const uint8_t *public_key);
static int db_async_link_session_to_pubkey(uint64_t session_id,
                                           const uint8_t *public_key);
static int db_async_unlink_session_identity(uint64_t session_id);
static void bytes_to_hex(const uint8_t *bytes, int len, char *hex_out);
static uint64_t db_global_identity_create_anonymous(void);
static int db_ensure_global_treatment_schema(void);
static int db_ensure_profile_treatment_schema(void);

static const char *db_treatment_profile_key(const char *profile) {
  const char *profile_key =
      (profile && profile[0]) ? profile : wamble_runtime_profile_key();
  return (profile_key && profile_key[0]) ? profile_key : "__default__";
}

static int append_conninfo_text(char *out, size_t out_size, size_t *offset,
                                const char *text) {
  if (!out || out_size == 0 || !offset)
    return -1;
  const char *src = text ? text : "";
  while (*src) {
    if (*offset + 1 >= out_size)
      return -1;
    out[*offset] = *src;
    (*offset)++;
    src++;
  }
  out[*offset] = '\0';
  return 0;
}

static int append_conninfo_quoted_value(char *out, size_t out_size,
                                        size_t *offset, const char *value) {
  const char *src = value ? value : "";
  if (append_conninfo_text(out, out_size, offset, "'") != 0)
    return -1;
  while (*src) {
    if (*src == '\'' || *src == '\\') {
      if (append_conninfo_text(out, out_size, offset, "\\") != 0)
        return -1;
    }
    if (*offset + 1 >= out_size)
      return -1;
    out[*offset] = *src;
    (*offset)++;
    src++;
  }
  out[*offset] = '\0';
  return append_conninfo_text(out, out_size, offset, "'");
}

static int build_conninfo_from_cfg(const WambleConfig *cfg, int use_global,
                                   char *out, size_t out_size) {
  if (!cfg || !out || out_size == 0)
    return -1;
  out[0] = '\0';

  const char *db_name = use_global ? cfg->global_db_name : cfg->db_name;
  const char *db_user = use_global ? cfg->global_db_user : cfg->db_user;
  const char *db_pass = use_global ? cfg->global_db_pass : cfg->db_pass;
  const char *db_host = use_global ? cfg->global_db_host : cfg->db_host;
  int db_port = use_global ? cfg->global_db_port : cfg->db_port;

  size_t offset = 0;
  if (append_conninfo_text(out, out_size, &offset, "dbname=") != 0 ||
      append_conninfo_quoted_value(out, out_size, &offset, db_name) != 0 ||
      append_conninfo_text(out, out_size, &offset, " user=") != 0 ||
      append_conninfo_quoted_value(out, out_size, &offset, db_user) != 0 ||
      append_conninfo_text(out, out_size, &offset, " password=") != 0 ||
      append_conninfo_quoted_value(out, out_size, &offset, db_pass) != 0 ||
      append_conninfo_text(out, out_size, &offset, " host=") != 0 ||
      append_conninfo_quoted_value(out, out_size, &offset, db_host) != 0) {
    out[0] = '\0';
    return -1;
  }
  if (db_port > 0) {
    char port_buf[32];
    snprintf(port_buf, sizeof(port_buf), "%d", db_port);
    if (append_conninfo_text(out, out_size, &offset, " port=") != 0 ||
        append_conninfo_quoted_value(out, out_size, &offset, port_buf) != 0) {
      out[0] = '\0';
      return -1;
    }
  }
  return 0;
}

static PGconn *ensure_connection(void) {
  if (db_conn_tls) {
    if (PQstatus(db_conn_tls) != CONNECTION_OK) {
      PQreset(db_conn_tls);
      if (PQstatus(db_conn_tls) != CONNECTION_OK) {
        PQfinish(db_conn_tls);
        db_conn_tls = NULL;
        return NULL;
      }
    }
    return db_conn_tls;
  }
  char conn[512];
  if (build_conninfo_from_cfg(get_config(), 0, conn, sizeof conn) != 0)
    return NULL;
  db_conn_tls = PQconnectdb(conn);
  if (PQstatus(db_conn_tls) != CONNECTION_OK) {
    PQfinish(db_conn_tls);
    db_conn_tls = NULL;
    return NULL;
  }
  return db_conn_tls;
}

static PGconn *ensure_global_connection(void) {
  if (db_global_conn_tls) {
    if (PQstatus(db_global_conn_tls) != CONNECTION_OK) {
      PQreset(db_global_conn_tls);
      if (PQstatus(db_global_conn_tls) != CONNECTION_OK) {
        PQfinish(db_global_conn_tls);
        db_global_conn_tls = NULL;
        return NULL;
      }
    }
    return db_global_conn_tls;
  }

  if (g_global_conn_configured && g_global_conn_str[0]) {
    db_global_conn_tls = PQconnectdb(g_global_conn_str);
  } else {
    char conn[512];
    if (build_conninfo_from_cfg(get_config(), 1, conn, sizeof conn) != 0)
      return NULL;
    db_global_conn_tls = PQconnectdb(conn);
  }
  if (PQstatus(db_global_conn_tls) != CONNECTION_OK) {
    PQfinish(db_global_conn_tls);
    db_global_conn_tls = NULL;
    return NULL;
  }
  return db_global_conn_tls;
}

static PGresult *pq_exec_locked(const char *command) {
  PGconn *c = ensure_connection();
  if (!c)
    return NULL;
  PGresult *res = PQexec(c, command);
  if (!res)
    return NULL;
  return res;
}

static PGresult *
pq_exec_params_locked(const char *command, int nParams, const Oid *paramTypes,
                      const char *const *paramValues, const int *paramLengths,
                      const int *paramFormats, int resultFormat) {
  PGconn *c = ensure_connection();
  if (!c)
    return NULL;
  PGresult *res = PQexecParams(c, command, nParams, paramTypes, paramValues,
                               paramLengths, paramFormats, resultFormat);
  if (!res)
    return NULL;
  return res;
}

static PGresult *pq_exec_params_global_locked(const char *command, int nParams,
                                              const Oid *paramTypes,
                                              const char *const *paramValues,
                                              const int *paramLengths,
                                              const int *paramFormats,
                                              int resultFormat) {
  PGconn *c = ensure_global_connection();
  if (!c)
    return NULL;
  PGresult *res = PQexecParams(c, command, nParams, paramTypes, paramValues,
                               paramLengths, paramFormats, resultFormat);
  if (!res)
    return NULL;
  return res;
}

int db_set_global_store_connection(const char *connection_string) {
  char derived_conn[512];
  if (!connection_string || !connection_string[0]) {
    if (build_conninfo_from_cfg(get_config(), 1, derived_conn,
                                sizeof derived_conn) != 0)
      return -1;
    connection_string = derived_conn;
  }
  size_t n = strlen(connection_string);
  if (n >= sizeof(g_global_conn_str))
    return -1;
  PGconn *probe = PQconnectdb(connection_string);
  if (!probe)
    return -1;
  int ok = (PQstatus(probe) == CONNECTION_OK) ? 0 : -1;
  PQfinish(probe);
  if (ok != 0)
    return -1;

  memcpy(g_global_conn_str, connection_string, n + 1);
  g_global_conn_configured = 1;
  if (db_global_conn_tls) {
    PQfinish(db_global_conn_tls);
    db_global_conn_tls = NULL;
  }
  return ok;
}

static int db_ensure_global_policy_schema(void) {
  const char *ddl[] = {
      "CREATE TABLE IF NOT EXISTS global_policy_rules ("
      "  id BIGSERIAL PRIMARY KEY,"
      "  global_identity_id BIGINT NOT NULL,"
      "  action VARCHAR(128) NOT NULL,"
      "  resource VARCHAR(256) NOT NULL,"
      "  effect VARCHAR(8) NOT NULL CHECK (effect IN ('allow', 'deny')),"
      "  permission_level INTEGER NOT NULL DEFAULT 0,"
      "  policy_version VARCHAR(64) NOT NULL DEFAULT 'v1',"
      "  reason TEXT,"
      "  created_at TIMESTAMPTZ DEFAULT NOW(),"
      "  updated_at TIMESTAMPTZ DEFAULT NOW()"
      ")",
      "ALTER TABLE global_policy_rules "
      "ADD COLUMN IF NOT EXISTS scope VARCHAR(256) NOT NULL DEFAULT '*'",
      "ALTER TABLE global_policy_rules "
      "ADD COLUMN IF NOT EXISTS source VARCHAR(32) NOT NULL DEFAULT 'manual'",
      "ALTER TABLE global_policy_rules "
      "ADD COLUMN IF NOT EXISTS snapshot_revision_id BIGINT",
      "ALTER TABLE global_policy_rules "
      "ADD COLUMN IF NOT EXISTS not_before_at TIMESTAMPTZ",
      "ALTER TABLE global_policy_rules "
      "ADD COLUMN IF NOT EXISTS not_after_at TIMESTAMPTZ",
      "ALTER TABLE global_policy_rules "
      "ADD COLUMN IF NOT EXISTS context_key VARCHAR(128)",
      "ALTER TABLE global_policy_rules "
      "ADD COLUMN IF NOT EXISTS context_value VARCHAR(256)",
      "CREATE INDEX IF NOT EXISTS idx_policy_identity_action_scope "
      "ON global_policy_rules(global_identity_id, action, scope, resource)",
      "CREATE INDEX IF NOT EXISTS idx_policy_source_snapshot "
      "ON global_policy_rules(source, snapshot_revision_id)"};

  for (size_t i = 0; i < sizeof(ddl) / sizeof(ddl[0]); i++) {
    PGresult *res =
        pq_exec_params_global_locked(ddl[i], 0, NULL, NULL, NULL, NULL, 0);
    if (!res)
      return -1;
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
      PQclear(res);
      return -1;
    }
    PQclear(res);
  }

  return 0;
}

static int db_ensure_global_identity_schema(void) {
  const char *ddl = "CREATE TABLE IF NOT EXISTS global_identities ("
                    "  id BIGSERIAL PRIMARY KEY,"
                    "  public_key BYTEA UNIQUE CHECK (LENGTH(public_key) = 32),"
                    "  created_at TIMESTAMPTZ DEFAULT NOW()"
                    ")";
  PGresult *res =
      pq_exec_params_global_locked(ddl, 0, NULL, NULL, NULL, NULL, 0);
  if (!res)
    return -1;
  int ok = (PQresultStatus(res) == PGRES_COMMAND_OK) ? 0 : -1;
  PQclear(res);
  return ok;
}

static int db_ensure_global_identity_tag_schema(void) {
  const char *ddl[] = {
      "CREATE TABLE IF NOT EXISTS global_identity_tags ("
      "  global_identity_id BIGINT NOT NULL,"
      "  tag VARCHAR(128) NOT NULL,"
      "  created_at TIMESTAMPTZ DEFAULT NOW(),"
      "  PRIMARY KEY (global_identity_id, tag)"
      ")",
      "CREATE INDEX IF NOT EXISTS idx_global_identity_tags_tag "
      "ON global_identity_tags(tag, global_identity_id)"};
  for (size_t i = 0; i < sizeof(ddl) / sizeof(ddl[0]); i++) {
    PGresult *res =
        pq_exec_params_global_locked(ddl[i], 0, NULL, NULL, NULL, NULL, 0);
    if (!res)
      return -1;
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
      PQclear(res);
      return -1;
    }
    PQclear(res);
  }
  return 0;
}

static int db_ensure_global_treatment_schema(void) {
  const char *ddl[] = {
      "CREATE TABLE IF NOT EXISTS global_treatment_groups ("
      "  id BIGSERIAL PRIMARY KEY,"
      "  group_key VARCHAR(128) NOT NULL,"
      "  priority INTEGER NOT NULL,"
      "  is_default BOOLEAN NOT NULL DEFAULT FALSE,"
      "  source VARCHAR(32) NOT NULL DEFAULT 'config',"
      "  snapshot_revision_id BIGINT,"
      "  created_at TIMESTAMPTZ DEFAULT NOW()"
      ")",
      "CREATE UNIQUE INDEX IF NOT EXISTS idx_treatment_group_key_source "
      "ON global_treatment_groups(group_key, source, "
      "COALESCE(snapshot_revision_id, 0))",
      "CREATE TABLE IF NOT EXISTS global_treatment_assignment_rules ("
      "  id BIGSERIAL PRIMARY KEY,"
      "  global_identity_id BIGINT NOT NULL,"
      "  profile_scope VARCHAR(256) NOT NULL DEFAULT '*',"
      "  group_key VARCHAR(128) NOT NULL,"
      "  priority INTEGER NOT NULL,"
      "  source VARCHAR(32) NOT NULL DEFAULT 'config',"
      "  snapshot_revision_id BIGINT,"
      "  created_at TIMESTAMPTZ DEFAULT NOW()"
      ")",
      "CREATE INDEX IF NOT EXISTS idx_treatment_assignment_lookup "
      "ON global_treatment_assignment_rules(global_identity_id, profile_scope, "
      "priority, group_key)",
      "CREATE TABLE IF NOT EXISTS global_treatment_assignment_predicates ("
      "  rule_id BIGINT NOT NULL REFERENCES "
      "global_treatment_assignment_rules(id) ON DELETE CASCADE,"
      "  fact_key VARCHAR(128) NOT NULL,"
      "  op VARCHAR(16) NOT NULL,"
      "  value_type INTEGER NOT NULL,"
      "  value_text VARCHAR(256),"
      "  value_num DOUBLE PRECISION,"
      "  value_bool BOOLEAN,"
      "  value_fact_ref VARCHAR(128)"
      ")",
      "CREATE TABLE IF NOT EXISTS global_treatment_group_edges ("
      "  source_group_key VARCHAR(128) NOT NULL,"
      "  target_group_key VARCHAR(128) NOT NULL,"
      "  source VARCHAR(32) NOT NULL DEFAULT 'config',"
      "  snapshot_revision_id BIGINT,"
      "  PRIMARY KEY (source_group_key, target_group_key, source, "
      "snapshot_revision_id)"
      ")",
      "CREATE TABLE IF NOT EXISTS global_treatment_group_outputs ("
      "  id BIGSERIAL PRIMARY KEY,"
      "  group_key VARCHAR(128) NOT NULL,"
      "  hook_name VARCHAR(64) NOT NULL DEFAULT '*',"
      "  output_kind VARCHAR(32) NOT NULL,"
      "  output_key VARCHAR(128) NOT NULL,"
      "  value_type INTEGER NOT NULL,"
      "  value_text VARCHAR(256),"
      "  value_num DOUBLE PRECISION,"
      "  value_bool BOOLEAN,"
      "  value_fact_ref VARCHAR(128),"
      "  source VARCHAR(32) NOT NULL DEFAULT 'config',"
      "  snapshot_revision_id BIGINT,"
      "  created_at TIMESTAMPTZ DEFAULT NOW()"
      ")",
      "CREATE UNIQUE INDEX IF NOT EXISTS idx_treatment_outputs_unique "
      "ON global_treatment_group_outputs(group_key, hook_name, output_kind, "
      "output_key, source, COALESCE(snapshot_revision_id, 0))"};
  for (size_t i = 0; i < sizeof(ddl) / sizeof(ddl[0]); i++) {
    PGresult *res =
        pq_exec_params_global_locked(ddl[i], 0, NULL, NULL, NULL, NULL, 0);
    if (!res)
      return -1;
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
      PQclear(res);
      return -1;
    }
    PQclear(res);
  }
  return 0;
}

static int db_ensure_profile_treatment_schema(void) {
  const char *ddl[] = {
      "ALTER TABLE sessions "
      "ADD COLUMN IF NOT EXISTS treatment_group_key VARCHAR(128)",
      "ALTER TABLE sessions "
      "ADD COLUMN IF NOT EXISTS treatment_rule_id BIGINT",
      "ALTER TABLE sessions "
      "ADD COLUMN IF NOT EXISTS treatment_snapshot_revision_id BIGINT",
      "ALTER TABLE sessions "
      "ADD COLUMN IF NOT EXISTS treatment_assigned_at TIMESTAMPTZ",
      "ALTER TABLE boards "
      "ADD COLUMN IF NOT EXISTS last_mover_treatment_group VARCHAR(128)",
      "CREATE INDEX IF NOT EXISTS idx_sessions_treatment_group "
      "ON sessions(treatment_group_key)"};
  for (size_t i = 0; i < sizeof(ddl) / sizeof(ddl[0]); i++) {
    PGresult *res = pq_exec_params_locked(ddl[i], 0, NULL, NULL, NULL, NULL, 0);
    if (!res)
      return -1;
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
      PQclear(res);
      return -1;
    }
    PQclear(res);
  }
  return 0;
}

int db_validate_global_policy(void) {
  if (db_ensure_global_identity_schema() != 0 ||
      db_ensure_global_identity_tag_schema() != 0 ||
      db_ensure_global_policy_schema() != 0)
    return -1;
  const char *query = "SELECT id "
                      "FROM global_policy_rules "
                      "WHERE action = 'trust.tier' "
                      "  AND resource = 'tier' "
                      "  AND (scope = '*' OR scope LIKE 'profile:%' OR "
                      "scope LIKE 'profile_group:%') "
                      "LIMIT 1";
  PGresult *res =
      pq_exec_params_global_locked(query, 0, NULL, NULL, NULL, NULL, 0);
  if (!res)
    return -1;
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    return -1;
  }
  int ok = (PQntuples(res) > 0) ? 0 : -1;
  PQclear(res);
  return ok;
}

static DbStatus db_get_or_create_session_identity(const uint8_t *token,
                                                  uint64_t *out_identity_id) {
  if (!token || !out_identity_id)
    return DB_ERR_BAD_DATA;
  *out_identity_id = 0;
  if (db_ensure_global_identity_schema() != 0)
    return DB_ERR_EXEC;
  const char *sid_query =
      "SELECT global_identity_id FROM sessions WHERE token = decode($1, 'hex')";
  char token_hex[33];
  bytes_to_hex(token, TOKEN_LENGTH, token_hex);
  const char *sid_params[] = {token_hex};
  PGresult *sid_res =
      pq_exec_params_locked(sid_query, 1, NULL, sid_params, NULL, NULL, 0);
  if (!sid_res)
    return DB_ERR_CONN;
  if (PQresultStatus(sid_res) != PGRES_TUPLES_OK) {
    PQclear(sid_res);
    return DB_ERR_EXEC;
  }
  if (PQntuples(sid_res) == 0) {
    PQclear(sid_res);
    return DB_NOT_FOUND;
  }

  uint64_t identity_id = 0;
  if (!PQgetisnull(sid_res, 0, 0)) {
    char *endptr = NULL;
    identity_id = strtoull(PQgetvalue(sid_res, 0, 0), &endptr, 10);
    if (!endptr || *endptr != '\0') {
      PQclear(sid_res);
      return DB_ERR_BAD_DATA;
    }
  }
  PQclear(sid_res);

  if (identity_id == 0) {
    identity_id = db_global_identity_create_anonymous();
    if (identity_id == 0)
      return DB_ERR_EXEC;
    char identity_id_str[32];
    snprintf(identity_id_str, sizeof(identity_id_str), "%" PRIu64, identity_id);
    const char *update_query =
        "UPDATE sessions "
        "SET global_identity_id = $2 "
        "WHERE token = decode($1, 'hex') "
        "  AND (global_identity_id IS NULL OR global_identity_id = 0)";
    const char *update_params[] = {token_hex, identity_id_str};
    PGresult *upd = pq_exec_params_locked(update_query, 2, NULL, update_params,
                                          NULL, NULL, 0);
    if (!upd)
      return DB_ERR_CONN;
    if (PQresultStatus(upd) != PGRES_COMMAND_OK) {
      PQclear(upd);
      return DB_ERR_EXEC;
    }
    int updated_rows = atoi(PQcmdTuples(upd));
    PQclear(upd);
    if (updated_rows == 0) {
      PGresult *recheck =
          pq_exec_params_locked(sid_query, 1, NULL, sid_params, NULL, NULL, 0);
      if (!recheck)
        return DB_ERR_CONN;
      if (PQresultStatus(recheck) != PGRES_TUPLES_OK ||
          PQntuples(recheck) == 0) {
        PQclear(recheck);
        return DB_ERR_EXEC;
      }
      if (!PQgetisnull(recheck, 0, 0)) {
        char *endptr = NULL;
        uint64_t existing = strtoull(PQgetvalue(recheck, 0, 0), &endptr, 10);
        if (endptr && *endptr == '\0' && existing > 0)
          identity_id = existing;
      }
      PQclear(recheck);
      if (identity_id == 0)
        return DB_ERR_EXEC;
    }
  }

  *out_identity_id = identity_id;
  return DB_OK;
}

static int db_ensure_config_snapshot_table(void) {
  const char *ddl1 = "CREATE TABLE IF NOT EXISTS global_runtime_config_blobs ("
                     "  content_hash VARCHAR(32) PRIMARY KEY,"
                     "  config_text TEXT NOT NULL,"
                     "  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()"
                     ")";
  const char *ddl2 =
      "CREATE TABLE IF NOT EXISTS global_runtime_config_revisions ("
      "  id BIGSERIAL PRIMARY KEY,"
      "  profile_key VARCHAR(128) NOT NULL,"
      "  content_hash VARCHAR(32) NULL REFERENCES "
      "global_runtime_config_blobs(content_hash),"
      "  source VARCHAR(32) NOT NULL DEFAULT 'file',"
      "  result VARCHAR(16) NOT NULL,"
      "  error_text TEXT,"
      "  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
      "  activated_at TIMESTAMPTZ"
      ")";
  const char *ddl4 =
      "CREATE INDEX IF NOT EXISTS idx_runtime_config_revisions_profile_created "
      "ON global_runtime_config_revisions(profile_key, created_at DESC)";
  const char *ddl5 = "CREATE INDEX IF NOT EXISTS "
                     "idx_runtime_config_revisions_profile_result_created "
                     "ON global_runtime_config_revisions(profile_key, result, "
                     "created_at DESC)";
  PGresult *res =
      pq_exec_params_global_locked(ddl1, 0, NULL, NULL, NULL, NULL, 0);
  if (!res)
    return -1;
  int ok = (PQresultStatus(res) == PGRES_COMMAND_OK) ? 0 : -1;
  PQclear(res);
  if (ok != 0)
    return -1;
  res = pq_exec_params_global_locked(ddl2, 0, NULL, NULL, NULL, NULL, 0);
  if (!res)
    return -1;
  ok = (PQresultStatus(res) == PGRES_COMMAND_OK) ? 0 : -1;
  PQclear(res);
  if (ok != 0)
    return -1;
  res = pq_exec_params_global_locked(ddl4, 0, NULL, NULL, NULL, NULL, 0);
  if (!res)
    return -1;
  ok = (PQresultStatus(res) == PGRES_COMMAND_OK) ? 0 : -1;
  PQclear(res);
  if (ok != 0)
    return -1;
  res = pq_exec_params_global_locked(ddl5, 0, NULL, NULL, NULL, NULL, 0);
  if (!res)
    return -1;
  ok = (PQresultStatus(res) == PGRES_COMMAND_OK) ? 0 : -1;
  PQclear(res);
  return ok;
}

int db_record_config_event(const char *profile_key, const char *config_text,
                           const char *source, const char *result,
                           const char *error_text) {
  if (!result || !result[0])
    return -1;
  if (db_ensure_config_snapshot_table() != 0)
    return -1;
  const char *key =
      (profile_key && profile_key[0]) ? profile_key : "__default__";
  const char *src = (source && source[0]) ? source : "runtime";
  const char *err = (error_text && error_text[0]) ? error_text : NULL;
  PGresult *res = NULL;
  if (config_text && config_text[0]) {
    const char *blob_q =
        "INSERT INTO global_runtime_config_blobs (content_hash, config_text) "
        "VALUES (md5($1), $1) "
        "ON CONFLICT (content_hash) DO NOTHING";
    const char *blob_params[] = {config_text};
    res = pq_exec_params_global_locked(blob_q, 1, NULL, blob_params, NULL, NULL,
                                       0);
    if (!res)
      return -1;
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
      PQclear(res);
      return -1;
    }
    PQclear(res);
  }

  const char *rev_q =
      "INSERT INTO global_runtime_config_revisions "
      "(profile_key, content_hash, source, result, error_text, activated_at) "
      "VALUES ($1, CASE WHEN $2 IS NULL OR $2 = '' THEN NULL ELSE md5($2) END, "
      "        $3, $4, $5, CASE WHEN $4 = 'active' THEN NOW() ELSE NULL END) "
      "RETURNING id";
  const char *rev_params[] = {key, config_text, src, result, err};
  res = pq_exec_params_global_locked(rev_q, 5, NULL, rev_params, NULL, NULL, 0);
  if (!res)
    return -1;
  if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
    PQclear(res);
    return -1;
  }
  char *endptr = NULL;
  uint64_t rev_id = strtoull(PQgetvalue(res, 0, 0), &endptr, 10);
  PQclear(res);
  if (!endptr || *endptr != '\0' || rev_id == 0)
    return -1;

  return 0;
}

int db_store_config_snapshot(const char *profile_key, const char *config_text) {
  return db_record_config_event(profile_key, config_text, "file", "active",
                                NULL);
}

int db_load_config_snapshot(const char *profile_key, char **out_config_text) {
  if (!out_config_text)
    return -1;
  *out_config_text = NULL;
  if (db_ensure_config_snapshot_table() != 0)
    return -1;
  const char *key =
      (profile_key && profile_key[0]) ? profile_key : "__default__";
  const char *query =
      "SELECT b.config_text "
      "FROM global_runtime_config_revisions r "
      "JOIN global_runtime_config_blobs b ON b.content_hash = r.content_hash "
      "WHERE r.profile_key = $1 AND r.result = 'active' "
      "ORDER BY r.created_at DESC LIMIT 1";
  const char *params[] = {key};
  PGresult *res =
      pq_exec_params_global_locked(query, 1, NULL, params, NULL, NULL, 0);
  if (!res)
    return -1;
  if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
    PQclear(res);
    return -1;
  }
  const char *txt = PQgetvalue(res, 0, 0);
  if (!txt) {
    PQclear(res);
    return -1;
  }
  *out_config_text = wamble_strdup(txt);
  PQclear(res);
  return *out_config_text ? 0 : -1;
}

static int db_get_active_revision_id(const char *profile_key,
                                     uint64_t *out_revision_id) {
  if (!out_revision_id)
    return -1;
  *out_revision_id = 0;
  if (db_ensure_config_snapshot_table() != 0)
    return -1;
  const char *key =
      (profile_key && profile_key[0]) ? profile_key : "__default__";
  const char *query = "SELECT id FROM global_runtime_config_revisions "
                      "WHERE profile_key = $1 AND result = 'active' "
                      "ORDER BY created_at DESC LIMIT 1";
  const char *params[] = {key};
  PGresult *res =
      pq_exec_params_global_locked(query, 1, NULL, params, NULL, NULL, 0);
  if (!res)
    return -1;
  if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
    PQclear(res);
    return -1;
  }
  char *endptr = NULL;
  uint64_t id = strtoull(PQgetvalue(res, 0, 0), &endptr, 10);
  PQclear(res);
  if (!endptr || *endptr != '\0' || id == 0)
    return -1;
  *out_revision_id = id;
  return 0;
}

int db_write_batch_begin(void) {
  PGresult *res = pq_exec_locked("BEGIN");
  if (!res)
    return -1;
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    PQclear(res);
    return -1;
  }
  PQclear(res);
  return 0;
}

int db_write_batch_commit(void) {
  PGresult *res = pq_exec_locked("COMMIT");
  if (!res)
    return -1;
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    PQclear(res);
    return -1;
  }
  PQclear(res);
  return 0;
}

void db_write_batch_rollback(void) {
  PGresult *res = pq_exec_locked("ROLLBACK");
  if (res)
    PQclear(res);
}

typedef enum {
  DB_JOB_UPDATE_BOARD,
  DB_JOB_CREATE_RESERVATION,
  DB_JOB_REMOVE_RESERVATION,
  DB_JOB_RECORD_GAME_RESULT,
  DB_JOB_RECORD_MOVE,
  DB_JOB_RECORD_PAYOUT
} DbJobType;

typedef struct {
  DbJobType type;
  uint64_t board_id;
  uint64_t session_id;
  int move_number;
  int timeout_seconds;
  double points;
  char fen[FEN_MAX_LENGTH];
  char status[STATUS_MAX_LENGTH];
  char move_uci[MAX_UCI_LENGTH];
  char winning_side;
} DbJob;

static void bytes_to_hex(const uint8_t *bytes, int len, char *hex_out) {
  if (bytes == NULL || hex_out == NULL) {
    return;
  }
  for (int i = 0; i < len; i++) {
    snprintf(hex_out + i * 2, 3, "%02x", bytes[i]);
  }
  hex_out[len * 2] = '\0';
}

static void hex_to_bytes(const char *hex, uint8_t *bytes_out, int len) {
  for (int i = 0; i < len; i++) {
    sscanf(hex + i * 2, "%2hhx", &bytes_out[i]);
  }
}

int db_init(const char *connection_string) {
  if (db_initialized) {
    return 0;
  }

  (void)connection_string;

  db_initialized = true;
  return 0;
}

void db_cleanup(void) { db_initialized = false; }

static WAMBLE_THREAD_LOCAL uint64_t *tls_ids;
static WAMBLE_THREAD_LOCAL int tls_ids_cap;
static WAMBLE_THREAD_LOCAL WambleMove *tls_moves;
static WAMBLE_THREAD_LOCAL int tls_moves_cap;
static WAMBLE_THREAD_LOCAL DbPredictionRow *tls_predictions;
static WAMBLE_THREAD_LOCAL int tls_predictions_cap;

enum {
  TOKEN_READ_CACHE_CAP = 256,
  TOKEN_READ_CACHE_TTL_MS = 500,
};

typedef struct {
  uint8_t token[TOKEN_LENGTH];
  DbStatus status;
  uint64_t value;
  uint64_t expires_ms;
  int used;
} TokenReadCacheU64Entry;

static WAMBLE_THREAD_LOCAL TokenReadCacheU64Entry
    tls_session_cache[TOKEN_READ_CACHE_CAP];
static WAMBLE_THREAD_LOCAL TokenReadCacheU64Entry
    tls_persistent_session_cache[TOKEN_READ_CACHE_CAP];
static WAMBLE_THREAD_LOCAL int tls_session_cache_next = 0;
static WAMBLE_THREAD_LOCAL int tls_persistent_session_cache_next = 0;

static int token_cache_u64_lookup(TokenReadCacheU64Entry *cache, int cap,
                                  const uint8_t *token, uint64_t now_ms,
                                  DbStatus *out_status, uint64_t *out_value) {
  if (!cache || !token || !out_status || !out_value)
    return 0;
  for (int i = 0; i < cap; i++) {
    TokenReadCacheU64Entry *e = &cache[i];
    if (!e->used)
      continue;
    if (e->expires_ms < now_ms)
      continue;
    if (memcmp(e->token, token, TOKEN_LENGTH) != 0)
      continue;
    *out_status = e->status;
    *out_value = e->value;
    return 1;
  }
  return 0;
}

static void token_cache_u64_store(TokenReadCacheU64Entry *cache, int cap,
                                  int *next_slot, const uint8_t *token,
                                  DbStatus status, uint64_t value,
                                  uint64_t now_ms) {
  if (!cache || !next_slot || !token || cap <= 0)
    return;
  int idx = *next_slot;
  if (idx < 0 || idx >= cap)
    idx = 0;
  TokenReadCacheU64Entry *e = &cache[idx];
  memcpy(e->token, token, TOKEN_LENGTH);
  e->status = status;
  e->value = value;
  e->expires_ms = now_ms + TOKEN_READ_CACHE_TTL_MS;
  e->used = 1;
  *next_slot = (idx + 1) % cap;
}

void db_cleanup_thread(void) {
  if (db_conn_tls) {
    PQfinish(db_conn_tls);
    db_conn_tls = NULL;
  }
  if (db_global_conn_tls) {
    PQfinish(db_global_conn_tls);
    db_global_conn_tls = NULL;
  }
  if (tls_ids) {
    free(tls_ids);
    tls_ids = NULL;
    tls_ids_cap = 0;
  }
  if (tls_moves) {
    free(tls_moves);
    tls_moves = NULL;
    tls_moves_cap = 0;
  }
  memset(tls_session_cache, 0, sizeof(tls_session_cache));
  memset(tls_persistent_session_cache, 0, sizeof(tls_persistent_session_cache));
  tls_session_cache_next = 0;
  tls_persistent_session_cache_next = 0;
}

static uint64_t db_global_identity_create_anonymous(void) {
  if (db_ensure_global_identity_schema() != 0)
    return 0;
  const char *query =
      "INSERT INTO global_identities DEFAULT VALUES RETURNING id";
  PGresult *res =
      pq_exec_params_global_locked(query, 0, NULL, NULL, NULL, NULL, 0);
  if (!res)
    return 0;
  if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
    PQclear(res);
    return 0;
  }
  uint64_t id = strtoull(PQgetvalue(res, 0, 0), NULL, 10);
  PQclear(res);
  return id;
}

static uint64_t
db_global_identity_resolve_or_create_pubkey(const uint8_t *public_key) {
  if (!public_key)
    return 0;
  if (db_ensure_global_identity_schema() != 0)
    return 0;
  const char *query = "INSERT INTO global_identities (public_key) "
                      "VALUES (decode($1, 'hex')) "
                      "ON CONFLICT (public_key) DO UPDATE "
                      "SET public_key = EXCLUDED.public_key "
                      "RETURNING id";
  char public_key_hex[65];
  bytes_to_hex(public_key, 32, public_key_hex);
  const char *paramValues[] = {public_key_hex};
  PGresult *res =
      pq_exec_params_global_locked(query, 1, NULL, paramValues, NULL, NULL, 0);
  if (!res)
    return 0;
  if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
    PQclear(res);
    return 0;
  }
  uint64_t id = strtoull(PQgetvalue(res, 0, 0), NULL, 10);
  PQclear(res);
  return id;
}

static int parse_identity_numeric_selector(const char *selector,
                                           uint64_t *out_identity_id) {
  if (!selector || !out_identity_id)
    return -1;
  const char *idtxt = selector;
  if (strncmp(idtxt, "identity:", 9) == 0)
    idtxt += 9;
  else if (strncmp(idtxt, "id:", 3) == 0)
    idtxt += 3;
  if (!idtxt[0])
    return -1;
  char *endptr = NULL;
  uint64_t id = strtoull(idtxt, &endptr, 10);
  if (!endptr || *endptr != '\0' || id == 0)
    return -1;
  *out_identity_id = id;
  return 0;
}

static uint64_t db_resolve_single_identity_selector(const char *selector) {
  if (!selector || !selector[0] || strcmp(selector, "*") == 0)
    return 0;
  uint64_t numeric_id = 0;
  if (parse_identity_numeric_selector(selector, &numeric_id) == 0)
    return numeric_id;
  const char *hex = selector;
  if (strncmp(selector, "pubkey:", 7) == 0)
    hex = selector + 7;
  if (strlen(hex) != 64)
    return UINT64_MAX;
  uint8_t key[32] = {0};
  for (int i = 0; i < 64; i++) {
    int c = hex[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
          (c >= 'A' && c <= 'F')))
      return UINT64_MAX;
  }
  hex_to_bytes(hex, key, 32);
  return db_global_identity_resolve_or_create_pubkey(key);
}

static int db_collect_identity_ids_for_selector(const char *selector,
                                                uint64_t **out_ids,
                                                int *out_count) {
  if (!out_ids || !out_count)
    return -1;
  *out_ids = NULL;
  *out_count = 0;
  if (!selector || !selector[0] || strcmp(selector, "*") == 0) {
    uint64_t *ids = (uint64_t *)malloc(sizeof(uint64_t));
    if (!ids)
      return -1;
    ids[0] = 0;
    *out_ids = ids;
    *out_count = 1;
    return 0;
  }
  if (strncmp(selector, "tag:", 4) == 0) {
    const char *tag = selector + 4;
    if (!tag[0])
      return -1;
    if (db_ensure_global_identity_tag_schema() != 0)
      return -1;
    const char *query = "SELECT global_identity_id "
                        "FROM global_identity_tags "
                        "WHERE tag = $1 "
                        "ORDER BY global_identity_id";
    const char *params[] = {tag};
    PGresult *res =
        pq_exec_params_global_locked(query, 1, NULL, params, NULL, NULL, 0);
    if (!res)
      return -1;
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
      PQclear(res);
      return -1;
    }
    int n = PQntuples(res);
    if (n == 0) {
      PQclear(res);
      return 0;
    }
    uint64_t *ids = (uint64_t *)calloc((size_t)n, sizeof(uint64_t));
    if (!ids) {
      PQclear(res);
      return -1;
    }
    for (int i = 0; i < n; i++) {
      char *endptr = NULL;
      uint64_t id = strtoull(PQgetvalue(res, i, 0), &endptr, 10);
      if (!endptr || *endptr != '\0' || id == 0) {
        free(ids);
        PQclear(res);
        return -1;
      }
      ids[i] = id;
    }
    PQclear(res);
    *out_ids = ids;
    *out_count = n;
    return 0;
  }

  uint64_t identity_id = db_resolve_single_identity_selector(selector);
  if (identity_id == UINT64_MAX)
    return -1;
  uint64_t *ids = (uint64_t *)malloc(sizeof(uint64_t));
  if (!ids)
    return -1;
  ids[0] = identity_id;
  *out_ids = ids;
  *out_count = 1;
  return 0;
}

static const WambleFact *find_fact(const WambleFact *facts, int fact_count,
                                   const char *key) {
  if (!facts || fact_count <= 0 || !key)
    return NULL;
  for (int i = 0; i < fact_count; i++) {
    if (strcmp(facts[i].key, key) == 0)
      return &facts[i];
  }
  return NULL;
}

static int fact_compare_numeric(double lhs, double rhs, const char *op) {
  if (strcmp(op, "eq") == 0)
    return lhs == rhs;
  if (strcmp(op, "ne") == 0)
    return lhs != rhs;
  if (strcmp(op, "gt") == 0)
    return lhs > rhs;
  if (strcmp(op, "gte") == 0)
    return lhs >= rhs;
  if (strcmp(op, "lt") == 0)
    return lhs < rhs;
  if (strcmp(op, "lte") == 0)
    return lhs <= rhs;
  return 0;
}

static int fact_matches_predicate(const WambleFact *fact, const char *op,
                                  int value_type, const char *value_text,
                                  double value_num, int value_bool) {
  if (strcmp(op, "exists") == 0)
    return fact != NULL;
  if (strcmp(op, "absent") == 0)
    return fact == NULL;
  if (!fact)
    return 0;
  if (fact->value_type == WAMBLE_TREATMENT_VALUE_STRING &&
      value_type == WAMBLE_TREATMENT_VALUE_STRING) {
    if (strcmp(op, "eq") == 0)
      return strcmp(fact->string_value, value_text ? value_text : "") == 0;
    if (strcmp(op, "ne") == 0)
      return strcmp(fact->string_value, value_text ? value_text : "") != 0;
    return 0;
  }
  if ((fact->value_type == WAMBLE_TREATMENT_VALUE_INT ||
       fact->value_type == WAMBLE_TREATMENT_VALUE_DOUBLE) &&
      (value_type == WAMBLE_TREATMENT_VALUE_INT ||
       value_type == WAMBLE_TREATMENT_VALUE_DOUBLE)) {
    double lhs = (fact->value_type == WAMBLE_TREATMENT_VALUE_INT)
                     ? (double)fact->int_value
                     : fact->double_value;
    return fact_compare_numeric(lhs, value_num, op);
  }
  if (fact->value_type == WAMBLE_TREATMENT_VALUE_BOOL &&
      value_type == WAMBLE_TREATMENT_VALUE_BOOL) {
    if (strcmp(op, "eq") == 0)
      return fact->bool_value == value_bool;
    if (strcmp(op, "ne") == 0)
      return fact->bool_value != value_bool;
  }
  return 0;
}

static void
normalize_policy_scope_resource(const char *action, const char *raw_resource,
                                char *out_scope, size_t out_scope_len,
                                char *out_resource, size_t out_resource_len) {
  if (!out_scope || !out_resource || out_scope_len == 0 ||
      out_resource_len == 0)
    return;
  out_scope[0] = '\0';
  out_resource[0] = '\0';
  const char *res = (raw_resource && raw_resource[0]) ? raw_resource : "*";
  const char *sep = strstr(res, "::");
  if (sep) {
    size_t scope_len = (size_t)(sep - res);
    if (scope_len >= out_scope_len)
      scope_len = out_scope_len - 1;
    memcpy(out_scope, res, scope_len);
    out_scope[scope_len] = '\0';
    snprintf(out_resource, out_resource_len, "%s", sep + 2);
    if (out_resource[0] == '\0')
      snprintf(out_resource, out_resource_len, "*");
    return;
  }
  if (strcmp(action ? action : "", "trust.tier") == 0 &&
      (strcmp(res, "*") == 0 || strncmp(res, "profile:", 8) == 0 ||
       strncmp(res, "profile_group:", 14) == 0)) {
    snprintf(out_scope, out_scope_len, "%s", res);
    snprintf(out_resource, out_resource_len, "tier");
    return;
  }
  snprintf(out_scope, out_scope_len, "*");
  snprintf(out_resource, out_resource_len, "%s", res);
}

int db_apply_config_policy_rules(const char *profile_key) {
  if (db_ensure_global_identity_schema() != 0 ||
      db_ensure_global_identity_tag_schema() != 0 ||
      db_ensure_global_policy_schema() != 0)
    return -1;
  const char *profile_scope_key =
      (profile_key && profile_key[0]) ? profile_key : "__default__";
  uint64_t snapshot_id = 0;
  (void)db_get_active_revision_id(profile_scope_key, &snapshot_id);

  PGresult *res =
      pq_exec_params_global_locked("BEGIN", 0, NULL, NULL, NULL, NULL, 0);
  if (!res)
    return -1;
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    PQclear(res);
    return -1;
  }
  PQclear(res);

  const char *delete_q =
      "DELETE FROM global_policy_rules "
      "WHERE source = md5($1) "
      "   OR (source = 'config' AND snapshot_revision_id IN ("
      "       SELECT id FROM global_runtime_config_revisions WHERE "
      "profile_key = $1))";
  const char *delete_params[] = {profile_scope_key};
  res = pq_exec_params_global_locked(delete_q, 1, NULL, delete_params, NULL,
                                     NULL, 0);
  if (!res) {
    (void)pq_exec_params_global_locked("ROLLBACK", 0, NULL, NULL, NULL, NULL,
                                       0);
    return -1;
  }
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    PQclear(res);
    (void)pq_exec_params_global_locked("ROLLBACK", 0, NULL, NULL, NULL, NULL,
                                       0);
    return -1;
  }
  PQclear(res);

  int count = config_policy_rule_count();
  for (int i = 0; i < count; i++) {
    const WamblePolicyRuleSpec *r = config_policy_rule_get(i);
    if (!r || !r->action || !r->resource || !r->effect)
      continue;
    uint64_t *identity_ids = NULL;
    int identity_count = 0;
    if (db_collect_identity_ids_for_selector(
            r->identity_selector, &identity_ids, &identity_count) != 0) {
      (void)pq_exec_params_global_locked("ROLLBACK", 0, NULL, NULL, NULL, NULL,
                                         0);
      return -1;
    }
    if (identity_count == 0) {
      free(identity_ids);
      continue;
    }
    char snapshot_id_str[32];
    if (snapshot_id > 0) {
      snprintf(snapshot_id_str, sizeof(snapshot_id_str), "%" PRIu64,
               snapshot_id);
    }
    char level_str[16];
    snprintf(level_str, sizeof(level_str), "%d", r->permission_level);
    char not_before_str[32];
    char not_after_str[32];
    const char *not_before = NULL;
    const char *not_after = NULL;
    if (r->not_before_at > 0) {
      snprintf(not_before_str, sizeof(not_before_str), "%" PRId64,
               r->not_before_at);
      not_before = not_before_str;
    }
    if (r->not_after_at > 0) {
      snprintf(not_after_str, sizeof(not_after_str), "%" PRId64,
               r->not_after_at);
      not_after = not_after_str;
    }
    char scope[256];
    char resource[256];
    normalize_policy_scope_resource(r->action, r->resource, scope,
                                    sizeof(scope), resource, sizeof(resource));
    for (int j = 0; j < identity_count; j++) {
      char identity_id_str[32];
      snprintf(identity_id_str, sizeof(identity_id_str), "%" PRIu64,
               identity_ids[j]);
      const char *insert_q =
          "INSERT INTO global_policy_rules "
          "(global_identity_id, action, resource, scope, effect, "
          "permission_level, "
          " policy_version, reason, source, snapshot_revision_id, "
          "not_before_at, "
          " not_after_at, context_key, context_value) "
          "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, md5($14), $9, "
          "        CASE WHEN $10::text IS NULL THEN NULL ELSE "
          "to_timestamp($10::double precision) END, "
          "        CASE WHEN $11::text IS NULL THEN NULL ELSE "
          "to_timestamp($11::double precision) END, "
          "        $12, $13)";
      const char *params[] = {
          identity_id_str,
          r->action,
          resource,
          scope,
          r->effect,
          level_str,
          r->policy_version ? r->policy_version : "v1",
          r->reason ? r->reason : "",
          snapshot_id > 0 ? snapshot_id_str : NULL,
          not_before,
          not_after,
          r->context_key,
          r->context_value,
          profile_scope_key,
      };
      res = pq_exec_params_global_locked(insert_q, 14, NULL, params, NULL, NULL,
                                         0);
      if (!res || PQresultStatus(res) != PGRES_COMMAND_OK) {
        if (res)
          PQclear(res);
        free(identity_ids);
        (void)pq_exec_params_global_locked("ROLLBACK", 0, NULL, NULL, NULL,
                                           NULL, 0);
        return -1;
      }
      PQclear(res);
    }
    free(identity_ids);
  }

  res = pq_exec_params_global_locked("COMMIT", 0, NULL, NULL, NULL, NULL, 0);
  if (!res)
    return -1;
  int ok = (PQresultStatus(res) == PGRES_COMMAND_OK) ? 0 : -1;
  PQclear(res);
  return ok;
}

static int config_find_treatment_group_index(const char *group_key) {
  int count = config_treatment_group_count();
  for (int i = 0; i < count; i++) {
    const WambleTreatmentGroupSpec *g = config_treatment_group_get(i);
    if (g && g->group_key && strcmp(g->group_key, group_key) == 0)
      return i;
  }
  return -1;
}

int db_validate_global_treatments(void) {
  if (db_ensure_global_treatment_schema() != 0)
    return -1;
  int group_count = config_treatment_group_count();
  int default_count = 0;
  for (int i = 0; i < group_count; i++) {
    const WambleTreatmentGroupSpec *g = config_treatment_group_get(i);
    if (!g || !g->group_key || !g->group_key[0])
      return -1;
    if (g->is_default)
      default_count++;
    for (int j = i + 1; j < group_count; j++) {
      const WambleTreatmentGroupSpec *other = config_treatment_group_get(j);
      if (other && other->group_key &&
          strcmp(other->group_key, g->group_key) == 0)
        return -1;
    }
  }
  if (group_count > 0 && default_count != 1)
    return -1;
  int edge_count = config_treatment_edge_count();
  for (int i = 0; i < edge_count; i++) {
    const WambleTreatmentEdgeSpec *e = config_treatment_edge_get(i);
    if (!e || !e->source_group_key || !e->target_group_key)
      return -1;
    if (config_find_treatment_group_index(e->source_group_key) < 0)
      return -1;
    if (!e->target_group_key[0])
      return -1;
  }
  int rule_count = config_treatment_rule_count();
  for (int i = 0; i < rule_count; i++) {
    const WambleTreatmentRuleSpec *r = config_treatment_rule_get(i);
    if (!r || !r->group_key ||
        config_find_treatment_group_index(r->group_key) < 0)
      return -1;
  }
  int output_count = config_treatment_output_count();
  for (int i = 0; i < output_count; i++) {
    const WambleTreatmentOutputSpec *o = config_treatment_output_get(i);
    if (!o || !o->group_key || !o->output_kind || !o->output_key ||
        config_find_treatment_group_index(o->group_key) < 0)
      return -1;
    for (int j = i + 1; j < output_count; j++) {
      const WambleTreatmentOutputSpec *other = config_treatment_output_get(j);
      if (!other)
        continue;
      if (strcmp(other->group_key ? other->group_key : "", o->group_key) == 0 &&
          strcmp(other->hook_name ? other->hook_name : "*",
                 o->hook_name ? o->hook_name : "*") == 0 &&
          strcmp(other->output_kind ? other->output_kind : "",
                 o->output_kind) == 0 &&
          strcmp(other->output_key ? other->output_key : "", o->output_key) ==
              0)
        return -1;
    }
  }
  return 0;
}

int db_apply_config_treatment_rules(const char *profile_key) {
  if (db_validate_global_treatments() != 0 ||
      db_ensure_global_identity_schema() != 0 ||
      db_ensure_global_identity_tag_schema() != 0)
    return -1;
  const char *profile_scope_key =
      (profile_key && profile_key[0]) ? profile_key : "__default__";
  uint64_t snapshot_id = 0;
  (void)db_get_active_revision_id(profile_scope_key, &snapshot_id);

  PGresult *res =
      pq_exec_params_global_locked("BEGIN", 0, NULL, NULL, NULL, NULL, 0);
  if (!res)
    return -1;
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    PQclear(res);
    return -1;
  }
  PQclear(res);

  const char *delete_groups =
      "DELETE FROM global_treatment_groups WHERE source = md5($1)";
  const char *delete_rules =
      "DELETE FROM global_treatment_assignment_rules WHERE source = md5($1)";
  const char *delete_edges =
      "DELETE FROM global_treatment_group_edges WHERE source = md5($1)";
  const char *delete_outputs =
      "DELETE FROM global_treatment_group_outputs WHERE source = md5($1)";
  const char *delete_params[] = {profile_scope_key};
  const char *delete_sql[] = {delete_outputs, delete_edges, delete_rules,
                              delete_groups};
  for (size_t i = 0; i < sizeof(delete_sql) / sizeof(delete_sql[0]); i++) {
    res = pq_exec_params_global_locked(delete_sql[i], 1, NULL, delete_params,
                                       NULL, NULL, 0);
    if (!res || PQresultStatus(res) != PGRES_COMMAND_OK) {
      if (res)
        PQclear(res);
      (void)pq_exec_params_global_locked("ROLLBACK", 0, NULL, NULL, NULL, NULL,
                                         0);
      return -1;
    }
    PQclear(res);
  }

  char snapshot_id_str[32];
  snprintf(snapshot_id_str, sizeof(snapshot_id_str), "%" PRIu64, snapshot_id);
  const char *snapshot_param = snapshot_id_str;

  for (int i = 0; i < config_treatment_group_count(); i++) {
    const WambleTreatmentGroupSpec *g = config_treatment_group_get(i);
    if (!g)
      continue;
    char priority_str[16];
    snprintf(priority_str, sizeof(priority_str), "%d", g->priority);
    const char *params[] = {g->group_key, priority_str,
                            g->is_default ? "true" : "false", snapshot_param,
                            profile_scope_key};
    res = pq_exec_params_global_locked(
        "INSERT INTO global_treatment_groups "
        "(group_key, priority, is_default, snapshot_revision_id, source) "
        "VALUES ($1, $2, $3::boolean, $4, md5($5))",
        5, NULL, params, NULL, NULL, 0);
    if (!res || PQresultStatus(res) != PGRES_COMMAND_OK) {
      if (res)
        PQclear(res);
      (void)pq_exec_params_global_locked("ROLLBACK", 0, NULL, NULL, NULL, NULL,
                                         0);
      return -1;
    }
    PQclear(res);
  }

  for (int i = 0; i < config_treatment_rule_count(); i++) {
    const WambleTreatmentRuleSpec *r = config_treatment_rule_get(i);
    if (!r)
      continue;
    uint64_t *identity_ids = NULL;
    int identity_count = 0;
    if (db_collect_identity_ids_for_selector(
            r->identity_selector, &identity_ids, &identity_count) != 0) {
      (void)pq_exec_params_global_locked("ROLLBACK", 0, NULL, NULL, NULL, NULL,
                                         0);
      return -1;
    }
    char priority_str[16];
    snprintf(priority_str, sizeof(priority_str), "%d", r->priority);
    for (int j = 0; j < identity_count; j++) {
      char identity_id_str[32];
      snprintf(identity_id_str, sizeof(identity_id_str), "%" PRIu64,
               identity_ids[j]);
      const char *rule_params[] = {identity_id_str, r->profile_scope,
                                   r->group_key,    priority_str,
                                   snapshot_param,  profile_scope_key};
      res = pq_exec_params_global_locked(
          "INSERT INTO global_treatment_assignment_rules "
          "(global_identity_id, profile_scope, group_key, priority, "
          " snapshot_revision_id, source) "
          "VALUES ($1, $2, $3, $4, $5, md5($6)) RETURNING id",
          6, NULL, rule_params, NULL, NULL, 0);
      if (!res || PQresultStatus(res) != PGRES_TUPLES_OK ||
          PQntuples(res) == 0) {
        if (res)
          PQclear(res);
        free(identity_ids);
        (void)pq_exec_params_global_locked("ROLLBACK", 0, NULL, NULL, NULL,
                                           NULL, 0);
        return -1;
      }
      uint64_t rule_id = strtoull(PQgetvalue(res, 0, 0), NULL, 10);
      PQclear(res);
      for (int k = 0; k < r->predicate_count; k++) {
        char rule_id_str[32];
        char type_str[16];
        char num_str[64];
        snprintf(rule_id_str, sizeof(rule_id_str), "%" PRIu64, rule_id);
        snprintf(type_str, sizeof(type_str), "%d",
                 (int)r->predicates[k].value.type);
        const char *num_param = NULL;
        const char *bool_param = NULL;
        if (r->predicates[k].value.type == WAMBLE_TREATMENT_VALUE_INT) {
          snprintf(num_str, sizeof(num_str), "%" PRId64,
                   r->predicates[k].value.int_value);
          num_param = num_str;
        } else if (r->predicates[k].value.type ==
                   WAMBLE_TREATMENT_VALUE_DOUBLE) {
          snprintf(num_str, sizeof(num_str), "%.17g",
                   r->predicates[k].value.double_value);
          num_param = num_str;
        } else if (r->predicates[k].value.type == WAMBLE_TREATMENT_VALUE_BOOL) {
          bool_param = r->predicates[k].value.bool_value ? "true" : "false";
        }
        const char *pred_params[] = {
            rule_id_str,
            r->predicates[k].fact_key,
            r->predicates[k].op,
            type_str,
            r->predicates[k].value.string_value,
            num_param,
            bool_param,
            r->predicates[k].value.fact_key,
        };
        res = pq_exec_params_global_locked(
            "INSERT INTO global_treatment_assignment_predicates "
            "(rule_id, fact_key, op, value_type, value_text, value_num, "
            " value_bool, value_fact_ref) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7::boolean, $8)",
            8, NULL, pred_params, NULL, NULL, 0);
        if (!res || PQresultStatus(res) != PGRES_COMMAND_OK) {
          if (res)
            PQclear(res);
          free(identity_ids);
          (void)pq_exec_params_global_locked("ROLLBACK", 0, NULL, NULL, NULL,
                                             NULL, 0);
          return -1;
        }
        PQclear(res);
      }
    }
    free(identity_ids);
  }

  for (int i = 0; i < config_treatment_edge_count(); i++) {
    const WambleTreatmentEdgeSpec *e = config_treatment_edge_get(i);
    if (!e)
      continue;
    const char *params[] = {e->source_group_key, e->target_group_key,
                            snapshot_param, profile_scope_key};
    res = pq_exec_params_global_locked(
        "INSERT INTO global_treatment_group_edges "
        "(source_group_key, target_group_key, snapshot_revision_id, source) "
        "VALUES ($1, $2, $3, md5($4))",
        4, NULL, params, NULL, NULL, 0);
    if (!res || PQresultStatus(res) != PGRES_COMMAND_OK) {
      if (res)
        PQclear(res);
      (void)pq_exec_params_global_locked("ROLLBACK", 0, NULL, NULL, NULL, NULL,
                                         0);
      return -1;
    }
    PQclear(res);
  }

  for (int i = 0; i < config_treatment_output_count(); i++) {
    const WambleTreatmentOutputSpec *o = config_treatment_output_get(i);
    if (!o)
      continue;
    char type_str[16];
    char num_str[64];
    snprintf(type_str, sizeof(type_str), "%d", (int)o->value.type);
    const char *num_param = NULL;
    const char *bool_param = NULL;
    if (o->value.type == WAMBLE_TREATMENT_VALUE_INT) {
      snprintf(num_str, sizeof(num_str), "%" PRId64, o->value.int_value);
      num_param = num_str;
    } else if (o->value.type == WAMBLE_TREATMENT_VALUE_DOUBLE) {
      snprintf(num_str, sizeof(num_str), "%.17g", o->value.double_value);
      num_param = num_str;
    } else if (o->value.type == WAMBLE_TREATMENT_VALUE_BOOL) {
      bool_param = o->value.bool_value ? "true" : "false";
    }
    const char *params[] = {
        o->group_key,      o->hook_name ? o->hook_name : "*",
        o->output_kind,    o->output_key,
        type_str,          o->value.string_value,
        num_param,         bool_param,
        o->value.fact_key, snapshot_param,
        profile_scope_key};
    res = pq_exec_params_global_locked(
        "INSERT INTO global_treatment_group_outputs "
        "(group_key, hook_name, output_kind, output_key, value_type, "
        " value_text, value_num, value_bool, value_fact_ref, "
        " snapshot_revision_id, source) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8::boolean, $9, $10, md5($11))",
        11, NULL, params, NULL, NULL, 0);
    if (!res || PQresultStatus(res) != PGRES_COMMAND_OK) {
      if (res)
        PQclear(res);
      (void)pq_exec_params_global_locked("ROLLBACK", 0, NULL, NULL, NULL, NULL,
                                         0);
      return -1;
    }
    PQclear(res);
  }

  res = pq_exec_params_global_locked("COMMIT", 0, NULL, NULL, NULL, NULL, 0);
  if (!res)
    return -1;
  int ok = (PQresultStatus(res) == PGRES_COMMAND_OK) ? 0 : -1;
  PQclear(res);
  return ok;
}

static int db_materialize_treatment_value_from_row(PGresult *res, int row,
                                                   const WambleFact *facts,
                                                   int fact_count,
                                                   WambleTreatmentAction *out) {
  if (!res || !out)
    return -1;
  long value_type = strtol(PQgetvalue(res, row, 3), NULL, 10);
  out->value_type = (WambleTreatmentValueType)value_type;
  switch (out->value_type) {
  case WAMBLE_TREATMENT_VALUE_STRING:
    snprintf(out->string_value, sizeof(out->string_value), "%s",
             PQgetvalue(res, row, 4));
    break;
  case WAMBLE_TREATMENT_VALUE_INT:
    out->int_value = strtoll(PQgetvalue(res, row, 5), NULL, 10);
    break;
  case WAMBLE_TREATMENT_VALUE_DOUBLE:
    out->double_value = strtod(PQgetvalue(res, row, 5), NULL);
    break;
  case WAMBLE_TREATMENT_VALUE_BOOL:
    out->bool_value = (PQgetvalue(res, row, 6)[0] == 't' ||
                       PQgetvalue(res, row, 6)[0] == '1');
    break;
  case WAMBLE_TREATMENT_VALUE_FACT_REF: {
    const WambleFact *fact =
        find_fact(facts, fact_count, PQgetvalue(res, row, 7));
    if (!fact)
      return -1;
    out->value_type = fact->value_type;
    if (fact->value_type == WAMBLE_TREATMENT_VALUE_STRING) {
      snprintf(out->string_value, sizeof(out->string_value), "%s",
               fact->string_value);
    } else if (fact->value_type == WAMBLE_TREATMENT_VALUE_INT) {
      out->int_value = fact->int_value;
    } else if (fact->value_type == WAMBLE_TREATMENT_VALUE_DOUBLE) {
      out->double_value = fact->double_value;
    } else if (fact->value_type == WAMBLE_TREATMENT_VALUE_BOOL) {
      out->bool_value = fact->bool_value;
    }
    break;
  }
  default:
    break;
  }
  return 0;
}

static void db_apply_policy_treatment_overrides(const uint8_t *token,
                                                const char *profile_name,
                                                WamblePolicyDecision *out,
                                                const char *context_key,
                                                const char *context_value) {
  if (!token || !out)
    return;

  WambleFact facts[8];
  int fact_count = 0;
  memset(facts, 0, sizeof(facts));

  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "policy.action");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_STRING;
  snprintf(facts[fact_count].string_value,
           sizeof(facts[fact_count].string_value), "%s", out->action);
  fact_count++;

  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "policy.resource");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_STRING;
  snprintf(facts[fact_count].string_value,
           sizeof(facts[fact_count].string_value), "%s", out->resource);
  fact_count++;

  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "policy.allowed");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_BOOL;
  facts[fact_count].bool_value = out->allowed ? 1 : 0;
  fact_count++;

  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "policy.permission_level");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_INT;
  facts[fact_count].int_value = out->permission_level;
  fact_count++;

  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "policy.effect");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_STRING;
  snprintf(facts[fact_count].string_value,
           sizeof(facts[fact_count].string_value), "%s", out->effect);
  fact_count++;

  if (profile_name && profile_name[0] && fact_count < 8) {
    snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
             "profile.name");
    facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_STRING;
    snprintf(facts[fact_count].string_value,
             sizeof(facts[fact_count].string_value), "%s", profile_name);
    fact_count++;
  }

  if (context_key && context_key[0] && fact_count < 8) {
    snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
             "policy.context_key");
    facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_STRING;
    snprintf(facts[fact_count].string_value,
             sizeof(facts[fact_count].string_value), "%s", context_key);
    fact_count++;
  }

  if (context_value && context_value[0] && fact_count < 8) {
    snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
             "policy.context_value");
    facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_STRING;
    snprintf(facts[fact_count].string_value,
             sizeof(facts[fact_count].string_value), "%s", context_value);
    fact_count++;
  }

  WambleTreatmentAction actions[8];
  int action_count = 0;
  if (db_resolve_treatment_actions(token, profile_name ? profile_name : "",
                                   "policy.resolve", NULL, facts, fact_count,
                                   actions, 8, &action_count) != DB_OK) {
    return;
  }

  for (int i = 0; i < action_count; i++) {
    const WambleTreatmentAction *action = &actions[i];
    if (strcmp(action->output_kind, "behavior") != 0)
      continue;

    if ((strcmp(action->output_key, "policy.allow") == 0 ||
         strcmp(action->output_key, "policy.deny") == 0) &&
        (action->value_type == WAMBLE_TREATMENT_VALUE_BOOL ||
         action->value_type == WAMBLE_TREATMENT_VALUE_INT)) {
      int enabled = (action->value_type == WAMBLE_TREATMENT_VALUE_BOOL)
                        ? action->bool_value
                        : (action->int_value != 0);
      if (!enabled)
        continue;
      out->allowed = (strcmp(action->output_key, "policy.allow") == 0) ? 1 : 0;
      snprintf(out->effect, sizeof(out->effect), "%s",
               out->allowed ? "allow" : "deny");
      snprintf(out->reason, sizeof(out->reason), "%s",
               out->allowed ? "experiment_override_allow"
                            : "experiment_override_deny");
      snprintf(out->policy_version, sizeof(out->policy_version), "%s",
               "treatment");
      continue;
    }

    if (strcmp(action->output_key, "policy.permission_level.set") == 0 &&
        action->value_type == WAMBLE_TREATMENT_VALUE_INT) {
      out->permission_level = (int)action->int_value;
    } else if (strcmp(action->output_key, "policy.permission_level.delta") ==
                   0 &&
               action->value_type == WAMBLE_TREATMENT_VALUE_INT) {
      out->permission_level += (int)action->int_value;
    } else if (strcmp(action->output_key, "policy.permission_level.min") == 0 &&
               action->value_type == WAMBLE_TREATMENT_VALUE_INT &&
               out->permission_level < (int)action->int_value) {
      out->permission_level = (int)action->int_value;
    } else if (strcmp(action->output_key, "policy.reason") == 0 &&
               action->value_type == WAMBLE_TREATMENT_VALUE_STRING &&
               action->string_value[0]) {
      snprintf(out->reason, sizeof(out->reason), "%s", action->string_value);
      snprintf(out->policy_version, sizeof(out->policy_version), "%s",
               "treatment");
    }
  }

  if (!out->allowed)
    out->permission_level = 0;
}

DbStatus db_get_session_treatment_assignment(const uint8_t *token,
                                             WambleTreatmentAssignment *out) {
  if (!token || !out)
    return DB_ERR_BAD_DATA;
  if (db_ensure_profile_treatment_schema() != 0)
    return DB_ERR_EXEC;
  char token_hex[33];
  bytes_to_hex(token, TOKEN_LENGTH, token_hex);
  const char *params[] = {token_hex};
  PGresult *res = pq_exec_params_locked(
      "SELECT COALESCE(treatment_group_key, ''), COALESCE(treatment_rule_id, "
      "0), "
      "       COALESCE(treatment_snapshot_revision_id, 0), "
      "       COALESCE(EXTRACT(EPOCH FROM treatment_assigned_at)::bigint, 0) "
      "FROM sessions WHERE token = decode($1, 'hex')",
      1, NULL, params, NULL, NULL, 0);
  if (!res)
    return DB_ERR_CONN;
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    return DB_ERR_EXEC;
  }
  if (PQntuples(res) == 0) {
    PQclear(res);
    return DB_NOT_FOUND;
  }
  memset(out, 0, sizeof(*out));
  snprintf(out->group_key, sizeof(out->group_key), "%s", PQgetvalue(res, 0, 0));
  out->rule_id = strtoull(PQgetvalue(res, 0, 1), NULL, 10);
  out->snapshot_revision_id = strtoull(PQgetvalue(res, 0, 2), NULL, 10);
  out->assigned_at = (time_t)strtoull(PQgetvalue(res, 0, 3), NULL, 10);
  PQclear(res);
  return out->group_key[0] ? DB_OK : DB_NOT_FOUND;
}

DbStatus db_assign_session_treatment(const uint8_t *token, const char *profile,
                                     const WambleFact *facts, int fact_count,
                                     WambleTreatmentAssignment *out) {
  if (!token)
    return DB_ERR_BAD_DATA;
  if (db_ensure_profile_treatment_schema() != 0 ||
      db_ensure_global_treatment_schema() != 0)
    return DB_ERR_EXEC;

  uint64_t identity_id = 0;
  DbStatus sid_status = db_get_or_create_session_identity(token, &identity_id);
  if (sid_status != DB_OK)
    return sid_status;

  const char *profile_name = db_treatment_profile_key(profile);
  const char *group = config_profile_group(profile_name);
  if (!group)
    group = "";
  char scope_exact[256];
  char scope_group[256];
  snprintf(scope_exact, sizeof(scope_exact), "profile:%s", profile_name);
  snprintf(scope_group, sizeof(scope_group), "profile_group:%s", group);
  char identity_id_str[32];
  snprintf(identity_id_str, sizeof(identity_id_str), "%" PRIu64, identity_id);

  PGresult *res = pq_exec_params_global_locked(
      "SELECT id, group_key, priority, COALESCE(snapshot_revision_id, 0), "
      "       profile_scope "
      "FROM global_treatment_assignment_rules "
      "WHERE (global_identity_id = $1 OR global_identity_id = 0) "
      "  AND (profile_scope = $2 OR profile_scope = $3 OR profile_scope = '*') "
      "  AND source = md5($4) "
      "ORDER BY "
      "  CASE WHEN global_identity_id = $1 THEN 0 ELSE 1 END, "
      "  CASE WHEN profile_scope = $2 THEN 0 WHEN profile_scope = $3 THEN 1 "
      "ELSE 2 END, "
      "  priority DESC, id DESC",
      4, NULL,
      (const char *[]){identity_id_str, scope_exact, scope_group, profile_name},
      NULL, NULL, 0);
  if (!res)
    return DB_ERR_CONN;
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    return DB_ERR_EXEC;
  }

  uint64_t matched_rule_id = 0;
  uint64_t matched_snapshot_id = 0;
  char matched_group[128] = {0};
  for (int i = 0; i < PQntuples(res); i++) {
    uint64_t rule_id = strtoull(PQgetvalue(res, i, 0), NULL, 10);
    PGresult *pred_res = pq_exec_params_global_locked(
        "SELECT fact_key, op, value_type, COALESCE(value_text, ''), "
        "       COALESCE(value_num, 0), COALESCE(value_bool, FALSE) "
        "FROM global_treatment_assignment_predicates WHERE rule_id = $1",
        1, NULL, (const char *[]){PQgetvalue(res, i, 0)}, NULL, NULL, 0);
    if (!pred_res) {
      PQclear(res);
      return DB_ERR_CONN;
    }
    if (PQresultStatus(pred_res) != PGRES_TUPLES_OK) {
      PQclear(pred_res);
      PQclear(res);
      return DB_ERR_EXEC;
    }
    int matches = 1;
    for (int j = 0; j < PQntuples(pred_res); j++) {
      const WambleFact *fact =
          find_fact(facts, fact_count, PQgetvalue(pred_res, j, 0));
      int value_type = (int)strtol(PQgetvalue(pred_res, j, 2), NULL, 10);
      double value_num = strtod(PQgetvalue(pred_res, j, 4), NULL);
      int value_bool = (PQgetvalue(pred_res, j, 5)[0] == 't' ||
                        PQgetvalue(pred_res, j, 5)[0] == '1');
      if (!fact_matches_predicate(fact, PQgetvalue(pred_res, j, 1), value_type,
                                  PQgetvalue(pred_res, j, 3), value_num,
                                  value_bool)) {
        matches = 0;
        break;
      }
    }
    PQclear(pred_res);
    if (!matches)
      continue;
    if (matched_group[0] != '\0' &&
        strcmp(matched_group, PQgetvalue(res, i, 1)) != 0) {
      PQclear(res);
      return DB_ERR_BAD_DATA;
    }
    matched_rule_id = rule_id;
    matched_snapshot_id = strtoull(PQgetvalue(res, i, 3), NULL, 10);
    snprintf(matched_group, sizeof(matched_group), "%s", PQgetvalue(res, i, 1));
    break;
  }
  PQclear(res);

  if (!matched_group[0]) {
    res = pq_exec_params_global_locked(
        "SELECT group_key, COALESCE(snapshot_revision_id, 0) "
        "FROM global_treatment_groups "
        "WHERE is_default = TRUE AND source = md5($1) "
        "ORDER BY priority DESC, id DESC LIMIT 1",
        1, NULL, (const char *[]){profile_name}, NULL, NULL, 0);
    if (!res)
      return DB_ERR_CONN;
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
      if (res)
        PQclear(res);
      return DB_ERR_EXEC;
    }
    snprintf(matched_group, sizeof(matched_group), "%s", PQgetvalue(res, 0, 0));
    matched_snapshot_id = strtoull(PQgetvalue(res, 0, 1), NULL, 10);
    PQclear(res);
  }

  char token_hex[33];
  bytes_to_hex(token, TOKEN_LENGTH, token_hex);
  char rule_id_str[32];
  char snapshot_str[32];
  const char *rule_param = NULL;
  const char *snapshot_param = NULL;
  if (matched_rule_id > 0) {
    snprintf(rule_id_str, sizeof(rule_id_str), "%" PRIu64, matched_rule_id);
    rule_param = rule_id_str;
  }
  if (matched_snapshot_id > 0) {
    snprintf(snapshot_str, sizeof(snapshot_str), "%" PRIu64,
             matched_snapshot_id);
    snapshot_param = snapshot_str;
  }
  res = pq_exec_params_locked(
      "UPDATE sessions SET treatment_group_key = $2, treatment_rule_id = $3, "
      "treatment_snapshot_revision_id = $4, treatment_assigned_at = NOW() "
      "WHERE token = decode($1, 'hex')",
      4, NULL,
      (const char *[]){token_hex, matched_group, rule_param, snapshot_param},
      NULL, NULL, 0);
  if (!res)
    return DB_ERR_CONN;
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    PQclear(res);
    return DB_ERR_EXEC;
  }
  PQclear(res);

  res = pq_exec_params_global_locked(
      "INSERT INTO global_identity_tags(global_identity_id, tag) "
      "SELECT $1, output_key FROM global_treatment_group_outputs "
      "WHERE group_key = $2 AND output_kind = 'tag' "
      "  AND source = md5($3) "
      "ON CONFLICT DO NOTHING",
      3, NULL, (const char *[]){identity_id_str, matched_group, profile_name},
      NULL, NULL, 0);
  if (res)
    PQclear(res);

  if (out) {
    memset(out, 0, sizeof(*out));
    snprintf(out->group_key, sizeof(out->group_key), "%s", matched_group);
    out->rule_id = matched_rule_id;
    out->snapshot_revision_id = matched_snapshot_id;
    out->assigned_at = wamble_now_wall();
  }
  return DB_OK;
}

DbStatus db_resolve_treatment_actions(const uint8_t *token, const char *profile,
                                      const char *hook_name,
                                      const char *opponent_group_key,
                                      const WambleFact *facts, int fact_count,
                                      WambleTreatmentAction *out, int max_out,
                                      int *out_count) {
  if (out_count)
    *out_count = 0;
  if (!token || !hook_name || !out || max_out <= 0)
    return DB_ERR_BAD_DATA;
  const char *profile_key = db_treatment_profile_key(profile);
  WambleTreatmentAssignment assignment = {0};
  DbStatus st = db_assign_session_treatment(token, profile_key, facts,
                                            fact_count, &assignment);
  if (st != DB_OK)
    return st;
  if (opponent_group_key && opponent_group_key[0] &&
      !db_treatment_edge_allows(profile_key, assignment.group_key,
                                opponent_group_key))
    return DB_NOT_FOUND;
  PGresult *res = pq_exec_params_global_locked(
      "SELECT hook_name, output_kind, output_key, value_type, "
      "       COALESCE(value_text, ''), COALESCE(value_num, 0), "
      "       COALESCE(value_bool, FALSE), COALESCE(value_fact_ref, '') "
      "FROM global_treatment_group_outputs "
      "WHERE group_key = $1 AND (hook_name = $2 OR hook_name = '*') "
      "  AND source = md5($3) "
      "ORDER BY CASE WHEN hook_name = $2 THEN 0 ELSE 1 END, id",
      3, NULL, (const char *[]){assignment.group_key, hook_name, profile_key},
      NULL, NULL, 0);
  if (!res)
    return DB_ERR_CONN;
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    return DB_ERR_EXEC;
  }
  int n = PQntuples(res);
  if (n > max_out)
    n = max_out;
  for (int i = 0; i < n; i++) {
    memset(&out[i], 0, sizeof(out[i]));
    snprintf(out[i].hook_name, sizeof(out[i].hook_name), "%s",
             PQgetvalue(res, i, 0));
    snprintf(out[i].output_kind, sizeof(out[i].output_kind), "%s",
             PQgetvalue(res, i, 1));
    snprintf(out[i].output_key, sizeof(out[i].output_key), "%s",
             PQgetvalue(res, i, 2));
    if (db_materialize_treatment_value_from_row(res, i, facts, fact_count,
                                                &out[i]) != 0) {
      memset(&out[i], 0, sizeof(out[i]));
    }
  }
  PQclear(res);
  if (out_count)
    *out_count = n;
  return DB_OK;
}

int db_treatment_edge_allows(const char *profile, const char *source_group_key,
                             const char *target_group_key) {
  if (!source_group_key || !source_group_key[0] || !target_group_key ||
      !target_group_key[0])
    return 1;
  if (db_ensure_global_treatment_schema() != 0)
    return 1;
  const char *profile_key = db_treatment_profile_key(profile);
  PGresult *res = pq_exec_params_global_locked(
      "SELECT 1 FROM global_treatment_group_edges "
      "WHERE source_group_key = $1 "
      "  AND (target_group_key = $2 OR target_group_key = '*') "
      "  AND source = md5($3) "
      "LIMIT 1",
      3, NULL,
      (const char *[]){source_group_key, target_group_key, profile_key}, NULL,
      NULL, 0);
  if (!res)
    return 1;
  int allowed =
      (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) ? 1 : 0;
  PQclear(res);
  return allowed;
}

static int db_get_player_public_key_by_id(uint64_t player_id,
                                          uint8_t out_public_key[32]) {
  const char *query =
      "SELECT ENCODE(public_key, 'hex') FROM players WHERE id = $1";
  char player_id_str[32];
  snprintf(player_id_str, sizeof(player_id_str), "%" PRIu64, player_id);
  const char *paramValues[] = {player_id_str};
  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);
  if (!res)
    return -1;
  if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
    PQclear(res);
    return -1;
  }
  const char *hex = PQgetvalue(res, 0, 0);
  if (!hex || strlen(hex) != 64) {
    PQclear(res);
    return -1;
  }
  hex_to_bytes(hex, out_public_key, 32);
  PQclear(res);
  return 0;
}

DbStatus db_resolve_policy_decision(const uint8_t *token, const char *profile,
                                    const char *action, const char *resource,
                                    const char *context_key,
                                    const char *context_value,
                                    WamblePolicyDecision *out) {
  if (!token || !action || !action[0] || !resource || !resource[0] || !out)
    return DB_ERR_BAD_DATA;
  memset(out, 0, sizeof(*out));
  snprintf(out->action, sizeof(out->action), "%s", action);
  snprintf(out->resource, sizeof(out->resource), "%s", resource);
  snprintf(out->effect, sizeof(out->effect), "deny");
  snprintf(out->policy_version, sizeof(out->policy_version), "v1");
  snprintf(out->reason, sizeof(out->reason), "default_deny_no_rule");
  snprintf(out->scope, sizeof(out->scope), "*");

  if (db_ensure_global_identity_schema() != 0 ||
      db_ensure_global_policy_schema() != 0)
    return DB_ERR_EXEC;

  uint64_t identity_id = 0;
  DbStatus sid_status = db_get_or_create_session_identity(token, &identity_id);
  if (sid_status != DB_OK)
    return sid_status;
  out->global_identity_id = identity_id;

  const char *profile_name = (profile && profile[0]) ? profile : "";
  const char *group = config_profile_group(profile_name);
  if (!group)
    group = "";

  char scope_exact[256];
  char scope_group[256];
  snprintf(scope_exact, sizeof(scope_exact), "profile:%s", profile_name);
  snprintf(scope_group, sizeof(scope_group), "profile_group:%s", group);
  char identity_id_str[32];
  snprintf(identity_id_str, sizeof(identity_id_str), "%" PRIu64, identity_id);

  const char *query =
      "SELECT id, effect, permission_level, policy_version, "
      "       COALESCE(reason, ''), scope, "
      "       COALESCE(snapshot_revision_id, 0) "
      "FROM global_policy_rules "
      "WHERE action = $1 "
      "  AND (resource = $2 OR resource = '*') "
      "  AND (global_identity_id = $3 OR global_identity_id = 0) "
      "  AND (scope = $4 OR scope = $5 OR scope = '*') "
      "  AND (context_key IS NULL OR "
      "       ($6::text IS NOT NULL AND context_key = $6 AND "
      "        COALESCE(context_value, '') = COALESCE($7, ''))) "
      "  AND (not_before_at IS NULL OR not_before_at <= NOW()) "
      "  AND (not_after_at IS NULL OR not_after_at >= NOW()) "
      "ORDER BY "
      "  CASE WHEN global_identity_id = $3 THEN 0 ELSE 1 END, "
      "  CASE WHEN scope = $4 THEN 0 WHEN scope = $5 THEN 1 ELSE 2 END, "
      "  CASE WHEN resource = $2 THEN 0 ELSE 1 END, "
      "  CASE effect WHEN 'deny' THEN 0 ELSE 1 END, "
      "  id DESC "
      "LIMIT 1";
  const char *params[] = {action,       resource,    identity_id_str,
                          scope_exact,  scope_group, context_key,
                          context_value};
  PGresult *res =
      pq_exec_params_global_locked(query, 7, NULL, params, NULL, NULL, 0);
  if (!res)
    return DB_ERR_CONN;
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    return DB_ERR_EXEC;
  }
  if (PQntuples(res) == 0) {
    PQclear(res);
    out->allowed = 0;
    db_apply_policy_treatment_overrides(token, profile_name, out, context_key,
                                        context_value);
    if (!out->allowed)
      out->permission_level = 0;
    return DB_OK;
  }

  char *e = NULL;
  uint64_t rule_id = strtoull(PQgetvalue(res, 0, 0), &e, 10);
  if (!e || *e != '\0') {
    PQclear(res);
    return DB_ERR_BAD_DATA;
  }
  const char *effect = PQgetvalue(res, 0, 1);
  char *lp = NULL;
  long level = strtol(PQgetvalue(res, 0, 2), &lp, 10);
  if (!lp || *lp != '\0') {
    PQclear(res);
    return DB_ERR_BAD_DATA;
  }
  char *sp = NULL;
  uint64_t snapshot_revision_id = strtoull(PQgetvalue(res, 0, 6), &sp, 10);
  if (!sp || *sp != '\0')
    snapshot_revision_id = 0;

  out->rule_id = rule_id;
  out->snapshot_revision_id = snapshot_revision_id;
  out->permission_level = (int)level;
  snprintf(out->effect, sizeof(out->effect), "%s",
           effect && effect[0] ? effect : "deny");
  snprintf(out->policy_version, sizeof(out->policy_version), "%s",
           PQgetvalue(res, 0, 3));
  snprintf(out->reason, sizeof(out->reason), "%s", PQgetvalue(res, 0, 4));
  snprintf(out->scope, sizeof(out->scope), "%s", PQgetvalue(res, 0, 5));
  out->allowed = (strcmp(out->effect, "allow") == 0) ? 1 : 0;
  PQclear(res);
  db_apply_policy_treatment_overrides(token, profile_name, out, context_key,
                                      context_value);
  if (!out->allowed)
    out->permission_level = 0;
  return DB_OK;
}

const WambleQueryService *wamble_get_db_query_service(void) {
  static WambleQueryService svc;
  static int initialized = 0;
  if (!initialized) {
    svc.list_boards_by_status = db_list_boards_by_status;
    svc.get_board = db_get_board;
    svc.get_longest_game_moves = db_get_longest_game_moves;
    svc.get_active_session_count = db_get_active_session_count;
    svc.get_max_board_id = db_get_max_board_id;
    svc.get_session_by_token = db_get_session_by_token;
    svc.create_session = db_create_session;
    svc.get_persistent_session_by_token = db_get_persistent_session_by_token;
    svc.get_player_total_score = db_get_player_total_score;
    svc.get_player_prediction_score = db_get_player_prediction_score;
    svc.get_player_rating = db_get_player_rating;
    svc.get_session_games_played = db_get_session_games_played;
    svc.get_session_chess960_games_played =
        db_get_session_chess960_games_played;
    svc.get_persistent_player_stats = db_get_persistent_player_stats;
    svc.get_leaderboard = db_get_leaderboard;
    svc.get_moves_for_board = db_get_moves_for_board;
    svc.get_pending_predictions = db_get_pending_predictions;
    svc.create_prediction = db_create_prediction;
    svc.link_session_to_pubkey = db_async_link_session_to_pubkey;
    svc.unlink_session_identity = db_async_unlink_session_identity;
    svc.get_session_treatment_assignment = db_get_session_treatment_assignment;
    svc.resolve_policy_decision = db_resolve_policy_decision;
    svc.resolve_treatment_actions = db_resolve_treatment_actions;
    svc.treatment_edge_allows = db_treatment_edge_allows;
    initialized = 1;
  }
  return &svc;
}

static const WambleQueryService *get_query_service(void) {
  const WambleQueryService *qs = wamble_get_query_service();
  if (qs)
    return qs;
  return wamble_get_db_query_service();
}

static DbBoardIdList query_list_error(void) {
  DbBoardIdList out = {0};
  out.status = DB_ERR_EXEC;
  out.ids = NULL;
  out.count = 0;
  return out;
}

static DbBoardResult query_board_error(void) {
  DbBoardResult out = {0};
  out.status = DB_ERR_EXEC;
  out.fen[0] = '\0';
  out.status_text[0] = '\0';
  out.created_at = 0;
  out.last_assignment_time = 0;
  out.last_move_time = 0;
  out.reservation_time = 0;
  out.reserved_for_white = false;
  return out;
}

static DbMovesResult query_moves_error(void) {
  DbMovesResult out = {0};
  out.status = DB_ERR_EXEC;
  out.rows = NULL;
  out.count = 0;
  return out;
}

static DbPredictionsResult query_predictions_error(void) {
  DbPredictionsResult out = {0};
  out.status = DB_ERR_EXEC;
  out.rows = NULL;
  out.count = 0;
  return out;
}

static DbLeaderboardResult query_leaderboard_error(void) {
  DbLeaderboardResult out = {0};
  out.status = DB_ERR_EXEC;
  out.rows = NULL;
  out.count = 0;
  out.self_rank = 0;
  return out;
}

DbBoardIdList wamble_query_list_boards_by_status(const char *status) {
  const WambleQueryService *qs = get_query_service();
  if (!qs || !qs->list_boards_by_status || !status)
    return query_list_error();
  return qs->list_boards_by_status(status);
}

DbBoardResult wamble_query_get_board(uint64_t board_id) {
  const WambleQueryService *qs = get_query_service();
  if (!qs || !qs->get_board)
    return query_board_error();
  return qs->get_board(board_id);
}

DbMovesResult wamble_query_get_moves_for_board(uint64_t board_id) {
  const WambleQueryService *qs = get_query_service();
  if (!qs || !qs->get_moves_for_board)
    return query_moves_error();
  return qs->get_moves_for_board(board_id);
}

DbPredictionsResult wamble_query_get_pending_predictions(void) {
  const WambleQueryService *qs = get_query_service();
  if (!qs || !qs->get_pending_predictions)
    return query_predictions_error();
  return qs->get_pending_predictions();
}

DbStatus wamble_query_get_longest_game_moves(int *out_max_moves) {
  const WambleQueryService *qs = get_query_service();
  if (!qs || !qs->get_longest_game_moves)
    return DB_ERR_EXEC;
  return qs->get_longest_game_moves(out_max_moves);
}

DbStatus wamble_query_get_active_session_count(int *out_count) {
  const WambleQueryService *qs = get_query_service();
  if (!qs || !qs->get_active_session_count)
    return DB_ERR_EXEC;
  return qs->get_active_session_count(out_count);
}

DbStatus wamble_query_get_max_board_id(uint64_t *out_max_id) {
  const WambleQueryService *qs = get_query_service();
  if (!qs || !qs->get_max_board_id)
    return DB_ERR_EXEC;
  return qs->get_max_board_id(out_max_id);
}

DbStatus wamble_query_get_session_by_token(const uint8_t *token,
                                           uint64_t *out_session) {
  const WambleQueryService *qs = get_query_service();
  if (!qs || !qs->get_session_by_token)
    return DB_ERR_EXEC;
  return qs->get_session_by_token(token, out_session);
}

DbStatus wamble_query_create_session(const uint8_t *token, uint64_t player_id,
                                     uint64_t *out_session) {
  if (out_session)
    *out_session = 0;
  const WambleQueryService *qs = get_query_service();
  if (!qs || !qs->create_session)
    return DB_ERR_EXEC;
  uint64_t sid = qs->create_session(token, player_id);
  if (sid == 0)
    return DB_ERR_EXEC;
  if (out_session)
    *out_session = sid;
  return DB_OK;
}

DbStatus wamble_query_create_prediction(uint64_t board_id, uint64_t session_id,
                                        uint64_t parent_prediction_id,
                                        const char *predicted_move_uci,
                                        int move_number, int correct_streak,
                                        uint64_t *out_prediction_id) {
  const WambleQueryService *qs = get_query_service();
  if (!qs || !qs->create_prediction)
    return DB_ERR_EXEC;
  return qs->create_prediction(board_id, session_id, parent_prediction_id,
                               predicted_move_uci, move_number, correct_streak,
                               out_prediction_id);
}

DbStatus wamble_query_get_persistent_session_by_token(const uint8_t *token,
                                                      uint64_t *out_session) {
  const WambleQueryService *qs = get_query_service();
  if (!qs || !qs->get_persistent_session_by_token)
    return DB_ERR_EXEC;
  return qs->get_persistent_session_by_token(token, out_session);
}

DbStatus wamble_query_get_player_total_score(uint64_t session_id,
                                             double *out_total) {
  const WambleQueryService *qs = get_query_service();
  if (!qs || !qs->get_player_total_score)
    return DB_ERR_EXEC;
  return qs->get_player_total_score(session_id, out_total);
}

DbStatus wamble_query_get_player_prediction_score(uint64_t session_id,
                                                  double *out_total) {
  const WambleQueryService *qs = get_query_service();
  if (!qs || !qs->get_player_prediction_score)
    return DB_ERR_EXEC;
  return qs->get_player_prediction_score(session_id, out_total);
}

DbStatus wamble_query_get_player_rating(uint64_t session_id,
                                        double *out_rating) {
  const WambleQueryService *qs = get_query_service();
  if (!qs || !qs->get_player_rating)
    return DB_ERR_EXEC;
  return qs->get_player_rating(session_id, out_rating);
}

DbStatus wamble_query_get_session_games_played(uint64_t session_id,
                                               int *out_games) {
  const WambleQueryService *qs = get_query_service();
  if (!qs || !qs->get_session_games_played)
    return DB_ERR_EXEC;
  return qs->get_session_games_played(session_id, out_games);
}

DbStatus wamble_query_get_session_chess960_games_played(uint64_t session_id,
                                                        int *out_games) {
  const WambleQueryService *qs = get_query_service();
  if (!qs || !qs->get_session_chess960_games_played)
    return DB_ERR_EXEC;
  return qs->get_session_chess960_games_played(session_id, out_games);
}

DbStatus wamble_query_get_persistent_player_stats(
    const uint8_t *public_key, WamblePersistentPlayerStats *out_stats) {
  const WambleQueryService *qs = get_query_service();
  if (!qs || !qs->get_persistent_player_stats)
    return DB_ERR_EXEC;
  return qs->get_persistent_player_stats(public_key, out_stats);
}

DbLeaderboardResult wamble_query_get_leaderboard(uint64_t requester_session_id,
                                                 uint8_t leaderboard_type,
                                                 int limit) {
  const WambleQueryService *qs = get_query_service();
  if (!qs || !qs->get_leaderboard)
    return query_leaderboard_error();
  return qs->get_leaderboard(requester_session_id, leaderboard_type, limit);
}

DbStatus
wamble_query_get_session_treatment_assignment(const uint8_t *token,
                                              WambleTreatmentAssignment *out) {
  const WambleQueryService *qs = get_query_service();
  if (!qs || !qs->get_session_treatment_assignment)
    return DB_ERR_EXEC;
  return qs->get_session_treatment_assignment(token, out);
}

DbStatus wamble_query_resolve_policy_decision(
    const uint8_t *token, const char *profile, const char *action,
    const char *resource, const char *context_key, const char *context_value,
    WamblePolicyDecision *out) {
  const WambleQueryService *qs = get_query_service();
  if (!qs || !qs->resolve_policy_decision)
    return DB_ERR_EXEC;
  return qs->resolve_policy_decision(token, profile, action, resource,
                                     context_key, context_value, out);
}

DbStatus wamble_query_resolve_treatment_actions(
    const uint8_t *token, const char *profile, const char *hook_name,
    const char *opponent_group_key, const WambleFact *facts, int fact_count,
    WambleTreatmentAction *out, int max_out, int *out_count) {
  const WambleQueryService *qs = get_query_service();
  if (!qs || !qs->resolve_treatment_actions)
    return DB_ERR_EXEC;
  return qs->resolve_treatment_actions(token, profile, hook_name,
                                       opponent_group_key, facts, fact_count,
                                       out, max_out, out_count);
}

int wamble_query_treatment_edge_allows(const char *profile,
                                       const char *source_group_key,
                                       const char *target_group_key) {
  const WambleQueryService *qs = get_query_service();
  if (!qs || !qs->treatment_edge_allows)
    return 0;
  return qs->treatment_edge_allows(profile, source_group_key, target_group_key);
}

uint64_t db_create_session(const uint8_t *token, uint64_t player_id) {
  if (!token)
    return 0;
  if (db_ensure_profile_treatment_schema() != 0)
    return 0;

  uint64_t existing_session_id = 0;
  if (db_get_session_by_token(token, &existing_session_id) == DB_OK &&
      existing_session_id > 0) {
    return existing_session_id;
  }

  const char *query = "INSERT INTO sessions (token, player_id, "
                      "global_identity_id, config_revision_id, "
                      "policy_snapshot_revision_id, "
                      "treatment_group_key, treatment_rule_id, "
                      "treatment_snapshot_revision_id, treatment_assigned_at) "
                      "VALUES (decode($1, 'hex'), $2, $3, $4, $5, "
                      "        NULL, NULL, NULL, NULL) "
                      "RETURNING id";

  char token_hex[33];
  bytes_to_hex(token, TOKEN_LENGTH, token_hex);
  uint64_t global_identity_id = 0;
  if (player_id > 0) {
    uint8_t public_key[32];
    if (db_get_player_public_key_by_id(player_id, public_key) != 0)
      return 0;
    global_identity_id =
        db_global_identity_resolve_or_create_pubkey(public_key);
  } else {
    global_identity_id = db_global_identity_create_anonymous();
  }
  if (global_identity_id == 0)
    return 0;
  const char *profile_key = wamble_runtime_profile_key();
  uint64_t active_revision_id = 0;
  if (db_get_active_revision_id(profile_key, &active_revision_id) != 0)
    active_revision_id = 0;
  char player_id_str[32];
  if (player_id > 0)
    snprintf(player_id_str, sizeof(player_id_str), "%" PRIu64, player_id);
  char identity_id_str[32];
  snprintf(identity_id_str, sizeof(identity_id_str), "%" PRIu64,
           global_identity_id);
  char revision_id_str[32];
  const char *revision_param = NULL;
  if (active_revision_id > 0) {
    snprintf(revision_id_str, sizeof(revision_id_str), "%" PRIu64,
             active_revision_id);
    revision_param = revision_id_str;
  }
  const char *paramValues[] = {token_hex, player_id > 0 ? player_id_str : NULL,
                               identity_id_str, revision_param, revision_param};

  PGresult *res =
      pq_exec_params_locked(query, 5, NULL, paramValues, NULL, NULL, 0);

  if (!res)
    return 0;
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    if (db_get_session_by_token(token, &existing_session_id) == DB_OK &&
        existing_session_id > 0) {
      return existing_session_id;
    }
    return 0;
  }

  uint64_t session_id = strtoull(PQgetvalue(res, 0, 0), NULL, 10);
  PQclear(res);
  if (token) {
    uint64_t now_ms = wamble_now_mono_millis();
    token_cache_u64_store(tls_session_cache, TOKEN_READ_CACHE_CAP,
                          &tls_session_cache_next, token, DB_OK, session_id,
                          now_ms);
    token_cache_u64_store(tls_persistent_session_cache, TOKEN_READ_CACHE_CAP,
                          &tls_persistent_session_cache_next, token,
                          player_id > 0 ? DB_OK : DB_NOT_FOUND,
                          player_id > 0 ? session_id : 0, now_ms);
  }
  return session_id;
}

static DbStatus db_get_session_by_token(const uint8_t *token,
                                        uint64_t *out_session) {
  if (!out_session || !token)
    return DB_ERR_BAD_DATA;
  uint64_t now_ms = wamble_now_mono_millis();
  DbStatus cached_status = DB_ERR_EXEC;
  uint64_t cached_value = 0;
  if (token_cache_u64_lookup(tls_session_cache, TOKEN_READ_CACHE_CAP, token,
                             now_ms, &cached_status, &cached_value)) {
    if (cached_status == DB_OK)
      *out_session = cached_value;
    return cached_status;
  }
  const char *query = "SELECT id FROM sessions WHERE token = decode($1, 'hex')";

  char token_hex[33];
  bytes_to_hex(token, TOKEN_LENGTH, token_hex);

  const char *paramValues[] = {token_hex};

  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);

  if (!res) {
    token_cache_u64_store(tls_session_cache, TOKEN_READ_CACHE_CAP,
                          &tls_session_cache_next, token, DB_ERR_CONN, 0,
                          now_ms);
    return DB_ERR_CONN;
  }
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    token_cache_u64_store(tls_session_cache, TOKEN_READ_CACHE_CAP,
                          &tls_session_cache_next, token, DB_ERR_EXEC, 0,
                          now_ms);
    return DB_ERR_EXEC;
  }
  if (PQntuples(res) == 0) {
    PQclear(res);
    token_cache_u64_store(tls_session_cache, TOKEN_READ_CACHE_CAP,
                          &tls_session_cache_next, token, DB_NOT_FOUND, 0,
                          now_ms);
    return DB_NOT_FOUND;
  }

  char *endptr = NULL;
  uint64_t session_id = strtoull(PQgetvalue(res, 0, 0), &endptr, 10);
  if (!endptr || *endptr != '\0') {
    PQclear(res);
    token_cache_u64_store(tls_session_cache, TOKEN_READ_CACHE_CAP,
                          &tls_session_cache_next, token, DB_ERR_BAD_DATA, 0,
                          now_ms);
    return DB_ERR_BAD_DATA;
  }
  *out_session = session_id;
  PQclear(res);
  token_cache_u64_store(tls_session_cache, TOKEN_READ_CACHE_CAP,
                        &tls_session_cache_next, token, DB_OK, session_id,
                        now_ms);
  return DB_OK;
}

static DbStatus db_get_persistent_session_by_token(const uint8_t *token,
                                                   uint64_t *out_session) {
  if (!out_session || !token)
    return DB_ERR_BAD_DATA;
  uint64_t now_ms = wamble_now_mono_millis();
  DbStatus cached_status = DB_ERR_EXEC;
  uint64_t cached_value = 0;
  if (token_cache_u64_lookup(tls_persistent_session_cache, TOKEN_READ_CACHE_CAP,
                             token, now_ms, &cached_status, &cached_value)) {
    if (cached_status == DB_OK)
      *out_session = cached_value;
    return cached_status;
  }
  const char *query =
      "SELECT id FROM sessions WHERE token = decode($1, 'hex') AND "
      "player_id IS NOT NULL";

  char token_hex[33];
  bytes_to_hex(token, TOKEN_LENGTH, token_hex);

  const char *paramValues[] = {token_hex};

  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);

  if (!res) {
    token_cache_u64_store(tls_persistent_session_cache, TOKEN_READ_CACHE_CAP,
                          &tls_persistent_session_cache_next, token,
                          DB_ERR_CONN, 0, now_ms);
    return DB_ERR_CONN;
  }
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    token_cache_u64_store(tls_persistent_session_cache, TOKEN_READ_CACHE_CAP,
                          &tls_persistent_session_cache_next, token,
                          DB_ERR_EXEC, 0, now_ms);
    return DB_ERR_EXEC;
  }
  if (PQntuples(res) == 0) {
    PQclear(res);
    token_cache_u64_store(tls_persistent_session_cache, TOKEN_READ_CACHE_CAP,
                          &tls_persistent_session_cache_next, token,
                          DB_NOT_FOUND, 0, now_ms);
    return DB_NOT_FOUND;
  }

  char *endptr = NULL;
  uint64_t session_id = strtoull(PQgetvalue(res, 0, 0), &endptr, 10);
  if (!endptr || *endptr != '\0') {
    PQclear(res);
    token_cache_u64_store(tls_persistent_session_cache, TOKEN_READ_CACHE_CAP,
                          &tls_persistent_session_cache_next, token,
                          DB_ERR_BAD_DATA, 0, now_ms);
    return DB_ERR_BAD_DATA;
  }
  *out_session = session_id;
  PQclear(res);
  token_cache_u64_store(tls_persistent_session_cache, TOKEN_READ_CACHE_CAP,
                        &tls_persistent_session_cache_next, token, DB_OK,
                        session_id, now_ms);
  return DB_OK;
}

void db_async_update_session_last_seen(uint64_t session_id) {
  const char *query = "UPDATE sessions SET last_seen_at = NOW() WHERE id = $1";

  char session_id_str[32];
  snprintf(session_id_str, sizeof(session_id_str), "%" PRIu64, session_id);

  const char *paramValues[] = {session_id_str};

  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);
  if (!res)
    return;
  PQclear(res);
}

uint64_t db_create_board(const char *fen) {
  const char *query =
      "INSERT INTO boards (fen, status) VALUES ($1, 'DORMANT') RETURNING id";

  const char *paramValues[] = {fen};

  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);

  if (!res)
    return 0;
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    return 0;
  }

  uint64_t board_id = strtoull(PQgetvalue(res, 0, 0), NULL, 10);
  PQclear(res);
  return board_id;
}

static DbStatus db_get_max_board_id(uint64_t *out_max_id) {
  if (!out_max_id)
    return DB_ERR_BAD_DATA;
  const char *query = "SELECT MAX(id) FROM boards";
  PGresult *res = pq_exec_locked(query);
  if (!res)
    return DB_ERR_CONN;
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    return DB_ERR_EXEC;
  }
  if (PQntuples(res) == 0 || PQgetisnull(res, 0, 0)) {
    PQclear(res);
    return DB_NOT_FOUND;
  }
  char *endptr = NULL;
  uint64_t max_id = strtoull(PQgetvalue(res, 0, 0), &endptr, 10);
  if (!endptr || *endptr != '\0') {
    PQclear(res);
    return DB_ERR_BAD_DATA;
  }
  *out_max_id = max_id;
  PQclear(res);
  return DB_OK;
}

int db_insert_board(uint64_t board_id, const char *fen, const char *status) {
  if (board_id == 0 || !fen || !status)
    return -1;
  char board_id_str[32];
  snprintf(board_id_str, sizeof(board_id_str), "%" PRIu64, (uint64_t)board_id);
  const char *paramValues[] = {board_id_str, fen, status};
  const char *query =
      "INSERT INTO boards (id, fen, status) "
      "VALUES ($1, $2, $3) ON CONFLICT (id) DO UPDATE SET fen = "
      "EXCLUDED.fen, status = EXCLUDED.status";

  PGresult *res =
      pq_exec_params_locked(query, 3, NULL, paramValues, NULL, NULL, 0);
  if (!res)
    return -1;
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    PQclear(res);
    return -1;
  }
  PQclear(res);

  const char *seq_query =
      "SELECT setval('boards_id_seq', GREATEST($1, (SELECT last_value "
      "FROM boards_id_seq)), true)";
  const char *seq_params[] = {board_id_str};
  PGresult *seq_res =
      pq_exec_params_locked(seq_query, 1, NULL, seq_params, NULL, NULL, 0);
  if (seq_res)
    PQclear(seq_res);
  return 0;
}

int db_insert_board_mode_variant(uint64_t board_id, int mode_variant_id) {
  if (board_id == 0)
    return -1;
  char board_id_str[32];
  char mode_variant_id_str[16];
  snprintf(board_id_str, sizeof(board_id_str), "%" PRIu64, board_id);
  snprintf(mode_variant_id_str, sizeof(mode_variant_id_str), "%d",
           mode_variant_id);
  const char *paramValues[] = {board_id_str, mode_variant_id_str};
  const char *query =
      "INSERT INTO board_mode_variants (board_id, game_mode, mode_variant_id) "
      "VALUES ($1, 'chess960', $2) ON CONFLICT (board_id) DO UPDATE SET "
      "game_mode = EXCLUDED.game_mode, mode_variant_id = "
      "EXCLUDED.mode_variant_id";
  PGresult *res =
      pq_exec_params_locked(query, 2, NULL, paramValues, NULL, NULL, 0);
  if (!res)
    return -1;
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    PQclear(res);
    return -1;
  }
  PQclear(res);
  return 0;
}

int db_async_update_board(uint64_t board_id, const char *fen,
                          const char *status) {
  const char *query = "UPDATE boards SET fen = $2, status = $3, updated_at = "
                      "NOW() WHERE id = $1";

  char board_id_str[32];
  snprintf(board_id_str, sizeof(board_id_str), "%" PRIu64, board_id);

  const char *paramValues[] = {board_id_str, fen, status};

  PGresult *res =
      pq_exec_params_locked(query, 3, NULL, paramValues, NULL, NULL, 0);

  if (!res)
    return -1;
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    PQclear(res);
    return -1;
  }

  PQclear(res);
  return 0;
}

int db_async_update_board_assignment_time(uint64_t board_id) {
  const char *query =
      "UPDATE boards SET last_assignment_time = NOW() WHERE id = $1";

  char board_id_str[32];
  snprintf(board_id_str, sizeof(board_id_str), "%" PRIu64, board_id);

  const char *paramValues[] = {board_id_str};

  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);

  if (!res)
    return -1;
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    PQclear(res);
    return -1;
  }

  PQclear(res);
  return 0;
}

int db_async_update_board_move_meta(uint64_t board_id,
                                    const char *last_mover_treatment_group) {
  const char *query = "UPDATE boards SET last_move_time = NOW(), "
                      "last_mover_treatment_group = $2 "
                      "WHERE id = $1";

  char board_id_str[32];
  snprintf(board_id_str, sizeof(board_id_str), "%" PRIu64, board_id);

  const char *paramValues[] = {board_id_str, last_mover_treatment_group};

  PGresult *res =
      pq_exec_params_locked(query, 2, NULL, paramValues, NULL, NULL, 0);

  if (!res)
    return -1;
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    PQclear(res);
    return -1;
  }

  PQclear(res);
  return 0;
}

int db_async_update_board_reservation_meta(uint64_t board_id,
                                           time_t reservation_time,
                                           int reserved_for_white) {
  const char *query =
      "UPDATE boards SET reservation_started_at = CASE WHEN $2::bigint > 0 "
      "THEN to_timestamp($2::bigint) ELSE NULL END, "
      "reserved_for_white = $3 WHERE id = $1";

  char board_id_str[32];
  char reservation_time_str[32];
  char reserved_str[2];
  snprintf(board_id_str, sizeof(board_id_str), "%" PRIu64, board_id);
  snprintf(reservation_time_str, sizeof(reservation_time_str), "%lld",
           (long long)reservation_time);
  reserved_str[0] = reserved_for_white ? 't' : 'f';
  reserved_str[1] = '\0';

  const char *paramValues[] = {board_id_str, reservation_time_str,
                               reserved_str};

  PGresult *res =
      pq_exec_params_locked(query, 3, NULL, paramValues, NULL, NULL, 0);

  if (!res)
    return -1;
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    PQclear(res);
    return -1;
  }

  PQclear(res);
  return 0;
}

static DbBoardResult db_get_board(uint64_t board_id) {
  DbBoardResult out = {0};
  out.status = DB_NOT_FOUND;
  out.reserved_for_white = false;
  const char *query =
      "SELECT b.fen, b.status, "
      "COALESCE(EXTRACT(EPOCH FROM b.created_at)::bigint, 0), "
      "COALESCE(EXTRACT(EPOCH FROM b.last_assignment_time)::bigint, 0), "
      "COALESCE(EXTRACT(EPOCH FROM b.last_move_time)::bigint, 0), "
      "COALESCE(b.last_mover_treatment_group, ''), "
      "COALESCE(EXTRACT(EPOCH FROM r.started_at)::bigint, "
      "COALESCE(EXTRACT(EPOCH FROM b.reservation_started_at)::bigint, 0)), "
      "COALESCE(r.reserved_for_white, COALESCE(b.reserved_for_white, FALSE)), "
      "COALESCE(bmv.mode_variant_id, -1) "
      "FROM boards b "
      "LEFT JOIN reservations r ON r.board_id = b.id "
      "LEFT JOIN board_mode_variants bmv ON bmv.board_id = b.id "
      "WHERE b.id = $1";

  char board_id_str[32];
  snprintf(board_id_str, sizeof(board_id_str), "%" PRIu64, board_id);

  const char *paramValues[] = {board_id_str};

  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);
  if (!res) {
    out.status = DB_ERR_CONN;
    return out;
  }
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    out.status = DB_ERR_EXEC;
    PQclear(res);
    return out;
  }
  if (PQntuples(res) == 0) {
    out.status = DB_NOT_FOUND;
    PQclear(res);
    return out;
  }

  snprintf(out.fen, FEN_MAX_LENGTH, "%s", PQgetvalue(res, 0, 0));
  strncpy(out.status_text, PQgetvalue(res, 0, 1), STATUS_MAX_LENGTH - 1);
  out.status_text[STATUS_MAX_LENGTH - 1] = '\0';
  out.created_at = (time_t)strtoull(PQgetvalue(res, 0, 2), NULL, 10);
  out.last_assignment_time = (time_t)strtoull(PQgetvalue(res, 0, 3), NULL, 10);
  out.last_move_time = (time_t)strtoull(PQgetvalue(res, 0, 4), NULL, 10);
  snprintf(out.last_mover_treatment_group,
           sizeof(out.last_mover_treatment_group), "%s", PQgetvalue(res, 0, 5));
  out.reservation_time = (time_t)strtoull(PQgetvalue(res, 0, 6), NULL, 10);
  out.reserved_for_white =
      (PQgetvalue(res, 0, 7)[0] == 't' || PQgetvalue(res, 0, 7)[0] == '1');
  out.mode_variant_id = (int)strtol(PQgetvalue(res, 0, 8), NULL, 10);
  out.status = DB_OK;
  PQclear(res);
  return out;
}

static DbBoardIdList db_list_boards_by_status(const char *status) {
  DbBoardIdList out = {0};
  out.status = DB_ERR_EXEC;
  const char *query =
      "SELECT id FROM boards WHERE status = $1 ORDER BY created_at";
  const char *paramValues[] = {status};
  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);
  if (!res) {
    out.status = DB_ERR_CONN;
    return out;
  }
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    out.status = DB_ERR_EXEC;
    PQclear(res);
    return out;
  }
  int count = PQntuples(res);
  if (count <= 0) {
    out.status = DB_OK;
    out.ids = NULL;
    out.count = 0;
    PQclear(res);
    return out;
  }
  if (tls_ids_cap < count) {
    uint64_t *newbuf =
        (uint64_t *)realloc(tls_ids, (size_t)count * sizeof(uint64_t));
    if (!newbuf) {
      out.status = DB_ERR_EXEC;
      PQclear(res);
      return out;
    }
    tls_ids = newbuf;
    tls_ids_cap = count;
  }
  out.count = count;
  for (int i = 0; i < count; i++) {
    tls_ids[i] = strtoull(PQgetvalue(res, i, 0), NULL, 10);
  }
  out.ids = tls_ids;
  out.status = DB_OK;
  PQclear(res);
  return out;
}

int db_async_record_move(uint64_t board_id, uint64_t session_id,
                         const char *move_uci, int move_number) {
  const char *query = "INSERT INTO moves (board_id, session_id, move_uci, "
                      "move_number) VALUES ($1, $2, $3, $4)";

  char board_id_str[32];
  char session_id_str[32];
  char move_number_str[16];

  snprintf(board_id_str, sizeof(board_id_str), "%" PRIu64, board_id);
  snprintf(session_id_str, sizeof(session_id_str), "%" PRIu64, session_id);
  snprintf(move_number_str, sizeof(move_number_str), "%d", move_number);

  const char *paramValues[] = {board_id_str, session_id_str, move_uci,
                               move_number_str};

  PGresult *res =
      pq_exec_params_locked(query, 4, NULL, paramValues, NULL, NULL, 0);

  if (!res)
    return -1;
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    PQclear(res);
    return -1;
  }

  PQclear(res);
  return 0;
}

DbStatus db_create_prediction(uint64_t board_id, uint64_t session_id,
                              uint64_t parent_prediction_id,
                              const char *predicted_move_uci, int move_number,
                              int correct_streak, uint64_t *out_prediction_id) {
  const char *query =
      "INSERT INTO predictions (board_id, session_id, predicted_move_uci, "
      "move_number, parent_prediction_id, correct_streak, status) "
      "VALUES ($1, $2, $3, $4, NULLIF($5, '0')::bigint, $6, 'PENDING') "
      "RETURNING id";

  char board_id_str[32];
  char session_id_str[32];
  char move_number_str[16];
  char parent_id_str[32];
  char correct_streak_str[16];

  snprintf(board_id_str, sizeof(board_id_str), "%" PRIu64, board_id);
  snprintf(session_id_str, sizeof(session_id_str), "%" PRIu64, session_id);
  snprintf(move_number_str, sizeof(move_number_str), "%d", move_number);
  snprintf(parent_id_str, sizeof(parent_id_str), "%" PRIu64,
           parent_prediction_id);
  snprintf(correct_streak_str, sizeof(correct_streak_str), "%d",
           correct_streak);

  const char *paramValues[] = {board_id_str,       session_id_str,
                               predicted_move_uci, move_number_str,
                               parent_id_str,      correct_streak_str};
  PGresult *res =
      pq_exec_params_locked(query, 6, NULL, paramValues, NULL, NULL, 0);

  if (!res)
    return DB_ERR_EXEC;
  if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
    PQclear(res);
    return DB_ERR_EXEC;
  }

  if (out_prediction_id)
    *out_prediction_id = strtoull(PQgetvalue(res, 0, 0), NULL, 10);
  PQclear(res);
  return DB_OK;
}

int db_async_create_prediction(uint64_t board_id, uint64_t session_id,
                               uint64_t parent_prediction_id,
                               const char *predicted_move_uci, int move_number,
                               int correct_streak) {
  uint64_t prediction_id = 0;
  DbStatus st = db_create_prediction(board_id, session_id, parent_prediction_id,
                                     predicted_move_uci, move_number,
                                     correct_streak, &prediction_id);
  return st == DB_OK ? 0 : -1;
}

int db_async_resolve_prediction(uint64_t board_id, uint64_t session_id,
                                int move_number, const char *status,
                                double points_awarded) {
  const char *query =
      "WITH upd AS ("
      "  UPDATE predictions "
      "  SET status = $4, points_awarded = $5, resolved_at = NOW() "
      "  WHERE board_id = $1 AND session_id = $2 AND move_number = $3 "
      "    AND status = 'PENDING' "
      "  RETURNING session_id, points_awarded"
      ") "
      "UPDATE sessions s "
      "SET total_prediction_score = s.total_prediction_score + "
      "upd.points_awarded "
      "FROM upd WHERE s.id = upd.session_id";

  char board_id_str[32];
  char session_id_str[32];
  char move_number_str[16];
  char points_str[32];

  snprintf(board_id_str, sizeof(board_id_str), "%" PRIu64, board_id);
  snprintf(session_id_str, sizeof(session_id_str), "%" PRIu64, session_id);
  snprintf(move_number_str, sizeof(move_number_str), "%d", move_number);
  snprintf(points_str, sizeof(points_str), "%.4f", points_awarded);

  const char *paramValues[] = {board_id_str, session_id_str, move_number_str,
                               status, points_str};
  PGresult *res =
      pq_exec_params_locked(query, 5, NULL, paramValues, NULL, NULL, 0);

  if (!res)
    return -1;
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    PQclear(res);
    return -1;
  }

  PQclear(res);
  return 0;
}

DbPredictionsResult db_get_pending_predictions(void) {
  DbPredictionsResult out = {0};
  out.status = DB_OK;
  out.rows = NULL;
  out.count = 0;

  const char *query =
      "WITH RECURSIVE active_tree AS ("
      "  SELECT p.id, p.parent_prediction_id "
      "  FROM predictions p "
      "  WHERE p.status = 'PENDING' "
      "  UNION "
      "  SELECT parent.id, parent.parent_prediction_id "
      "  FROM predictions parent "
      "  JOIN active_tree child ON child.parent_prediction_id = parent.id"
      "), "
      "prediction_depths AS ("
      "  SELECT p.id, p.parent_prediction_id, 0 AS depth "
      "  FROM predictions p "
      "  WHERE p.parent_prediction_id IS NULL "
      "  UNION ALL "
      "  SELECT child.id, child.parent_prediction_id, parent.depth + 1 "
      "  FROM predictions child "
      "  JOIN prediction_depths parent ON child.parent_prediction_id = "
      "parent.id"
      ") "
      "SELECT p.id, p.board_id, COALESCE(p.parent_prediction_id, 0), "
      "encode(s.token, 'hex'), p.predicted_move_uci, p.status, p.move_number, "
      "COALESCE(d.depth, 0), COALESCE(p.correct_streak, 0), p.points_awarded, "
      "EXTRACT(EPOCH FROM p.created_at)::bigint "
      "FROM predictions p "
      "JOIN active_tree a ON a.id = p.id "
      "JOIN sessions s ON s.id = p.session_id "
      "LEFT JOIN prediction_depths d ON d.id = p.id "
      "ORDER BY p.created_at ASC, p.id ASC";

  PGresult *res = pq_exec_params_locked(query, 0, NULL, NULL, NULL, NULL, 0);
  if (!res)
    return query_predictions_error();
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    return query_predictions_error();
  }

  int count = PQntuples(res);
  if (count <= 0) {
    PQclear(res);
    return out;
  }

  if (count > tls_predictions_cap) {
    DbPredictionRow *rows = (DbPredictionRow *)realloc(
        tls_predictions, (size_t)count * sizeof(*tls_predictions));
    if (!rows) {
      PQclear(res);
      return query_predictions_error();
    }
    tls_predictions = rows;
    tls_predictions_cap = count;
  }

  for (int i = 0; i < count; i++) {
    memset(&tls_predictions[i], 0, sizeof(tls_predictions[i]));
    tls_predictions[i].id = strtoull(PQgetvalue(res, i, 0), NULL, 10);
    tls_predictions[i].board_id = strtoull(PQgetvalue(res, i, 1), NULL, 10);
    tls_predictions[i].parent_prediction_id =
        strtoull(PQgetvalue(res, i, 2), NULL, 10);
    hex_to_bytes(PQgetvalue(res, i, 3), tls_predictions[i].player_token,
                 TOKEN_LENGTH);
    strncpy(tls_predictions[i].predicted_move_uci, PQgetvalue(res, i, 4),
            MAX_UCI_LENGTH - 1);
    strncpy(tls_predictions[i].status, PQgetvalue(res, i, 5),
            STATUS_MAX_LENGTH - 1);
    tls_predictions[i].move_number =
        (int)strtol(PQgetvalue(res, i, 6), NULL, 10);
    tls_predictions[i].depth = (int)strtol(PQgetvalue(res, i, 7), NULL, 10);
    tls_predictions[i].correct_streak =
        (int)strtol(PQgetvalue(res, i, 8), NULL, 10);
    tls_predictions[i].points_awarded = strtod(PQgetvalue(res, i, 9), NULL);
    tls_predictions[i].created_at =
        (time_t)strtoull(PQgetvalue(res, i, 10), NULL, 10);
  }

  PQclear(res);
  out.rows = tls_predictions;
  out.count = count;
  return out;
}

static DbMovesResult db_get_moves_for_board(uint64_t board_id) {
  DbMovesResult out = {0};
  out.status = DB_ERR_EXEC;
  const char *query =
      "SELECT m.id, m.board_id, encode(s.token, 'hex'), m.move_uci, "
      "EXTRACT(EPOCH FROM m.timestamp)::bigint, m.move_number "
      "FROM moves m "
      "JOIN sessions s ON m.session_id = s.id "
      "WHERE m.board_id = $1 "
      "ORDER BY m.move_number";

  char board_id_str[32];
  snprintf(board_id_str, sizeof(board_id_str), "%" PRIu64, board_id);

  const char *paramValues[] = {board_id_str};

  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);
  if (!res) {
    out.status = DB_ERR_CONN;
    return out;
  }
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    out.status = DB_ERR_EXEC;
    PQclear(res);
    return out;
  }
  int count = PQntuples(res);
  if (count <= 0) {
    out.status = DB_OK;
    out.rows = NULL;
    out.count = 0;
    PQclear(res);
    return out;
  }
  if (tls_moves_cap < count) {
    WambleMove *newbuf =
        (WambleMove *)realloc(tls_moves, (size_t)count * sizeof(WambleMove));
    if (!newbuf) {
      out.status = DB_ERR_EXEC;
      PQclear(res);
      return out;
    }
    tls_moves = newbuf;
    tls_moves_cap = count;
  }
  out.count = count;
  for (int i = 0; i < count; i++) {
    tls_moves[i].id = strtoull(PQgetvalue(res, i, 0), NULL, 10);
    tls_moves[i].board_id = strtoull(PQgetvalue(res, i, 1), NULL, 10);

    const char *token_hex = PQgetvalue(res, i, 2);
    hex_to_bytes(token_hex, tls_moves[i].player_token, TOKEN_LENGTH);
    strncpy(tls_moves[i].uci_move, PQgetvalue(res, i, 3), MAX_UCI_LENGTH - 1);
    tls_moves[i].uci_move[MAX_UCI_LENGTH - 1] = '\0';
    tls_moves[i].timestamp = (time_t)strtoull(PQgetvalue(res, i, 4), NULL, 10);

    char *endptr;
    long move_number = strtol(PQgetvalue(res, i, 5), &endptr, 10);
    if (*endptr != '\0' || move_number < 0) {
      out.rows = NULL;
      out.count = 0;
      out.status = DB_ERR_BAD_DATA;
      PQclear(res);
      return out;
    }
    tls_moves[i].is_white_move = (move_number % 2 == 1);
  }
  out.rows = tls_moves;
  out.status = DB_OK;
  PQclear(res);
  return out;
}

int db_async_create_reservation(uint64_t board_id, uint64_t session_id,
                                int timeout_seconds, int reserved_for_white) {
  const char *query =
      "INSERT INTO reservations (board_id, session_id, expires_at, started_at, "
      "reserved_for_white) "
      "VALUES ($1, $2, NOW() + $3 * INTERVAL '1 second', NOW(), $4) "
      "ON CONFLICT (board_id) DO UPDATE SET "
      "session_id = $2, expires_at = NOW() + $3 * INTERVAL '1 second', "
      "started_at = NOW(), reserved_for_white = $4";

  char board_id_str[32];
  char session_id_str[32];
  char timeout_str[16];
  char reserved_str[2];

  snprintf(board_id_str, sizeof(board_id_str), "%" PRIu64, board_id);
  snprintf(session_id_str, sizeof(session_id_str), "%" PRIu64, session_id);
  snprintf(timeout_str, sizeof(timeout_str), "%d", timeout_seconds);
  reserved_str[0] = reserved_for_white ? 't' : 'f';
  reserved_str[1] = '\0';

  const char *paramValues[] = {board_id_str, session_id_str, timeout_str,
                               reserved_str};

  PGresult *res =
      pq_exec_params_locked(query, 4, NULL, paramValues, NULL, NULL, 0);

  if (!res)
    return -1;
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    PQclear(res);
    return -1;
  }

  PQclear(res);
  return 0;
}

void db_expire_reservations(void) {
  const char *update_query =
      "UPDATE boards SET status = 'DORMANT', updated_at = NOW(), "
      "reservation_started_at = NULL, reserved_for_white = FALSE "
      "WHERE status = 'RESERVED' AND id IN "
      "(SELECT board_id FROM reservations WHERE expires_at <= NOW())";
  PGresult *res_update = pq_exec_locked(update_query);
  if (res_update)
    PQclear(res_update);

  const char *delete_query =
      "DELETE FROM reservations WHERE expires_at <= NOW()";
  PGresult *res_delete = pq_exec_locked(delete_query);
  if (res_delete)
    PQclear(res_delete);
}

void db_archive_inactive_boards(int timeout_seconds) {
  const char *query =
      "UPDATE boards SET status = 'DORMANT', updated_at = NOW() "
      "WHERE status = 'ACTIVE' AND updated_at <= NOW() - $1 * INTERVAL '1 "
      "second'";

  char timeout_str[16];
  snprintf(timeout_str, sizeof(timeout_str), "%d", timeout_seconds);
  const char *paramValues[] = {timeout_str};

  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);
  if (res)
    PQclear(res);
}
void db_async_remove_reservation(uint64_t board_id) {
  const char *query = "DELETE FROM reservations WHERE board_id = $1";

  char board_id_str[32];
  snprintf(board_id_str, sizeof(board_id_str), "%" PRIu64, board_id);

  const char *paramValues[] = {board_id_str};

  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);
  if (res)
    PQclear(res);

  const char *clear_query =
      "UPDATE boards SET reservation_started_at = NULL, reserved_for_white = "
      "FALSE WHERE id = $1";
  PGresult *res_clear =
      pq_exec_params_locked(clear_query, 1, NULL, paramValues, NULL, NULL, 0);
  if (res_clear)
    PQclear(res_clear);
}

int db_async_record_game_result(uint64_t board_id, char winning_side,
                                int move_count, int duration_seconds,
                                const char *termination_reason) {
  const char *query = "INSERT INTO game_results "
                      "(board_id, winning_side, move_count, duration_seconds, "
                      "termination_reason) VALUES ($1, $2, $3, $4, $5) "
                      "ON CONFLICT (board_id) DO UPDATE SET "
                      "winning_side = EXCLUDED.winning_side, "
                      "move_count = EXCLUDED.move_count, "
                      "duration_seconds = EXCLUDED.duration_seconds, "
                      "termination_reason = EXCLUDED.termination_reason";

  char board_id_str[32];
  char winning_side_str[2];
  char move_count_str[16];
  char duration_str[16];

  snprintf(board_id_str, sizeof(board_id_str), "%" PRIu64, board_id);
  winning_side_str[0] = winning_side;
  winning_side_str[1] = '\0';
  snprintf(move_count_str, sizeof(move_count_str), "%d", move_count);
  snprintf(duration_str, sizeof(duration_str), "%d", duration_seconds);

  const char *paramValues[] = {board_id_str, winning_side_str, move_count_str,
                               duration_str,
                               termination_reason ? termination_reason : ""};

  PGresult *res =
      pq_exec_params_locked(query, 5, NULL, paramValues, NULL, NULL, 0);

  if (!res)
    return -1;
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    PQclear(res);
    return -1;
  }

  PQclear(res);
  return 0;
}

int db_async_record_payout(uint64_t board_id, uint64_t session_id,
                           double points) {
  const char *query = "INSERT INTO payouts (board_id, session_id, "
                      "points_awarded) VALUES ($1, $2, $3)";

  char board_id_str[32];
  char session_id_str[32];
  char points_str[32];

  snprintf(board_id_str, sizeof(board_id_str), "%" PRIu64, board_id);
  snprintf(session_id_str, sizeof(session_id_str), "%" PRIu64, session_id);
  snprintf(points_str, sizeof(points_str), "%.4f", points);

  const char *paramValues[] = {board_id_str, session_id_str, points_str};

  PGresult *res =
      pq_exec_params_locked(query, 3, NULL, paramValues, NULL, NULL, 0);

  if (!res)
    return -1;
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    PQclear(res);
    return -1;
  }

  PQclear(res);
  return 0;
}

static DbStatus db_get_player_total_score(uint64_t session_id,
                                          double *out_total) {
  if (!out_total)
    return DB_ERR_BAD_DATA;
  const char *query = "SELECT COALESCE(total_score, 0) FROM sessions "
                      "WHERE id = $1";

  char session_id_str[32];
  snprintf(session_id_str, sizeof(session_id_str), "%" PRIu64, session_id);

  const char *paramValues[] = {session_id_str};

  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);

  if (!res)
    return DB_ERR_CONN;
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    return DB_ERR_EXEC;
  }
  if (PQntuples(res) == 0) {
    PQclear(res);
    return DB_NOT_FOUND;
  }

  char *endptr;
  double total = strtod(PQgetvalue(res, 0, 0), &endptr);
  if (*endptr != '\0') {
    PQclear(res);
    return DB_ERR_BAD_DATA;
  }
  PQclear(res);
  *out_total = total;
  return DB_OK;
}

static DbStatus db_get_player_prediction_score(uint64_t session_id,
                                               double *out_total) {
  if (!out_total)
    return DB_ERR_BAD_DATA;
  const char *query =
      "SELECT COALESCE(total_prediction_score, 0) FROM sessions "
      "WHERE id = $1";

  char session_id_str[32];
  snprintf(session_id_str, sizeof(session_id_str), "%" PRIu64, session_id);

  const char *paramValues[] = {session_id_str};
  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);

  if (!res)
    return DB_ERR_CONN;
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    return DB_ERR_EXEC;
  }
  if (PQntuples(res) == 0) {
    PQclear(res);
    return DB_NOT_FOUND;
  }

  char *endptr;
  double total = strtod(PQgetvalue(res, 0, 0), &endptr);
  if (*endptr != '\0') {
    PQclear(res);
    return DB_ERR_BAD_DATA;
  }
  PQclear(res);
  *out_total = total;
  return DB_OK;
}

static DbStatus db_get_player_rating(uint64_t session_id, double *out_rating) {
  if (!out_rating)
    return DB_ERR_BAD_DATA;
  const char *query = "SELECT COALESCE(p.rating, 0) FROM players p "
                      "JOIN sessions s ON s.player_id = p.id WHERE s.id = $1";

  char session_id_str[32];
  snprintf(session_id_str, sizeof(session_id_str), "%" PRIu64, session_id);

  const char *paramValues[] = {session_id_str};

  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);

  if (!res) {
    return DB_ERR_CONN;
  }
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    return DB_ERR_EXEC;
  }
  if (PQntuples(res) == 0) {
    PQclear(res);
    return DB_NOT_FOUND;
  }

  char *endptr;
  double rating = strtod(PQgetvalue(res, 0, 0), &endptr);
  if (*endptr != '\0') {
    PQclear(res);
    return DB_ERR_BAD_DATA;
  }
  PQclear(res);
  *out_rating = rating;
  return DB_OK;
}

int db_async_update_player_rating(uint64_t session_id, double rating) {
  const char *query = "UPDATE players SET rating = $2 WHERE id = (SELECT "
                      "player_id FROM sessions WHERE id = $1)";

  char session_id_str[32];
  char rating_str[32];
  snprintf(session_id_str, sizeof(session_id_str), "%" PRIu64, session_id);
  snprintf(rating_str, sizeof(rating_str), "%.4f", rating);

  const char *paramValues[] = {session_id_str, rating_str};

  PGresult *res =
      pq_exec_params_locked(query, 2, NULL, paramValues, NULL, NULL, 0);
  if (!res || PQresultStatus(res) != PGRES_COMMAND_OK) {
    if (res)
      PQclear(res);
    return -1;
  }
  PQclear(res);
  return 0;
}

static DbStatus db_get_active_session_count(int *out_count) {
  if (!out_count)
    return DB_ERR_BAD_DATA;
  const char *query = "SELECT COUNT(*) FROM sessions WHERE last_seen_at > "
                      "NOW() - INTERVAL '5 minutes'";

  PGresult *res = pq_exec_locked(query);

  if (!res)
    return DB_ERR_CONN;
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    return DB_ERR_EXEC;
  }

  char *endptr;
  long count = strtol(PQgetvalue(res, 0, 0), &endptr, 10);
  if (*endptr != '\0' || count < 0) {
    PQclear(res);
    return DB_ERR_BAD_DATA;
  }
  PQclear(res);
  *out_count = (int)count;
  return DB_OK;
}

static DbStatus db_get_longest_game_moves(int *out_max_moves) {
  if (!out_max_moves)
    return DB_ERR_BAD_DATA;
  const char *query = "SELECT COALESCE(MAX(move_number), 0) FROM moves m "
                      "JOIN boards b ON m.board_id = b.id "
                      "WHERE b.status IN ('ACTIVE', 'RESERVED', 'DORMANT')";

  PGresult *res = pq_exec_locked(query);

  if (!res)
    return DB_ERR_CONN;
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    return DB_ERR_EXEC;
  }

  char *endptr;
  long max_moves = strtol(PQgetvalue(res, 0, 0), &endptr, 10);
  if (*endptr != '\0' || max_moves < 0) {
    PQclear(res);
    return DB_ERR_BAD_DATA;
  }
  PQclear(res);
  *out_max_moves = (int)max_moves;
  return DB_OK;
}

static DbStatus db_get_session_games_played(uint64_t session_id,
                                            int *out_games) {
  if (!out_games)
    return DB_ERR_BAD_DATA;
  const char *query = "SELECT COALESCE(games_played, 0) FROM sessions "
                      "WHERE id = $1";

  char session_id_str[32];
  snprintf(session_id_str, sizeof(session_id_str), "%" PRIu64, session_id);

  const char *paramValues[] = {session_id_str};

  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);

  if (!res)
    return DB_ERR_CONN;
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    return DB_ERR_EXEC;
  }
  if (PQntuples(res) == 0) {
    PQclear(res);
    return DB_NOT_FOUND;
  }

  char *endptr;
  long games_played = strtol(PQgetvalue(res, 0, 0), &endptr, 10);
  if (*endptr != '\0' || games_played < 0) {
    PQclear(res);
    return DB_ERR_BAD_DATA;
  }
  PQclear(res);
  *out_games = (int)games_played;
  return DB_OK;
}

static DbStatus db_get_session_chess960_games_played(uint64_t session_id,
                                                     int *out_games) {
  if (!out_games)
    return DB_ERR_BAD_DATA;
  const char *query =
      "SELECT COUNT(DISTINCT m.board_id) "
      "FROM moves m "
      "JOIN board_mode_variants bmv ON bmv.board_id = m.board_id "
      "WHERE m.session_id = $1";

  char session_id_str[32];
  snprintf(session_id_str, sizeof(session_id_str), "%" PRIu64, session_id);

  const char *paramValues[] = {session_id_str};

  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);

  if (!res)
    return DB_ERR_CONN;
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    return DB_ERR_EXEC;
  }

  char *endptr;
  long chess960_games_played = strtol(PQgetvalue(res, 0, 0), &endptr, 10);
  if (*endptr != '\0' || chess960_games_played < 0) {
    PQclear(res);
    return DB_ERR_BAD_DATA;
  }
  PQclear(res);
  *out_games = (int)chess960_games_played;
  return DB_OK;
}

static DbStatus
db_get_persistent_player_stats(const uint8_t *public_key,
                               WamblePersistentPlayerStats *out_stats) {
  if (!public_key || !out_stats)
    return DB_ERR_BAD_DATA;

  const char *query =
      "SELECT COALESCE(SUM(s.total_score), 0), "
      "COALESCE(SUM(s.total_prediction_score), 0), "
      "COALESCE(p.rating, 0), "
      "COALESCE(SUM(s.games_played), 0), "
      "(SELECT COUNT(DISTINCT m.board_id) "
      " FROM sessions s2 "
      " JOIN moves m ON m.session_id = s2.id "
      " JOIN board_mode_variants bmv ON bmv.board_id = m.board_id "
      " WHERE s2.player_id = p.id) "
      "FROM players p "
      "LEFT JOIN sessions s ON s.player_id = p.id "
      "WHERE p.public_key = decode($1, 'hex') "
      "GROUP BY p.id, p.rating";

  char public_key_hex[65];
  bytes_to_hex(public_key, 32, public_key_hex);
  const char *paramValues[] = {public_key_hex};

  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);
  if (!res)
    return DB_ERR_CONN;
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    return DB_ERR_EXEC;
  }
  if (PQntuples(res) == 0) {
    PQclear(res);
    return DB_NOT_FOUND;
  }

  char *endptr = NULL;
  out_stats->score = strtod(PQgetvalue(res, 0, 0), &endptr);
  if (!endptr || *endptr != '\0') {
    PQclear(res);
    return DB_ERR_BAD_DATA;
  }
  out_stats->prediction_score = strtod(PQgetvalue(res, 0, 1), &endptr);
  if (!endptr || *endptr != '\0') {
    PQclear(res);
    return DB_ERR_BAD_DATA;
  }
  out_stats->rating = strtod(PQgetvalue(res, 0, 2), &endptr);
  if (!endptr || *endptr != '\0') {
    PQclear(res);
    return DB_ERR_BAD_DATA;
  }
  long games_played = strtol(PQgetvalue(res, 0, 3), &endptr, 10);
  if (!endptr || *endptr != '\0' || games_played < 0) {
    PQclear(res);
    return DB_ERR_BAD_DATA;
  }
  long chess960_games_played = strtol(PQgetvalue(res, 0, 4), &endptr, 10);
  if (!endptr || *endptr != '\0' || chess960_games_played < 0) {
    PQclear(res);
    return DB_ERR_BAD_DATA;
  }
  PQclear(res);

  out_stats->games_played = (int)games_played;
  out_stats->chess960_games_played = (int)chess960_games_played;
  return DB_OK;
}

DbLeaderboardResult db_get_leaderboard(uint64_t requester_session_id,
                                       uint8_t leaderboard_type, int limit) {
  static WAMBLE_THREAD_LOCAL DbLeaderboardEntry
      rows[WAMBLE_MAX_LEADERBOARD_ENTRIES];
  DbLeaderboardResult out = {0};
  out.status = DB_ERR_EXEC;
  out.rows = rows;
  out.count = 0;
  out.self_rank = 0;

  int effective_limit = limit;
  if (effective_limit <= 0)
    effective_limit = 10;
  if (effective_limit > WAMBLE_MAX_LEADERBOARD_ENTRIES)
    effective_limit = WAMBLE_MAX_LEADERBOARD_ENTRIES;

  uint8_t effective_type = leaderboard_type;
  if (effective_type != WAMBLE_LEADERBOARD_RATING)
    effective_type = WAMBLE_LEADERBOARD_SCORE;

  char limit_str[16];
  snprintf(limit_str, sizeof(limit_str), "%d", effective_limit);
  const char *top_query = NULL;
  const char *rank_query = NULL;
  if (effective_type == WAMBLE_LEADERBOARD_RATING) {
    top_query =
        "SELECT s.id, s.total_score, COALESCE(p.rating, 0), s.games_played "
        "FROM sessions s "
        "LEFT JOIN players p ON p.id = s.player_id "
        "ORDER BY COALESCE(p.rating, 0) DESC, s.total_score DESC, s.id ASC "
        "LIMIT $1";
    rank_query =
        "SELECT rank_pos FROM ("
        "  SELECT s.id, ROW_NUMBER() OVER ("
        "    ORDER BY COALESCE(p.rating, 0) DESC, s.total_score DESC, s.id ASC"
        "  ) AS rank_pos "
        "  FROM sessions s "
        "  LEFT JOIN players p ON p.id = s.player_id"
        ") ranked WHERE id = $1";
  } else {
    top_query =
        "SELECT s.id, s.total_score, COALESCE(p.rating, 0), s.games_played "
        "FROM sessions s "
        "LEFT JOIN players p ON p.id = s.player_id "
        "ORDER BY s.total_score DESC, COALESCE(p.rating, 0) DESC, s.id ASC "
        "LIMIT $1";
    rank_query =
        "SELECT rank_pos FROM ("
        "  SELECT s.id, ROW_NUMBER() OVER ("
        "    ORDER BY s.total_score DESC, COALESCE(p.rating, 0) DESC, s.id ASC"
        "  ) AS rank_pos "
        "  FROM sessions s "
        "  LEFT JOIN players p ON p.id = s.player_id"
        ") ranked WHERE id = $1";
  }
  const char *top_params[] = {limit_str};
  PGresult *res =
      pq_exec_params_locked(top_query, 1, NULL, top_params, NULL, NULL, 0);
  if (!res) {
    out.status = DB_ERR_CONN;
    return out;
  }
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    out.status = DB_ERR_EXEC;
    return out;
  }

  int n = PQntuples(res);
  if (n > WAMBLE_MAX_LEADERBOARD_ENTRIES)
    n = WAMBLE_MAX_LEADERBOARD_ENTRIES;
  for (int i = 0; i < n; i++) {
    rows[i].rank = (uint32_t)(i + 1);
    rows[i].session_id = strtoull(PQgetvalue(res, i, 0), NULL, 10);
    rows[i].score = strtod(PQgetvalue(res, i, 1), NULL);
    rows[i].rating = strtod(PQgetvalue(res, i, 2), NULL);
    rows[i].games_played = (uint32_t)strtoul(PQgetvalue(res, i, 3), NULL, 10);
  }
  out.count = n;
  PQclear(res);

  if (requester_session_id > 0) {
    char sid_str[32];
    snprintf(sid_str, sizeof(sid_str), "%" PRIu64, requester_session_id);
    const char *rank_params[] = {sid_str};
    PGresult *rank_res =
        pq_exec_params_locked(rank_query, 1, NULL, rank_params, NULL, NULL, 0);
    if (!rank_res) {
      out.status = DB_ERR_CONN;
      return out;
    }
    if (PQresultStatus(rank_res) != PGRES_TUPLES_OK) {
      PQclear(rank_res);
      out.status = DB_ERR_EXEC;
      return out;
    }
    if (PQntuples(rank_res) > 0) {
      out.self_rank = (uint32_t)strtoul(PQgetvalue(rank_res, 0, 0), NULL, 10);
    }
    PQclear(rank_res);
  }

  out.status = DB_OK;
  return out;
}

void db_tick(void) { db_expire_reservations(); }

static uint64_t db_create_player(const uint8_t *public_key) {
  const char *query =
      "INSERT INTO players (public_key, rating) VALUES (decode($1, 'hex'), $2) "
      "RETURNING id";

  char public_key_hex[65];
  char rating_str[32];
  bytes_to_hex(public_key, 32, public_key_hex);
  snprintf(rating_str, sizeof(rating_str), "%d",
           get_config() ? get_config()->default_rating : 1200);

  const char *paramValues[] = {public_key_hex, rating_str};

  PGresult *res =
      pq_exec_params_locked(query, 2, NULL, paramValues, NULL, NULL, 0);

  if (!res)
    return 0;
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    return 0;
  }

  uint64_t player_id = strtoull(PQgetvalue(res, 0, 0), NULL, 10);
  PQclear(res);
  return player_id;
}

static uint64_t db_get_player_by_public_key(const uint8_t *public_key) {
  const char *query =
      "SELECT id FROM players WHERE public_key = decode($1, 'hex')";

  char public_key_hex[65];
  bytes_to_hex(public_key, 32, public_key_hex);

  const char *paramValues[] = {public_key_hex};

  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);

  if (!res)
    return 0;
  if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
    PQclear(res);
    return 0;
  }

  uint64_t player_id = strtoull(PQgetvalue(res, 0, 0), NULL, 10);
  PQclear(res);
  return player_id;
}

static int db_async_link_session_to_pubkey(uint64_t session_id,
                                           const uint8_t *public_key) {
  const char *query = "UPDATE sessions SET player_id = $2, global_identity_id "
                      "= $3 WHERE id = $1";
  if (!public_key)
    return -1;
  uint64_t player_id = db_get_player_by_public_key(public_key);
  if (player_id == 0)
    player_id = db_create_player(public_key);
  if (player_id == 0)
    return -1;

  uint64_t global_identity_id =
      db_global_identity_resolve_or_create_pubkey(public_key);
  if (global_identity_id == 0)
    return -1;

  char session_id_str[32];
  char player_id_str[32];
  char identity_id_str[32];
  snprintf(session_id_str, sizeof(session_id_str), "%" PRIu64, session_id);
  snprintf(player_id_str, sizeof(player_id_str), "%" PRIu64, player_id);
  snprintf(identity_id_str, sizeof(identity_id_str), "%" PRIu64,
           global_identity_id);

  const char *paramValues[] = {session_id_str, player_id_str, identity_id_str};

  PGresult *res =
      pq_exec_params_locked(query, 3, NULL, paramValues, NULL, NULL, 0);

  if (!res)
    return -1;
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    PQclear(res);
    return -1;
  }

  PQclear(res);
  memset(tls_persistent_session_cache, 0, sizeof(tls_persistent_session_cache));
  tls_persistent_session_cache_next = 0;
  return 0;
}

static int db_async_unlink_session_identity(uint64_t session_id) {
  const char *query =
      "UPDATE sessions "
      "SET player_id = NULL, global_identity_id = $2, "
      "    treatment_group_key = NULL, treatment_rule_id = NULL, "
      "    treatment_snapshot_revision_id = NULL, treatment_assigned_at = NULL "
      "WHERE id = $1";

  uint64_t global_identity_id = db_global_identity_create_anonymous();
  if (global_identity_id == 0)
    return -1;

  char session_id_str[32];
  char identity_id_str[32];
  snprintf(session_id_str, sizeof(session_id_str), "%" PRIu64, session_id);
  snprintf(identity_id_str, sizeof(identity_id_str), "%" PRIu64,
           global_identity_id);

  const char *paramValues[] = {session_id_str, identity_id_str};

  PGresult *res =
      pq_exec_params_locked(query, 2, NULL, paramValues, NULL, NULL, 0);

  if (!res)
    return -1;
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    PQclear(res);
    return -1;
  }

  PQclear(res);
  memset(tls_persistent_session_cache, 0, sizeof(tls_persistent_session_cache));
  tls_persistent_session_cache_next = 0;
  return 0;
}
