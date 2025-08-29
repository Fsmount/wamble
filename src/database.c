#include "../include/wamble/wamble.h"
#include <libpq-fe.h>
#include <string.h>

static PGconn *db_conn = NULL;
static bool db_initialized = false;
static wamble_mutex_t db_conn_mutex;

static PGresult *pq_exec_locked(const char *command) {
  PGresult *res;
  wamble_mutex_lock(&db_conn_mutex);
  res = PQexec(db_conn, command);
  wamble_mutex_unlock(&db_conn_mutex);
  return res;
}

static PGresult *
pq_exec_params_locked(const char *command, int nParams, const Oid *paramTypes,
                      const char *const *paramValues, const int *paramLengths,
                      const int *paramFormats, int resultFormat) {
  PGresult *res;
  wamble_mutex_lock(&db_conn_mutex);
  res = PQexecParams(db_conn, command, nParams, paramTypes, paramValues,
                     paramLengths, paramFormats, resultFormat);
  wamble_mutex_unlock(&db_conn_mutex);
  return res;
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

#ifndef WAMBLE_SINGLE_THREADED
#define DB_QUEUE_CAP 1024
static DbJob db_queue[DB_QUEUE_CAP];
static int db_q_head = 0;
static int db_q_tail = 0;
static wamble_mutex_t db_q_mutex;
static wamble_cond_t db_q_cond;
static wamble_thread_t db_workers[2];
static int db_worker_running = 0;
static unsigned long db_q_dropped = 0;
static unsigned long db_job_failures[6] = {0};
static unsigned long db_job_success[6] = {0};

static int db_q_empty(void) { return db_q_head == db_q_tail; }
static int db_q_full(void) {
  return ((db_q_tail + 1) % DB_QUEUE_CAP) == db_q_head;
}

static void db_q_push(const DbJob *job) {
  wamble_mutex_lock(&db_q_mutex);
  if (!db_q_full()) {
    db_queue[db_q_tail] = *job;
    db_q_tail = (db_q_tail + 1) % DB_QUEUE_CAP;
    wamble_cond_signal(&db_q_cond);
  } else {
    db_q_dropped++;
    if ((db_q_dropped % get_config()->db_log_frequency) == 1UL) {
      LOG_WARN("db queue full, dropping jobs (total: %lu)", db_q_dropped);
    }
  }
  wamble_mutex_unlock(&db_q_mutex);
}

static int db_q_pop(DbJob *out) {
  wamble_mutex_lock(&db_q_mutex);
  while (db_worker_running && db_q_empty()) {
    wamble_cond_wait(&db_q_cond, &db_q_mutex);
  }
  if (!db_worker_running && db_q_empty()) {
    wamble_mutex_unlock(&db_q_mutex);
    return 0;
  }
  *out = db_queue[db_q_head];
  db_q_head = (db_q_head + 1) % DB_QUEUE_CAP;
  wamble_mutex_unlock(&db_q_mutex);
  return 1;
}

static void *db_worker_main(void *arg) {
  (void)arg;
  DbJob job;
  while (db_worker_running) {
    if (!db_q_pop(&job))
      continue;
    if (!db_conn)
      continue;
    switch (job.type) {
    case DB_JOB_UPDATE_BOARD:
      if (db_update_board(job.board_id, job.fen, job.status) == 0)
        db_job_success[DB_JOB_UPDATE_BOARD]++;
      else {
        db_job_failures[DB_JOB_UPDATE_BOARD]++;
        if ((db_job_failures[DB_JOB_UPDATE_BOARD] %
             get_config()->db_log_frequency) == 1UL)
          LOG_ERROR("db failure: update_board (total: %lu)",
                    db_job_failures[DB_JOB_UPDATE_BOARD]);
      }
      break;
    case DB_JOB_CREATE_RESERVATION:
      if (db_create_reservation(job.board_id, job.session_id,
                                job.timeout_seconds) == 0)
        db_job_success[DB_JOB_CREATE_RESERVATION]++;
      else {
        db_job_failures[DB_JOB_CREATE_RESERVATION]++;
        if ((db_job_failures[DB_JOB_CREATE_RESERVATION] %
             get_config()->db_log_frequency) == 1UL)
          LOG_ERROR("db failure: create_reservation (total: %lu)",
                    db_job_failures[DB_JOB_CREATE_RESERVATION]);
      }
      break;
    case DB_JOB_REMOVE_RESERVATION:
      db_remove_reservation(job.board_id);
      db_job_success[DB_JOB_REMOVE_RESERVATION]++;
      break;
    case DB_JOB_RECORD_GAME_RESULT:
      if (db_record_game_result(job.board_id, job.winning_side) == 0)
        db_job_success[DB_JOB_RECORD_GAME_RESULT]++;
      else {
        db_job_failures[DB_JOB_RECORD_GAME_RESULT]++;
        if ((db_job_failures[DB_JOB_RECORD_GAME_RESULT] %
             get_config()->db_log_frequency) == 1UL)
          LOG_ERROR("db failure: record_game_result (total: %lu)",
                    db_job_failures[DB_JOB_RECORD_GAME_RESULT]);
      }
      break;
    case DB_JOB_RECORD_MOVE:
      if (db_record_move(job.board_id, job.session_id, job.move_uci,
                         job.move_number) == 0)
        db_job_success[DB_JOB_RECORD_MOVE]++;
      else {
        db_job_failures[DB_JOB_RECORD_MOVE]++;
        if ((db_job_failures[DB_JOB_RECORD_MOVE] %
             get_config()->db_log_frequency) == 1UL)
          LOG_ERROR("db failure: record_move (total: %lu)",
                    db_job_failures[DB_JOB_RECORD_MOVE]);
      }
      break;
    case DB_JOB_RECORD_PAYOUT:
      if (db_record_payout(job.board_id, job.session_id, job.points) == 0)
        db_job_success[DB_JOB_RECORD_PAYOUT]++;
      else {
        db_job_failures[DB_JOB_RECORD_PAYOUT]++;
        if ((db_job_failures[DB_JOB_RECORD_PAYOUT] %
             get_config()->db_log_frequency) == 1UL)
          LOG_ERROR("db failure: record_payout (total: %lu)",
                    db_job_failures[DB_JOB_RECORD_PAYOUT]);
      }
      break;
    }
  }
  return NULL;
}
#endif

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
    LOG_WARN("Database already initialized");
    return 0;
  }

  LOG_INFO("Initializing database connection");
  wamble_mutex_init(&db_conn_mutex);
#ifndef WAMBLE_SINGLE_THREADED
  wamble_mutex_init(&db_q_mutex);
  wamble_cond_init(&db_q_cond);
#endif

  wamble_mutex_lock(&db_conn_mutex);
  db_conn = PQconnectdb(connection_string);
  if (PQstatus(db_conn) != CONNECTION_OK) {
    LOG_FATAL("failed to connect to db: %s", PQerrorMessage(db_conn));
    PQfinish(db_conn);
    db_conn = NULL;
    wamble_mutex_unlock(&db_conn_mutex);
    return -1;
  }
  wamble_mutex_unlock(&db_conn_mutex);

  db_initialized = true;

#ifndef WAMBLE_SINGLE_THREADED
  db_worker_running = 1;
  for (int i = 0; i < 2; i++) {
    wamble_thread_create(&db_workers[i], db_worker_main, NULL);
  }
  LOG_INFO("Database connection initialized and worker threads started");
#else
  LOG_INFO("Database connection initialized in single-threaded mode");
#endif
  return 0;
}

void db_cleanup(void) {
  LOG_INFO("Cleaning up database connection");
  if (db_conn) {
    wamble_mutex_lock(&db_conn_mutex);
    PQfinish(db_conn);
    db_conn = NULL;
    wamble_mutex_unlock(&db_conn_mutex);
  }
  db_initialized = false;
#ifndef WAMBLE_SINGLE_THREADED
  if (db_worker_running) {
    wamble_mutex_lock(&db_q_mutex);
    db_worker_running = 0;
    wamble_cond_broadcast(&db_q_cond);
    wamble_mutex_unlock(&db_q_mutex);
    for (int i = 0; i < 2; i++) {
      wamble_thread_join(db_workers[i], NULL);
    }
    LOG_INFO("Database worker threads stopped");
  }
#endif
  wamble_mutex_destroy(&db_conn_mutex);
#ifndef WAMBLE_SINGLE_THREADED
  wamble_mutex_destroy(&db_q_mutex);
  wamble_cond_destroy(&db_q_cond);
#endif
  LOG_INFO("Database cleanup complete");
}

void db_async_update_board(uint64_t board_id, const char *fen,
                           const char *status) {
#ifdef WAMBLE_SINGLE_THREADED
  db_update_board(board_id, fen, status);
#else
  DbJob j;
  j.type = DB_JOB_UPDATE_BOARD;
  j.board_id = board_id;
  strncpy(j.fen, fen ? fen : "", FEN_MAX_LENGTH - 1);
  j.fen[FEN_MAX_LENGTH - 1] = '\0';
  strncpy(j.status, status ? status : "", STATUS_MAX_LENGTH - 1);
  j.status[STATUS_MAX_LENGTH - 1] = '\0';
  db_q_push(&j);
#endif
}

void db_async_create_reservation(uint64_t board_id, uint64_t session_id,
                                 int timeout_seconds) {
#ifdef WAMBLE_SINGLE_THREADED
  db_create_reservation(board_id, session_id, timeout_seconds);
#else
  DbJob j;
  j.type = DB_JOB_CREATE_RESERVATION;
  j.board_id = board_id;
  j.session_id = session_id;
  j.timeout_seconds = timeout_seconds;
  db_q_push(&j);
#endif
}

void db_async_remove_reservation(uint64_t board_id) {
#ifdef WAMBLE_SINGLE_THREADED
  db_remove_reservation(board_id);
#else
  DbJob j;
  j.type = DB_JOB_REMOVE_RESERVATION;
  j.board_id = board_id;
  db_q_push(&j);
#endif
}

void db_async_record_game_result(uint64_t board_id, char winning_side) {
#ifdef WAMBLE_SINGLE_THREADED
  db_record_game_result(board_id, winning_side);
#else
  DbJob j;
  j.type = DB_JOB_RECORD_GAME_RESULT;
  j.board_id = board_id;
  j.winning_side = winning_side;
  db_q_push(&j);
#endif
}

void db_async_record_move(uint64_t board_id, uint64_t session_id,
                          const char *move_uci, int move_number) {
#ifdef WAMBLE_SINGLE_THREADED
  db_record_move(board_id, session_id, move_uci, move_number);
#else
  DbJob j;
  j.type = DB_JOB_RECORD_MOVE;
  j.board_id = board_id;
  j.session_id = session_id;
  j.move_number = move_number;
  if (move_uci) {
    strncpy(j.move_uci, move_uci, MAX_UCI_LENGTH - 1);
    j.move_uci[MAX_UCI_LENGTH - 1] = '\0';
  } else {
    j.move_uci[0] = '\0';
  }
  db_q_push(&j);
#endif
}

void db_async_record_payout(uint64_t board_id, uint64_t session_id,
                            double points) {
#ifdef WAMBLE_SINGLE_THREADED
  db_record_payout(board_id, session_id, points);
#else
  DbJob j;
  j.type = DB_JOB_RECORD_PAYOUT;
  j.board_id = board_id;
  j.session_id = session_id;
  j.points = points;
  db_q_push(&j);
#endif
}

uint64_t db_create_session(const uint8_t *token, uint64_t player_id) {
  const char *query = "INSERT INTO sessions (token, player_id) VALUES "
                      "(decode($1, 'hex'), $2) RETURNING id";

  char token_hex[33];
  bytes_to_hex(token, TOKEN_LENGTH, token_hex);

  char player_id_str[32];
  if (player_id > 0) {
    snprintf(player_id_str, sizeof(player_id_str), "%lu", player_id);
  }

  const char *paramValues[] = {token_hex, player_id > 0 ? player_id_str : NULL};

  if (!db_conn) {
    return 0;
  }

  PGresult *res =
      pq_exec_params_locked(query, 2, NULL, paramValues, NULL, NULL, 0);

  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    return 0;
  }

  uint64_t session_id = strtoull(PQgetvalue(res, 0, 0), NULL, 10);
  PQclear(res);
  return session_id;
}

uint64_t db_get_session_by_token(const uint8_t *token) {
  const char *query = "SELECT id FROM sessions WHERE token = decode($1, 'hex')";

  char token_hex[33];
  bytes_to_hex(token, TOKEN_LENGTH, token_hex);

  const char *paramValues[] = {token_hex};

  if (!db_conn) {
    return 0;
  }

  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);

  if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
    PQclear(res);
    return 0;
  }

  uint64_t session_id = strtoull(PQgetvalue(res, 0, 0), NULL, 10);
  PQclear(res);
  return session_id;
}

void db_update_session_last_seen(uint64_t session_id) {
  const char *query = "UPDATE sessions SET last_seen_at = NOW() WHERE id = $1";

  char session_id_str[32];
  snprintf(session_id_str, sizeof(session_id_str), "%lu", session_id);

  const char *paramValues[] = {session_id_str};

  if (!db_conn) {
    return;
  }

  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);
  PQclear(res);
}

uint64_t db_create_board(const char *fen) {
  const char *query =
      "INSERT INTO boards (fen, status) VALUES ($1, 'DORMANT') RETURNING id";

  const char *paramValues[] = {fen};

  if (!db_conn) {
    return 0;
  }

  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);

  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    return 0;
  }

  uint64_t board_id = strtoull(PQgetvalue(res, 0, 0), NULL, 10);
  PQclear(res);
  return board_id;
}

int db_update_board(uint64_t board_id, const char *fen, const char *status) {
  const char *query = "UPDATE boards SET fen = $2, status = $3, updated_at = "
                      "NOW() WHERE id = $1";

  char board_id_str[32];
  snprintf(board_id_str, sizeof(board_id_str), "%lu", board_id);

  const char *paramValues[] = {board_id_str, fen, status};

  if (!db_conn) {
    return -1;
  }

  PGresult *res =
      pq_exec_params_locked(query, 3, NULL, paramValues, NULL, NULL, 0);

  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    PQclear(res);
    return -1;
  }

  PQclear(res);
  return 0;
}

int db_get_board(uint64_t board_id, char *fen_out, char *status_out) {
  const char *query = "SELECT fen, status FROM boards WHERE id = $1";

  char board_id_str[32];
  snprintf(board_id_str, sizeof(board_id_str), "%lu", board_id);

  const char *paramValues[] = {board_id_str};

  if (!db_conn) {
    return -1;
  }

  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);

  if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
    PQclear(res);
    return -1;
  }

  snprintf(fen_out, FEN_MAX_LENGTH, "%s", PQgetvalue(res, 0, 0));
  strncpy(status_out, PQgetvalue(res, 0, 1), STATUS_MAX_LENGTH - 1);
  status_out[STATUS_MAX_LENGTH - 1] = '\0';

  PQclear(res);
  return 0;
}

int db_get_boards_by_status(const char *status, uint64_t *board_ids,
                            int max_boards) {
  const char *query =
      "SELECT id FROM boards WHERE status = $1 ORDER BY created_at";

  const char *paramValues[] = {status};

  if (!db_conn) {
    return -1;
  }

  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);

  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    return -1;
  }

  int count = PQntuples(res);
  if (count > max_boards) {
    count = max_boards;
  }

  for (int i = 0; i < count; i++) {
    board_ids[i] = strtoull(PQgetvalue(res, i, 0), NULL, 10);
  }

  PQclear(res);
  return count;
}

int db_record_move(uint64_t board_id, uint64_t session_id, const char *move_uci,
                   int move_number) {
  const char *query = "INSERT INTO moves (board_id, session_id, move_uci, "
                      "move_number) VALUES ($1, $2, $3, $4)";

  char board_id_str[32];
  char session_id_str[32];
  char move_number_str[16];

  snprintf(board_id_str, sizeof(board_id_str), "%lu", board_id);
  snprintf(session_id_str, sizeof(session_id_str), "%lu", session_id);
  snprintf(move_number_str, sizeof(move_number_str), "%d", move_number);

  const char *paramValues[] = {board_id_str, session_id_str, move_uci,
                               move_number_str};

  if (!db_conn) {
    return -1;
  }

  PGresult *res =
      pq_exec_params_locked(query, 4, NULL, paramValues, NULL, NULL, 0);

  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    PQclear(res);
    return -1;
  }

  PQclear(res);
  return 0;
}

int db_get_moves_for_board(uint64_t board_id, WambleMove *moves_out,
                           int max_moves) {
  const char *query =
      "SELECT m.id, m.board_id, encode(s.token, 'hex'), m.move_uci, "
      "EXTRACT(EPOCH FROM m.timestamp)::bigint, m.move_number "
      "FROM moves m "
      "JOIN sessions s ON m.session_id = s.id "
      "WHERE m.board_id = $1 "
      "ORDER BY m.move_number";

  char board_id_str[32];
  snprintf(board_id_str, sizeof(board_id_str), "%lu", board_id);

  const char *paramValues[] = {board_id_str};

  if (!db_conn) {
    return -1;
  }

  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);

  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    return -1;
  }

  int count = PQntuples(res);
  if (count == 0) {
    PQclear(res);
    return 0;
  }

  if (count > max_moves) {
    count = max_moves;
  }

  for (int i = 0; i < count; i++) {
    moves_out[i].id = strtoull(PQgetvalue(res, i, 0), NULL, 10);
    moves_out[i].board_id = strtoull(PQgetvalue(res, i, 1), NULL, 10);

    const char *token_hex = PQgetvalue(res, i, 2);
    hex_to_bytes(token_hex, moves_out[i].player_token, TOKEN_LENGTH);
    strncpy(moves_out[i].uci_move, PQgetvalue(res, i, 3), MAX_UCI_LENGTH - 1);
    moves_out[i].uci_move[MAX_UCI_LENGTH - 1] = '\0';
    moves_out[i].timestamp = strtoull(PQgetvalue(res, i, 4), NULL, 10);

    char *endptr;
    long move_number = strtol(PQgetvalue(res, i, 5), &endptr, 10);
    if (*endptr != '\0' || move_number < 0) {
      PQclear(res);
      return -1;
    }
    moves_out[i].is_white_move = (move_number % 2 == 1);
  }

  PQclear(res);
  return count;
}

int db_create_reservation(uint64_t board_id, uint64_t session_id,
                          int timeout_seconds) {
  const char *query =
      "INSERT INTO reservations (board_id, session_id, expires_at) "
      "VALUES ($1, $2, NOW() + $3 * INTERVAL '1 second') "
      "ON CONFLICT (board_id) DO UPDATE SET "
      "session_id = $2, expires_at = NOW() + $3 * INTERVAL '1 second'";

  char board_id_str[32];
  char session_id_str[32];
  char timeout_str[16];

  snprintf(board_id_str, sizeof(board_id_str), "%lu", board_id);
  snprintf(session_id_str, sizeof(session_id_str), "%lu", session_id);
  snprintf(timeout_str, sizeof(timeout_str), "%d", timeout_seconds);

  const char *paramValues[] = {board_id_str, session_id_str, timeout_str};

  if (!db_conn) {
    return -1;
  }

  PGresult *res =
      PQexecParams(db_conn, query, 3, NULL, paramValues, NULL, NULL, 0);

  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    PQclear(res);
    return -1;
  }

  PQclear(res);
  return 0;
}

void db_expire_reservations(void) {
  if (!db_conn) {
    return;
  }

  const char *update_query =
      "UPDATE boards SET status = 'DORMANT', updated_at = NOW() "
      "WHERE status = 'RESERVED' AND id IN "
      "(SELECT board_id FROM reservations WHERE expires_at <= NOW())";
  PGresult *res_update = pq_exec_locked(update_query);
  PQclear(res_update);

  const char *delete_query =
      "DELETE FROM reservations WHERE expires_at <= NOW()";
  PGresult *res_delete = pq_exec_locked(delete_query);
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

  if (!db_conn) {
    return;
  }

  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);
  PQclear(res);
}
void db_remove_reservation(uint64_t board_id) {
  const char *query = "DELETE FROM reservations WHERE board_id = $1";

  char board_id_str[32];
  snprintf(board_id_str, sizeof(board_id_str), "%lu", board_id);

  const char *paramValues[] = {board_id_str};

  if (!db_conn) {
    return;
  }

  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);
  PQclear(res);
}

int db_record_game_result(uint64_t board_id, char winning_side) {
  const char *query =
      "INSERT INTO game_results (board_id, winning_side) VALUES ($1, $2)";

  char board_id_str[32];
  char winning_side_str[2];

  snprintf(board_id_str, sizeof(board_id_str), "%lu", board_id);
  winning_side_str[0] = winning_side;
  winning_side_str[1] = '\0';

  const char *paramValues[] = {board_id_str, winning_side_str};

  if (!db_conn) {
    return -1;
  }

  PGresult *res =
      PQexecParams(db_conn, query, 2, NULL, paramValues, NULL, NULL, 0);

  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    PQclear(res);
    return -1;
  }

  PQclear(res);
  return 0;
}

int db_record_payout(uint64_t board_id, uint64_t session_id, double points) {
  const char *query = "INSERT INTO payouts (board_id, session_id, "
                      "points_awarded) VALUES ($1, $2, $3)";

  char board_id_str[32];
  char session_id_str[32];
  char points_str[32];

  snprintf(board_id_str, sizeof(board_id_str), "%lu", board_id);
  snprintf(session_id_str, sizeof(session_id_str), "%lu", session_id);
  snprintf(points_str, sizeof(points_str), "%.4f", points);

  const char *paramValues[] = {board_id_str, session_id_str, points_str};

  if (!db_conn) {
    return -1;
  }

  PGresult *res =
      PQexecParams(db_conn, query, 3, NULL, paramValues, NULL, NULL, 0);

  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    PQclear(res);
    return -1;
  }

  PQclear(res);
  return 0;
}

double db_get_player_total_score(uint64_t session_id) {
  const char *query = "SELECT COALESCE(SUM(points_awarded), 0) FROM payouts "
                      "WHERE session_id = $1";

  char session_id_str[32];
  snprintf(session_id_str, sizeof(session_id_str), "%lu", session_id);

  const char *paramValues[] = {session_id_str};

  if (!db_conn) {
    return 0.0;
  }

  PGresult *res =
      PQexecParams(db_conn, query, 1, NULL, paramValues, NULL, NULL, 0);

  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    return 0.0;
  }

  char *endptr;
  double total = strtod(PQgetvalue(res, 0, 0), &endptr);
  if (*endptr != '\0') {
    PQclear(res);
    return 0.0;
  }
  PQclear(res);
  return total;
}

int db_get_active_session_count(void) {
  const char *query = "SELECT COUNT(*) FROM sessions WHERE last_seen_at > "
                      "NOW() - INTERVAL '5 minutes'";

  if (!db_conn) {
    return 0;
  }

  PGresult *res = pq_exec_locked(query);

  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    return 0;
  }

  char *endptr;
  long count = strtol(PQgetvalue(res, 0, 0), &endptr, 10);
  if (*endptr != '\0' || count < 0) {
    PQclear(res);
    return 0;
  }
  PQclear(res);
  return (int)count;
}

int db_get_longest_game_moves(void) {
  const char *query = "SELECT COALESCE(MAX(move_number), 0) FROM moves m "
                      "JOIN boards b ON m.board_id = b.id "
                      "WHERE b.status IN ('ACTIVE', 'RESERVED', 'DORMANT')";

  if (!db_conn) {
    return 0;
  }

  PGresult *res = pq_exec_locked(query);

  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    return 0;
  }

  char *endptr;
  long max_moves = strtol(PQgetvalue(res, 0, 0), &endptr, 10);
  if (*endptr != '\0' || max_moves < 0) {
    PQclear(res);
    return 0;
  }
  PQclear(res);
  return (int)max_moves;
}

int db_get_session_games_played(uint64_t session_id) {
  const char *query =
      "SELECT COUNT(DISTINCT board_id) FROM moves WHERE session_id = $1";

  char session_id_str[32];
  snprintf(session_id_str, sizeof(session_id_str), "%lu", session_id);

  const char *paramValues[] = {session_id_str};

  if (!db_conn) {
    return 0;
  }

  PGresult *res =
      pq_exec_params_locked(query, 1, NULL, paramValues, NULL, NULL, 0);

  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    PQclear(res);
    return 0;
  }

  char *endptr;
  long games_played = strtol(PQgetvalue(res, 0, 0), &endptr, 10);
  if (*endptr != '\0' || games_played < 0) {
    PQclear(res);
    return 0;
  }
  PQclear(res);
  return (int)games_played;
}

void db_tick(void) { db_expire_reservations(); }
