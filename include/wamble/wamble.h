#ifndef WAMBLE_H
#define WAMBLE_H

#if defined(_WIN32)
#include <windows.h>
#elif defined(__unix__) || defined(__APPLE__)
#include <pthread.h>
#else
#define WAMBLE_SINGLE_THREADED
#endif

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define LOG_LEVEL_FATAL 0
#define LOG_LEVEL_ERROR 1
#define LOG_LEVEL_WARN 2
#define LOG_LEVEL_INFO 3
#define LOG_LEVEL_DEBUG 4

#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_LEVEL_INFO
#endif

static inline void wamble_log(int level, const char *file, int line,
                              const char *func, const char *level_str,
                              const char *format, ...) {
  (void)level;

  time_t now = time(NULL);
  char time_buf[21];
  strftime(time_buf, 21, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

  FILE *output_stream = (level <= LOG_LEVEL_WARN) ? stderr : stdout;
  fprintf(output_stream, "%s [%s] %s:%d:%s(): ", time_buf, level_str, file,
          line, func);

  va_list args;
  va_start(args, format);
  vfprintf(output_stream, format, args);
  va_end(args);

  fprintf(output_stream, "\n");
}

#define LOG_FATAL(format, ...)                                                 \
  do {                                                                         \
    wamble_log(LOG_LEVEL_FATAL, __FILE__, __LINE__, __func__, "FATAL", format, \
               ##__VA_ARGS__);                                                 \
    exit(1);                                                                   \
  } while (0)

#if LOG_LEVEL >= LOG_LEVEL_ERROR
#define LOG_ERROR(format, ...)                                                 \
  wamble_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "ERROR", format,   \
             ##__VA_ARGS__)
#else
#define LOG_ERROR(format, ...)                                                 \
  do {                                                                         \
  } while (0)
#endif

#if LOG_LEVEL >= LOG_LEVEL_WARN
#define LOG_WARN(format, ...)                                                  \
  wamble_log(LOG_LEVEL_WARN, __FILE__, __LINE__, __func__, "WARN", format,     \
             ##__VA_ARGS__)
#else
#define LOG_WARN(format, ...)                                                  \
  do {                                                                         \
  } while (0)
#endif

#if LOG_LEVEL >= LOG_LEVEL_INFO
#define LOG_INFO(format, ...)                                                  \
  wamble_log(LOG_LEVEL_INFO, __FILE__, __LINE__, __func__, "INFO", format,     \
             ##__VA_ARGS__)
#else
#define LOG_INFO(format, ...)                                                  \
  do {                                                                         \
  } while (0)
#endif

#if LOG_LEVEL >= LOG_LEVEL_DEBUG
#define LOG_DEBUG(format, ...)                                                 \
  wamble_log(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __func__, "DEBUG", format,   \
             ##__VA_ARGS__)
#else
#define LOG_DEBUG(format, ...)                                                 \
  do {                                                                         \
  } while (0)
#endif

#if defined(WAMBLE_SINGLE_THREADED)
typedef int wamble_thread_t;
typedef int wamble_mutex_t;
typedef int wamble_cond_t;
typedef void *(*wamble_thread_func_t)(void *);
static inline int wamble_thread_create(wamble_thread_t *thread,
                                       wamble_thread_func_t func, void *arg) {
  (void)thread;
  (void)func;
  (void)arg;
  return 0;
}
static inline int wamble_thread_join(wamble_thread_t thread, void **res) {
  (void)thread;
  (void)res;
  return 0;
}
static inline int wamble_thread_detach(wamble_thread_t thread) {
  (void)thread;
  return 0;
}
static inline int wamble_mutex_init(wamble_mutex_t *mutex) {
  (void)mutex;
  return 0;
}
static inline int wamble_mutex_destroy(wamble_mutex_t *mutex) {
  (void)mutex;
  return 0;
}
static inline int wamble_mutex_lock(wamble_mutex_t *mutex) {
  (void)mutex;
  return 0;
}
static inline int wamble_mutex_unlock(wamble_mutex_t *mutex) {
  (void)mutex;
  return 0;
}
static inline int wamble_cond_init(wamble_cond_t *cond) {
  (void)cond;
  return 0;
}
static inline int wamble_cond_destroy(wamble_cond_t *cond) {
  (void)cond;
  return 0;
}
static inline int wamble_cond_wait(wamble_cond_t *cond, wamble_mutex_t *mutex) {
  (void)cond;
  (void)mutex;
  return 0;
}
static inline int wamble_cond_signal(wamble_cond_t *cond) {
  (void)cond;
  return 0;
}
static inline int wamble_cond_broadcast(wamble_cond_t *cond) {
  (void)cond;
  return 0;
}
#elif defined(_WIN32)

typedef HANDLE wamble_thread_t;
typedef CRITICAL_SECTION wamble_mutex_t;
typedef CONDITION_VARIABLE wamble_cond_t;
typedef DWORD(WINAPI *wamble_thread_func_t)(void *);

static inline int wamble_thread_create(wamble_thread_t *thread,
                                       wamble_thread_func_t func, void *arg) {
  *thread = CreateThread(NULL, 0, func, arg, 0, NULL);
  return (*thread != NULL) ? 0 : -1;
}

static inline int wamble_thread_join(wamble_thread_t thread, void **res) {
  WaitForSingleObject(thread, INFINITE);
  if (res != NULL) {
    GetExitCodeThread(thread, (LPDWORD)res);
  }
  CloseHandle(thread);
  return 0;
}

static inline int wamble_thread_detach(wamble_thread_t thread) {
  return CloseHandle(thread) ? 0 : -1;
}

static inline int wamble_mutex_init(wamble_mutex_t *mutex) {
  InitializeCriticalSection(mutex);
  return 0;
}

static inline int wamble_mutex_destroy(wamble_mutex_t *mutex) {
  DeleteCriticalSection(mutex);
  return 0;
}

static inline int wamble_mutex_lock(wamble_mutex_t *mutex) {
  EnterCriticalSection(mutex);
  return 0;
}

static inline int wamble_mutex_unlock(wamble_mutex_t *mutex) {
  LeaveCriticalSection(mutex);
  return 0;
}

static inline int wamble_cond_init(wamble_cond_t *cond) {
  InitializeConditionVariable(cond);
  return 0;
}

static inline int wamble_cond_destroy(wamble_cond_t *cond) {
  (void)cond;
  return 0;
}

static inline int wamble_cond_wait(wamble_cond_t *cond, wamble_mutex_t *mutex) {
  return SleepConditionVariableCS(cond, mutex, INFINITE) ? 0 : -1;
}

static inline int wamble_cond_signal(wamble_cond_t *cond) {
  WakeConditionVariable(cond);
  return 0;
}

static inline int wamble_cond_broadcast(wamble_cond_t *cond) {
  WakeAllConditionVariable(cond);
  return 0;
}

#else
typedef pthread_t wamble_thread_t;
typedef pthread_mutex_t wamble_mutex_t;
typedef pthread_cond_t wamble_cond_t;
typedef void *(*wamble_thread_func_t)(void *);

static inline int wamble_thread_create(wamble_thread_t *thread,
                                       wamble_thread_func_t func, void *arg) {
  return pthread_create(thread, NULL, func, arg);
}

static inline int wamble_thread_join(wamble_thread_t thread, void **res) {
  return pthread_join(thread, res);
}

static inline int wamble_thread_detach(wamble_thread_t thread) {
  return pthread_detach(thread);
}

static inline int wamble_mutex_init(wamble_mutex_t *mutex) {
  return pthread_mutex_init(mutex, NULL);
}

static inline int wamble_mutex_destroy(wamble_mutex_t *mutex) {
  return pthread_mutex_destroy(mutex);
}

static inline int wamble_mutex_lock(wamble_mutex_t *mutex) {
  return pthread_mutex_lock(mutex);
}

static inline int wamble_mutex_unlock(wamble_mutex_t *mutex) {
  return pthread_mutex_unlock(mutex);
}

static inline int wamble_cond_init(wamble_cond_t *cond) {
  return pthread_cond_init(cond, NULL);
}

static inline int wamble_cond_destroy(wamble_cond_t *cond) {
  return pthread_cond_destroy(cond);
}

static inline int wamble_cond_wait(wamble_cond_t *cond, wamble_mutex_t *mutex) {
  return pthread_cond_wait(cond, mutex);
}

static inline int wamble_cond_signal(wamble_cond_t *cond) {
  return pthread_cond_signal(cond);
}

static inline int wamble_cond_broadcast(wamble_cond_t *cond) {
  return pthread_cond_broadcast(cond);
}
#endif

typedef struct {
  int port;
  int timeout_ms;
  int max_retries;
  int max_message_size;
  int buffer_size;
  int max_client_sessions;
  int session_timeout;
  int max_boards;
  int min_boards;
  int inactivity_timeout;
  int reservation_timeout;
  int k_factor;
  int default_rating;
  int max_players;
  int token_expiration;
  double max_pot;
  int max_moves_per_board;
  int max_contributors;
  char *db_host;
  char *db_user;
  char *db_pass;
  char *db_name;
  int select_timeout_usec;
  int cleanup_interval_sec;
  int max_token_attempts;
  int max_token_local_attempts;
  int db_log_frequency;
  double new_player_early_phase_mult;
  double new_player_mid_phase_mult;
  double new_player_end_phase_mult;
  double experienced_player_early_phase_mult;
  double experienced_player_mid_phase_mult;
  double experienced_player_end_phase_mult;
} WambleConfig;

void config_load(const char *filename, const char *profile);

#define FEN_MAX_LENGTH 90
#define MAX_UCI_LENGTH 6
#define TOKEN_LENGTH 16
#define STATUS_MAX_LENGTH 17

#define WAMBLE_CTRL_CLIENT_HELLO 0x01
#define WAMBLE_CTRL_SERVER_HELLO 0x02
#define WAMBLE_CTRL_PLAYER_MOVE 0x03
#define WAMBLE_CTRL_BOARD_UPDATE 0x04
#define WAMBLE_CTRL_ACK 0x05

#define get_bit(square) (1ULL << (square))
#define get_square(file, rank) ((rank) * 8 + (file))

#define KINGSIDE_CASTLE (1 << 0)
#define QUEENSIDE_CASTLE (1 << 1)

typedef unsigned long long Bitboard;

#define WHITE_PAWN 0
#define WHITE_KNIGHT 1
#define WHITE_BISHOP 2
#define WHITE_ROOK 3
#define WHITE_QUEEN 4
#define WHITE_KING 5
#define BLACK_PAWN 6
#define BLACK_KNIGHT 7
#define BLACK_BISHOP 8
#define BLACK_ROOK 9
#define BLACK_QUEEN 10
#define BLACK_KING 11

#define WHITE_KING_START 4
#define BLACK_KING_START 60

typedef struct {
  int from;
  int to;
  char promotion;
} Move;

typedef struct {
  int captured_piece_type;
  int captured_square;
  char prev_en_passant[3];
  char prev_castling[5];
  int prev_halfmove_clock;
  int prev_fullmove_number;
  int moving_piece_color;
} MoveInfo;

typedef struct {
  Bitboard pieces[12];
  Bitboard occupied[2];
  char turn;
  char castling[5];
  char en_passant[3];
  int halfmove_clock;
  int fullmove_number;
} Board;

typedef enum {
  BOARD_STATE_ACTIVE,
  BOARD_STATE_RESERVED,
  BOARD_STATE_DORMANT,
  BOARD_STATE_ARCHIVED
} BoardState;

typedef enum {
  GAME_RESULT_IN_PROGRESS,
  GAME_RESULT_WHITE_WINS,
  GAME_RESULT_BLACK_WINS,
  GAME_RESULT_DRAW
} GameResult;

#pragma pack(push, 1)
struct WambleMsg {
  uint8_t ctrl;
  uint8_t token[TOKEN_LENGTH];
  uint64_t board_id;
  uint32_t seq_num;
  uint8_t uci_len;
  char uci[MAX_UCI_LENGTH];
  char fen[FEN_MAX_LENGTH];
};
#pragma pack(pop)

int serialize_wamble_msg(const struct WambleMsg *msg, uint8_t *buffer);
int deserialize_wamble_msg(const uint8_t *buffer, size_t buffer_size,
                           struct WambleMsg *msg);

#define WAMBLE_SERIALIZED_SIZE                                                 \
  (1 + TOKEN_LENGTH + 8 + 4 + 1 + MAX_UCI_LENGTH + FEN_MAX_LENGTH)

typedef struct WamblePlayer {
  uint8_t token[TOKEN_LENGTH];
  uint8_t public_key[32];
  bool has_persistent_identity;
  time_t last_seen_time;
  double score;
  int games_played;
} WamblePlayer;

typedef struct WambleBoard {
  char fen[FEN_MAX_LENGTH];
  Board board;
  uint64_t id;
  BoardState state;
  GameResult result;
  time_t last_move_time;
  time_t creation_time;
  time_t last_assignment_time;
  uint8_t reservation_player_token[TOKEN_LENGTH];
  bool reserved_for_white;
  time_t reservation_time;
} WambleBoard;

typedef struct WambleClientSession {
  struct sockaddr_in addr;
  uint8_t token[TOKEN_LENGTH];
  uint32_t last_seq_num;
  time_t last_seen;
  uint32_t next_seq_num;
} WambleClientSession;

int validate_and_apply_move(WambleBoard *wamble_board, WamblePlayer *player,
                            const char *uci_move);

int parse_fen_to_bitboard(const char *fen, Board *board);
void bitboard_to_fen(const Board *board, char *fen);

MoveInfo make_move_bitboard(Board *board, const Move *move);
void unmake_move_bitboard(Board *board, const Move *move, const MoveInfo *info);

static inline int square_to_index(int file, int rank) {
  return rank * 8 + file;
}

static inline void index_to_square(int index, int *file, int *rank) {
  *file = index % 8;
  *rank = index / 8;
}

typedef enum { GAME_PHASE_EARLY, GAME_PHASE_MID, GAME_PHASE_END } GamePhase;

#define GAME_PHASE_EARLY_THRESHOLD 10
#define GAME_PHASE_MID_THRESHOLD 30

#define NEW_PLAYER_GAMES_THRESHOLD 10

typedef struct WambleMove {
  uint64_t id;
  uint64_t board_id;
  uint8_t player_token[TOKEN_LENGTH];
  char uci_move[MAX_UCI_LENGTH];
  time_t timestamp;
  bool is_white_move;
} WambleMove;

void board_manager_init(void);
void board_manager_tick(void);
WambleBoard *find_board_for_player(WamblePlayer *player);
void release_board(uint64_t board_id);
void archive_board(uint64_t board_id);
void update_player_ratings(WambleBoard *board);
int get_moves_for_board(uint64_t board_id, WambleMove **moves);
WambleBoard *get_board_by_id(uint64_t board_id);

WamblePlayer *get_player_by_id(uint64_t player_id);
int start_board_manager_thread(void);

void calculate_and_distribute_pot(uint64_t board_id);

void player_manager_init(void);
WamblePlayer *find_player_by_token(const uint8_t *token);
WamblePlayer *create_new_player(void);
void format_token_for_url(const uint8_t *token, char *url_buffer);
int decode_token_from_url(const char *url_string, uint8_t *token_buffer);
void player_manager_tick(void);

WamblePlayer *get_player_by_token(const uint8_t *token);

const WambleConfig *get_config(void);

void start_network_listener(void);
void send_response(const struct WambleMsg *msg);

int validate_message(const struct WambleMsg *msg, size_t received_size);
int is_duplicate_message(const struct sockaddr_in *addr, uint32_t seq_num);
void update_client_session(const struct sockaddr_in *addr, const uint8_t *token,
                           uint32_t seq_num);

void set_network_timeouts(int timeout_ms, int max_retries);
void cleanup_expired_sessions(void);

GamePhase get_game_phase(WambleBoard *board);

int db_init(const char *connection_string);
void db_cleanup(void);
void db_tick(void);

uint64_t db_create_session(const uint8_t *token, uint64_t player_id);
uint64_t db_get_session_by_token(const uint8_t *token);
void db_update_session_last_seen(uint64_t session_id);

uint64_t db_create_board(const char *fen);
int db_update_board(uint64_t board_id, const char *fen, const char *status);
int db_get_board(uint64_t board_id, char *fen_out, char *status_out);
int db_get_boards_by_status(const char *status, uint64_t *board_ids,
                            int max_boards);

int db_record_move(uint64_t board_id, uint64_t session_id, const char *move_uci,
                   int move_number);
int db_get_moves_for_board(uint64_t board_id, WambleMove *moves_out,
                           int max_moves);

int db_create_reservation(uint64_t board_id, uint64_t session_id,
                          int timeout_seconds);
void db_remove_reservation(uint64_t board_id);

int db_record_game_result(uint64_t board_id, char winning_side);
int db_record_payout(uint64_t board_id, uint64_t session_id, double points);
double db_get_player_total_score(uint64_t session_id);

int db_get_active_session_count(void);
int db_get_longest_game_moves(void);
int db_get_session_games_played(uint64_t session_id);

void db_expire_reservations(void);
void db_async_update_board(uint64_t board_id, const char *fen,
                           const char *status);
void db_async_create_reservation(uint64_t board_id, uint64_t session_id,
                                 int timeout_seconds);
void db_async_remove_reservation(uint64_t board_id);
void db_async_record_game_result(uint64_t board_id, char winning_side);
void db_async_record_move(uint64_t board_id, uint64_t session_id,
                          const char *move_uci, int move_number);
void db_async_record_payout(uint64_t board_id, uint64_t session_id,
                            double points);

void rng_init(void);
uint64_t rng_u64(void);
double rng_double(void);
void rng_bytes(uint8_t *out, size_t len);
void db_archive_inactive_boards(int timeout_seconds);

int create_and_bind_socket(int port);
int receive_message(int sockfd, struct WambleMsg *msg,
                    struct sockaddr_in *cliaddr);
void send_ack(int sockfd, const struct WambleMsg *msg,
              const struct sockaddr_in *cliaddr);
int send_reliable_message(int sockfd, const struct WambleMsg *msg,
                          const struct sockaddr_in *cliaddr, int timeout_ms,
                          int max_retries);
int wait_for_ack(int sockfd, uint32_t expected_seq, int timeout_ms);

static inline int tokens_equal(const uint8_t *token1, const uint8_t *token2) {
  for (int i = 0; i < TOKEN_LENGTH; i++) {
    if (token1[i] != token2[i]) {
      return 0;
    }
  }
  return 1;
}

#endif
