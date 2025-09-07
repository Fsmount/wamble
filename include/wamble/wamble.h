#ifndef WAMBLE_H
#define WAMBLE_H

#if defined(_WIN32)
#define WAMBLE_PLATFORM_WINDOWS
#elif defined(__unix__) || defined(__APPLE__)
#define WAMBLE_PLATFORM_POSIX
#else
#error "Unsupported platform"
#endif

#if defined(WAMBLE_PLATFORM_WINDOWS)
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <bcrypt.h>
#elif defined(WAMBLE_PLATFORM_POSIX)
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#else
#define WAMBLE_SINGLE_THREADED
#endif

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_MSC_VER)
#define WAMBLE_WEAK
#else
#define WAMBLE_WEAK __attribute__((weak))
#endif

#ifdef WAMBLE_PLATFORM_WINDOWS
#define wamble_getpid() GetCurrentProcessId()
#else
#include <unistd.h>
#define wamble_getpid() getpid()
#endif

#if defined(_MSC_VER) && _MSC_VER < 1900
static inline size_t wamble_strnlen(const char *s, size_t max) {
  size_t i = 0;
  if (!s)
    return 0;
  for (; i < max && s[i]; i++) {
  }
  return i;
}
#define strnlen wamble_strnlen
#endif

#if __STDC_VERSION__ >= 201112L
#define WAMBLE_THREAD_LOCAL _Thread_local
#elif defined(__GNUC__) || defined(__clang__)
#define WAMBLE_THREAD_LOCAL __thread
#elif defined(_MSC_VER)
#define WAMBLE_THREAD_LOCAL __declspec(thread)
#else
#define WAMBLE_THREAD_LOCAL
#endif

#ifdef WAMBLE_PLATFORM_WINDOWS
typedef SOCKET wamble_socket_t;
#define WAMBLE_INVALID_SOCKET INVALID_SOCKET
#else
typedef int wamble_socket_t;
#define WAMBLE_INVALID_SOCKET -1
#endif

#ifdef WAMBLE_PLATFORM_WINDOWS
typedef int wamble_socklen_t;
#else
typedef socklen_t wamble_socklen_t;
#endif

static inline int wamble_net_init(void);
static inline void wamble_net_cleanup(void);
static inline int wamble_close_socket(wamble_socket_t sock);
static inline int wamble_set_nonblocking(wamble_socket_t sock);
static inline const char *wamble_inet_ntop(int af, const void *src, char *dst,
                                           wamble_socklen_t size);
static inline int wamble_last_error(void);
static inline const char *wamble_strerror(int err);

#if defined(WAMBLE_PLATFORM_WINDOWS)
static inline int wamble_net_init(void) {
  WSADATA wsaData;
  int result = WSAStartup(MAKEWORD(2, 2), &wsaData);

  return result;
}

static inline void wamble_net_cleanup(void) { WSACleanup(); }

static inline int wamble_close_socket(wamble_socket_t sock) {
  return closesocket(sock);
}

static inline int wamble_set_nonblocking(wamble_socket_t sock) {
  u_long mode = 1;
  return ioctlsocket(sock, FIONBIO, &mode);
}

static inline const char *wamble_inet_ntop(int af, const void *src, char *dst,
                                           wamble_socklen_t size) {

  if (af == AF_INET) {
    struct in_addr tmp;
    memcpy(&tmp, src, sizeof(struct in_addr));
    return InetNtop(af, &tmp, dst, size);
  } else if (af == AF_INET6) {
    struct in6_addr tmp;
    memcpy(&tmp, src, sizeof(struct in6_addr));
    return InetNtop(af, &tmp, dst, size);
  }
  return NULL;
}

static inline int wamble_last_error(void) { return WSAGetLastError(); }

static inline const char *wamble_strerror(int err) {
  static WAMBLE_THREAD_LOCAL char buffer[256];
  FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                 NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buffer,
                 sizeof(buffer), NULL);
  return buffer;
}

#elif defined(WAMBLE_PLATFORM_POSIX)
static inline int wamble_net_init(void) { return 0; }

static inline void wamble_net_cleanup(void) {}

static inline int wamble_close_socket(wamble_socket_t sock) {
  return close(sock);
}

static inline int wamble_set_nonblocking(wamble_socket_t sock) {
  int flags = fcntl(sock, F_GETFL, 0);
  if (flags == -1)
    return -1;
  return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

static inline const char *wamble_inet_ntop(int af, const void *src, char *dst,
                                           wamble_socklen_t size) {
  return inet_ntop(af, src, dst, size);
}

static inline int wamble_last_error(void) { return errno; }

static inline const char *wamble_strerror(int err) { return strerror(err); }
#endif

#define LOG_LEVEL_FATAL 0
#define LOG_LEVEL_ERROR 1
#define LOG_LEVEL_WARN 2
#define LOG_LEVEL_INFO 3
#define LOG_LEVEL_DEBUG 4

#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_LEVEL_DEBUG
#endif

struct WambleConfig;
const struct WambleConfig *get_config(void);
void set_thread_config(const struct WambleConfig *cfg);
typedef struct WambleProfile WambleProfile;

static inline void wamble_log(int level, const char *file, int line,
                              const char *func, const char *level_str,
                              const char *format, ...);

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

typedef struct WambleConfig {
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
  double new_player_early_phase_mult;
  double new_player_mid_phase_mult;
  double new_player_end_phase_mult;
  double experienced_player_early_phase_mult;
  double experienced_player_mid_phase_mult;
  double experienced_player_end_phase_mult;
  int log_level;
  int log_level_main;
  int log_level_network;
  int log_level_database;
  int log_level_board_manager;
  int log_level_player_manager;
  int log_level_move_engine;
  int log_level_scoring;
} WambleConfig;

typedef enum {
  CONFIG_LOAD_OK = 0,
  CONFIG_LOAD_DEFAULTS = 1,
  CONFIG_LOAD_IO_ERROR = 2,
  CONFIG_LOAD_PROFILE_NOT_FOUND = 3,
} ConfigLoadStatus;

ConfigLoadStatus config_load(const char *filename, const char *profile,
                             char *status_msg, size_t status_msg_size);

struct WambleProfile {
  char *name;
  WambleConfig config;
  int advertise;
  int visibility;
  int db_isolated;
};

int config_profile_count(void);
const WambleProfile *config_get_profile(int index);
const WambleProfile *config_find_profile(const char *name);

int start_profile_listeners(void);
void stop_profile_listeners(void);
void reconcile_profile_listeners(void);

static inline void wamble_log(int level, const char *file, int line,
                              const char *func, const char *level_str,
                              const char *format, ...) {
  int effective = LOG_LEVEL_INFO;
  {
    const struct WambleConfig *cfg = get_config();
    if (cfg)
      effective = cfg->log_level;
    if (cfg && file) {
      if (strstr(file, "/network.c") || strstr(file, "network.c")) {
        if (cfg->log_level_network >= 0)
          effective = cfg->log_level_network;
      } else if (strstr(file, "/database.c") || strstr(file, "database.c")) {
        if (cfg->log_level_database >= 0)
          effective = cfg->log_level_database;
      } else if (strstr(file, "/board_manager.c") ||
                 strstr(file, "board_manager.c")) {
        if (cfg->log_level_board_manager >= 0)
          effective = cfg->log_level_board_manager;
      } else if (strstr(file, "/player_manager.c") ||
                 strstr(file, "player_manager.c")) {
        if (cfg->log_level_player_manager >= 0)
          effective = cfg->log_level_player_manager;
      } else if (strstr(file, "/move_engine.c") ||
                 strstr(file, "move_engine.c")) {
        if (cfg->log_level_move_engine >= 0)
          effective = cfg->log_level_move_engine;
      } else if (strstr(file, "/scoring.c") || strstr(file, "scoring.c")) {
        if (cfg->log_level_scoring >= 0)
          effective = cfg->log_level_scoring;
      } else if (strstr(file, "/main.c") || strstr(file, "main.c")) {
        if (cfg->log_level_main >= 0)
          effective = cfg->log_level_main;
      }
    }
  }
  if (level > effective) {
    return;
  }

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

#define FEN_MAX_LENGTH 90
#define MAX_UCI_LENGTH 6
#define TOKEN_LENGTH 16
#define STATUS_MAX_LENGTH 17

#define WAMBLE_CTRL_CLIENT_HELLO 0x01
#define WAMBLE_CTRL_SERVER_HELLO 0x02
#define WAMBLE_CTRL_PLAYER_MOVE 0x03
#define WAMBLE_CTRL_BOARD_UPDATE 0x04
#define WAMBLE_CTRL_ACK 0x05

#define WAMBLE_CTRL_LIST_PROFILES 0x06
#define WAMBLE_CTRL_PROFILE_INFO 0x07

#define WAMBLE_CTRL_ERROR 0x08
#define WAMBLE_CTRL_SERVER_NOTIFICATION 0x09
#define WAMBLE_CTRL_CLIENT_GOODBYE 0x0A
#define WAMBLE_CTRL_SPECTATE_GAME 0x0B
#define WAMBLE_CTRL_SPECTATE_UPDATE 0x0C

#define WAMBLE_CTRL_LOGIN_REQUEST 0x0D
#define WAMBLE_CTRL_LOGOUT 0x0E
#define WAMBLE_CTRL_LOGIN_SUCCESS 0x0F
#define WAMBLE_CTRL_LOGIN_FAILED 0x10
#define WAMBLE_CTRL_GET_PLAYER_STATS 0x11
#define WAMBLE_CTRL_PLAYER_STATS_DATA 0x12

#define WAMBLE_CTRL_GET_PROFILE_INFO 0x13
#define WAMBLE_CTRL_PROFILES_LIST 0x14

#define get_bit(square) (1ULL << (square))

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

typedef enum {
  MOVE_OK = 0,
  MOVE_ERR_INVALID_ARGS,
  MOVE_ERR_NOT_RESERVED,
  MOVE_ERR_NOT_TURN,
  MOVE_ERR_BAD_UCI,
  MOVE_ERR_ILLEGAL,
} MoveApplyStatus;

#define WAMBLE_PROTO_VERSION 1
#define WAMBLE_FLAG_UNRELIABLE 0x80

#pragma pack(push, 1)
struct WambleMsg {
  uint8_t ctrl;
  uint8_t flags;
  uint8_t token[TOKEN_LENGTH];
  uint64_t board_id;
  uint32_t seq_num;
  uint8_t uci_len;
  char uci[MAX_UCI_LENGTH];
  char fen[FEN_MAX_LENGTH];
  uint16_t error_code;
  char error_reason[FEN_MAX_LENGTH];
  uint8_t login_pubkey[32];
};
#pragma pack(pop)

#define WAMBLE_MAX_PAYLOAD 1200
#define WAMBLE_DUP_WINDOW 1024

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

int validate_and_apply_move_status(WambleBoard *wamble_board,
                                   WamblePlayer *player, const char *uci_move,
                                   MoveApplyStatus *out_status);

static inline int validate_and_apply_move(WambleBoard *wamble_board,
                                          WamblePlayer *player,
                                          const char *uci_move) {
  return validate_and_apply_move_status(wamble_board, player, uci_move, NULL);
}

int parse_fen_to_bitboard(const char *fen, Board *board);
void bitboard_to_fen(const Board *board, char *fen);

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
WambleBoard *get_board_by_id(uint64_t board_id);

void calculate_and_distribute_pot(uint64_t board_id);

void player_manager_init(void);
WamblePlayer *create_new_player(void);
WamblePlayer *login_player(const uint8_t *public_key);
void format_token_for_url(const uint8_t *token, char *url_buffer);
int decode_token_from_url(const char *url_string, uint8_t *token_buffer);
void player_manager_tick(void);

WamblePlayer *get_player_by_token(const uint8_t *token);
void network_init_thread_state(void);

void cleanup_expired_sessions(void);

int db_init(const char *connection_string);
void db_cleanup(void);
void db_tick(void);

uint64_t db_create_session(const uint8_t *token, uint64_t player_id);
uint64_t db_get_session_by_token(const uint8_t *token);
void db_async_update_session_last_seen(uint64_t session_id);

uint64_t db_create_board(const char *fen);
int db_async_update_board(uint64_t board_id, const char *fen,
                          const char *status);
int db_get_board(uint64_t board_id, char *fen_out, char *status_out);
int db_get_boards_by_status(const char *status, uint64_t *board_ids,
                            int max_boards);

int db_async_record_move(uint64_t board_id, uint64_t session_id,
                         const char *move_uci, int move_number);
int db_get_moves_for_board(uint64_t board_id, WambleMove *moves_out,
                           int max_moves);

int db_async_create_reservation(uint64_t board_id, uint64_t session_id,
                                int timeout_seconds);
void db_async_remove_reservation(uint64_t board_id);

int db_async_record_game_result(uint64_t board_id, char winning_side);
int db_async_record_payout(uint64_t board_id, uint64_t session_id,
                           double points);
double db_get_player_total_score(uint64_t session_id);

int db_get_active_session_count(void);
int db_get_longest_game_moves(void);
int db_get_session_games_played(uint64_t session_id);

uint64_t db_create_player(const uint8_t *public_key);
uint64_t db_get_player_by_public_key(const uint8_t *public_key);
int db_async_link_session_to_player(uint64_t session_id, uint64_t player_id);

void db_expire_reservations(void);

void db_cleanup_thread(void) WAMBLE_WEAK;

int db_get_trust_tier_by_token(const uint8_t *token);

void rng_init(void);
uint64_t rng_u64(void);
double rng_double(void);
void rng_bytes(uint8_t *out, size_t len);
void db_archive_inactive_boards(int timeout_seconds);

wamble_socket_t create_and_bind_socket(int port);
int receive_message(wamble_socket_t sockfd, struct WambleMsg *msg,
                    struct sockaddr_in *cliaddr);
void send_ack(wamble_socket_t sockfd, const struct WambleMsg *msg,
              const struct sockaddr_in *cliaddr);
int send_reliable_message(wamble_socket_t sockfd, const struct WambleMsg *msg,
                          const struct sockaddr_in *cliaddr, int timeout_ms,
                          int max_retries);
void handle_message(wamble_socket_t sockfd, const struct WambleMsg *msg,
                    const struct sockaddr_in *cliaddr);

static inline int tokens_equal(const uint8_t *token1, const uint8_t *token2) {
  for (int i = 0; i < TOKEN_LENGTH; i++) {
    if (token1[i] != token2[i]) {
      return 0;
    }
  }
  return 1;
}

#endif
