#ifndef WAMBLE_H
#define WAMBLE_H

#if !defined(_WIN32)
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif

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
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
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

int gmtime_w(struct tm *out_tm, const time_t *timer);

#ifdef WAMBLE_PLATFORM_WINDOWS
#define wamble_getpid() GetCurrentProcessId()
#else
#include <unistd.h>
#define wamble_getpid() getpid()
#endif

#ifdef WAMBLE_PLATFORM_WINDOWS
static inline int wamble_mkstemp(char *tmpl) {
  if (!tmpl)
    return -1;
  size_t len = strlen(tmpl);
  if (len == 0)
    return -1;
  if (_mktemp_s(tmpl, len + 1) != 0)
    return -1;
  int fd = _open(tmpl, _O_CREAT | _O_EXCL | _O_RDWR | _O_BINARY,
                 _S_IREAD | _S_IWRITE);
  return fd;
}
static inline int wamble_unlink(const char *path) { return _unlink(path); }
#else
#define wamble_mkstemp mkstemp
#define wamble_unlink unlink
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
void wamble_config_push(const struct WambleConfig *cfg);
void wamble_config_pop(void);
typedef struct WambleProfile WambleProfile;

static inline void wamble_log(int level, const char *file, int line,
                              const char *func, const char *level_str,
                              const char *format, ...);

#define LOG_FATAL(...)                                                         \
  do {                                                                         \
    wamble_log(LOG_LEVEL_FATAL, __FILE__, __LINE__, __func__, "FATAL",         \
               __VA_ARGS__);                                                   \
    exit(1);                                                                   \
  } while (0)

#if LOG_LEVEL >= LOG_LEVEL_ERROR
#define LOG_ERROR(...)                                                         \
  wamble_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "ERROR",           \
             __VA_ARGS__)
#else
#define LOG_ERROR(...)                                                         \
  do {                                                                         \
  } while (0)
#endif

#if LOG_LEVEL >= LOG_LEVEL_WARN
#define LOG_WARN(...)                                                          \
  wamble_log(LOG_LEVEL_WARN, __FILE__, __LINE__, __func__, "WARN", __VA_ARGS__)
#else
#define LOG_WARN(...)                                                          \
  do {                                                                         \
  } while (0)
#endif

#if LOG_LEVEL >= LOG_LEVEL_INFO
#define LOG_INFO(...)                                                          \
  wamble_log(LOG_LEVEL_INFO, __FILE__, __LINE__, __func__, "INFO", __VA_ARGS__)
#else
#define LOG_INFO(...)                                                          \
  do {                                                                         \
  } while (0)
#endif

#if LOG_LEVEL >= LOG_LEVEL_DEBUG
#define LOG_DEBUG(...)                                                         \
  wamble_log(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __func__, "DEBUG",           \
             __VA_ARGS__)
#else
#define LOG_DEBUG(...)                                                         \
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
  int websocket_enabled;
  int websocket_port;
  int experiment_enabled;
  int experiment_seed;
  int experiment_arms;
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
  int persistence_max_intents;
  int persistence_max_payload_bytes;
  double new_player_early_phase_mult;
  double new_player_mid_phase_mult;
  double new_player_end_phase_mult;
  double experienced_player_early_phase_mult;
  double experienced_player_mid_phase_mult;
  double experienced_player_end_phase_mult;
  int log_level;

  int max_spectators;
  int spectator_visibility;
  int spectator_summary_hz;
  int spectator_focus_hz;
  int spectator_max_focus_per_session;

  char *spectator_summary_mode;
  int admin_trust_level;

  char *state_dir;
  char *websocket_path;
  char *experiment_pairings;
} WambleConfig;

typedef enum {
  CONFIG_LOAD_OK = 0,
  CONFIG_LOAD_DEFAULTS = 1,
  CONFIG_LOAD_PROFILE_NOT_FOUND = -1,
  CONFIG_LOAD_IO_ERROR = -2,
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

typedef enum {
  PROFILE_START_OK = 0,
  PROFILE_START_NONE = 1,
  PROFILE_START_CONFLICT = 2,
  PROFILE_START_SOCKET_ERROR = 3,
  PROFILE_START_BIND_ERROR = 4,
  PROFILE_START_THREAD_ERROR = 5,
  PROFILE_START_NO_SOCKET = 6,
  PROFILE_START_DEFAULT_RUNTIME = 7,
} ProfileStartStatus;

typedef enum {
  PROFILE_EXPORT_OK = 0,
  PROFILE_EXPORT_EMPTY = 1,
  PROFILE_EXPORT_BUFFER_TOO_SMALL = -1,
  PROFILE_EXPORT_NOT_READY = -2,
} ProfileExportStatus;

typedef enum {
  DB_OK = 0,
  DB_NOT_FOUND = 1,
  DB_ERR_CONN = -1,
  DB_ERR_EXEC = -2,
  DB_ERR_BAD_DATA = -3,
} DbStatus;

typedef enum {
  NET_OK = 0,
  NET_ERR_INVALID = -1,
  NET_ERR_TRUNCATED = -2,
  NET_ERR_IO = -3,
  NET_ERR_TIMEOUT = -4,
} NetworkStatus;

typedef enum {
  WS_GATEWAY_OK = 0,
  WS_GATEWAY_ERR_CONFIG = -1,
  WS_GATEWAY_ERR_BIND = -2,
  WS_GATEWAY_ERR_THREAD = -3,
  WS_GATEWAY_ERR_ALLOC = -4,
} WsGatewayStatus;

typedef enum {
  PLAYER_OK = 0,
  PLAYER_ERR_BUSY = -1,
  PLAYER_ERR_DB = -2,
  PLAYER_ERR_INVALID = -3,
  PLAYER_ERR_NOT_FOUND = -4,
} PlayerStatus;

typedef enum {
  BOARD_OK = 0,
  BOARD_ERR_NOT_FOUND = -1,
  BOARD_ERR_BUSY = -2,
  BOARD_ERR_DB = -3,
  BOARD_ERR_INVALID = -4,
} BoardStatus;

typedef enum {
  SCORING_OK = 0,
  SCORING_NONE = 1,
  SCORING_ERR_DB = -1,
  SCORING_ERR_INVALID = -2,
} ScoringStatus;

typedef enum {
  SERVER_OK = 0,
  SERVER_ERR_UNSUPPORTED_VERSION = -1,
  SERVER_ERR_UNKNOWN_CTRL = -2,
  SERVER_ERR_UNKNOWN_PLAYER = -3,
  SERVER_ERR_UNKNOWN_BOARD = -4,
  SERVER_ERR_MOVE_REJECTED = -5,
  SERVER_ERR_LOGIN_FAILED = -6,
  SERVER_ERR_SPECTATOR = -7,
  SERVER_ERR_LEGAL_MOVES = -8,
  SERVER_ERR_SEND_FAILED = -9,
  SERVER_ERR_INTERNAL = -10,
} ServerStatus;

ProfileStartStatus start_profile_listeners(int *out_started);
void stop_profile_listeners(void);
ProfileStartStatus reconcile_profile_listeners(void);
int profile_runtime_pump_inline(void);
int profile_runtime_take_ws_gateway_status(WsGatewayStatus *out_status,
                                           char *out_profile,
                                           size_t out_profile_size);

int state_save_to_file(const char *path);
int state_load_from_file(const char *path);

ProfileExportStatus profile_export_inherited_sockets(char *out_buf,
                                                     size_t out_buf_size,
                                                     int *out_count);
void profile_mark_sockets_inheritable(void);
ProfileExportStatus profile_prepare_state_save_and_inherit(
    char *out_state_map, size_t out_state_map_size, int *out_count);

uint64_t wamble_now_mono_millis(void);
time_t wamble_now_wall(void);

uint64_t wamble_now_nanos(void);

static inline void wamble_log(int level, const char *file, int line,
                              const char *func, const char *level_str,
                              const char *format, ...) {
  int effective = LOG_LEVEL_INFO;
  {
    const struct WambleConfig *cfg = get_config();
    if (cfg)
      effective = cfg->log_level;
  }
  if (level > effective) {
    return;
  }

  time_t now = wamble_now_wall();
  char time_buf[21];
  struct tm tm_utc;
  if (gmtime_w(&tm_utc, &now)) {
    strftime(time_buf, sizeof time_buf, "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
  } else {
    snprintf(time_buf, sizeof time_buf, "0000-00-00T00:00:00Z");
  }

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

struct WambleMove;

typedef struct {
  DbStatus status;
  char fen[FEN_MAX_LENGTH];
  char status_text[STATUS_MAX_LENGTH];
  time_t last_assignment_time;
} DbBoardResult;

typedef struct {
  DbStatus status;
  const uint64_t *ids;
  int count;
} DbBoardIdList;

typedef struct {
  DbStatus status;
  const struct WambleMove *rows;
  int count;
} DbMovesResult;

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

#define WAMBLE_CTRL_SPECTATE_STOP 0x15

#define WAMBLE_CTRL_GET_LEGAL_MOVES 0x16
#define WAMBLE_CTRL_LEGAL_MOVES 0x17

#define get_bit(square) (1ULL << (square))

typedef enum {
  SPECTATOR_STATE_IDLE,
  SPECTATOR_STATE_SUMMARY,
  SPECTATOR_STATE_FOCUS,
} SpectatorState;

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
#define WAMBLE_MIN_CLIENT_VERSION 1
#define WAMBLE_CAPABILITY_MASK 0x7F
#define WAMBLE_CAP_HOT_RELOAD 0x01
#define WAMBLE_CAP_PROFILE_STATE 0x02
#define WAMBLE_ERR_UNSUPPORTED_VERSION 1000

#define WAMBLE_FLAG_UNRELIABLE 0x80

#define WAMBLE_MAX_LEGAL_MOVES 218

typedef struct {
  uint8_t from;
  uint8_t to;
  int8_t promotion;
} WambleNetMove;

#pragma pack(push, 1)
struct WambleMsg {
  uint8_t ctrl;
  uint8_t flags;
  uint8_t header_version;
  uint8_t token[TOKEN_LENGTH];
  uint64_t board_id;
  uint32_t seq_num;
  uint8_t uci_len;
  char uci[MAX_UCI_LENGTH];
  char fen[FEN_MAX_LENGTH];
  uint16_t error_code;
  char error_reason[FEN_MAX_LENGTH];
  uint8_t login_pubkey[32];
  uint8_t move_square;
  uint8_t move_count;
  WambleNetMove moves[WAMBLE_MAX_LEGAL_MOVES];
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
  double rating;
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
  uint16_t last_mover_arm;
  uint8_t reservation_player_token[TOKEN_LENGTH];
  bool reserved_for_white;
  time_t reservation_time;
} WambleBoard;

#define WAMBLE_EXPERIMENT_ARM_NULL UINT16_MAX

typedef struct WambleClientSession {
  struct sockaddr_in addr;
  uint8_t token[TOKEN_LENGTH];
  uint32_t last_seq_num;
  time_t last_seen;
  uint32_t next_seq_num;
  uint16_t experiment_arm;
} WambleClientSession;

int validate_and_apply_move_status(WambleBoard *wamble_board,
                                   WamblePlayer *player, const char *uci_move,
                                   MoveApplyStatus *out_status);

int get_legal_moves_for_square(const Board *board, int square, Move *moves,
                               int max_moves);

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
void board_move_played(uint64_t board_id);
void board_game_completed(uint64_t board_id, GameResult result);
bool board_is_reserved_for_player(uint64_t board_id,
                                  const uint8_t *player_token);
void board_release_reservation(uint64_t board_id);
void board_archive(uint64_t board_id);
void update_player_ratings(WambleBoard *board);
WambleBoard *get_board_by_id(uint64_t board_id);
int get_total_board_count_public(void);
int board_manager_export(WambleBoard *out, int max, int *out_count,
                         uint64_t *out_next_id);
int board_manager_import(const WambleBoard *in, int count, uint64_t next_id);

ScoringStatus calculate_and_distribute_pot(uint64_t board_id);

void player_manager_init(void);
WamblePlayer *create_new_player(void);
WamblePlayer *login_player(const uint8_t *public_key);
void format_token_for_url(const uint8_t *token, char *url_buffer);
int decode_token_from_url(const char *url_string, uint8_t *token_buffer);
void player_manager_tick(void);

WamblePlayer *get_player_by_token(const uint8_t *token);
void discard_player_by_token(const uint8_t *token);
void network_init_thread_state(void);
uint16_t network_experiment_arm_for_token(const uint8_t *token);
int network_get_session_experiment_arm(const uint8_t *token, uint16_t *out_arm);

void cleanup_expired_sessions(void);

void rng_init(void);
uint64_t rng_u64(void);
double rng_double(void);
void rng_bytes(uint8_t *out, size_t len);
void rng_seed(uint64_t hi, uint64_t lo);

typedef enum {
  PERSISTENCE_STATUS_OK = 0,
  PERSISTENCE_STATUS_NO_BUFFER = 1,
  PERSISTENCE_STATUS_ALLOC_FAIL = 2,
  PERSISTENCE_STATUS_APPLY_FAIL = 3,
  PERSISTENCE_STATUS_EMPTY = 4,
} PersistenceStatus;

void wamble_emit_update_board(uint64_t board_id, const char *fen,
                              const char *status);
void wamble_emit_update_board_assignment_time(uint64_t board_id);
void wamble_emit_create_reservation(uint64_t board_id, const uint8_t *token,
                                    int timeout_seconds);
void wamble_emit_remove_reservation(uint64_t board_id);
void wamble_emit_record_game_result(uint64_t board_id, char winning_side);
void wamble_emit_update_session_last_seen(const uint8_t *token);
void wamble_emit_create_session(const uint8_t *token, uint64_t player_id);
void wamble_emit_link_session_to_pubkey(const uint8_t *token,
                                        const uint8_t *public_key);
void wamble_emit_record_payout(uint64_t board_id, const uint8_t *token,
                               double points);
void wamble_emit_create_board(uint64_t board_id, const char *fen,
                              const char *status);
void wamble_emit_record_move(uint64_t board_id, const uint8_t *token,
                             const char *move_uci, int move_number);

DbBoardIdList wamble_query_list_boards_by_status(const char *status);
DbBoardResult wamble_query_get_board(uint64_t board_id);
DbMovesResult wamble_query_get_moves_for_board(uint64_t board_id);
DbStatus wamble_query_get_longest_game_moves(int *out_max_moves);
DbStatus wamble_query_get_active_session_count(int *out_count);
DbStatus wamble_query_get_max_board_id(uint64_t *out_max_id);
DbStatus wamble_query_get_persistent_session_by_token(const uint8_t *token,
                                                      uint64_t *out_session);
DbStatus wamble_query_get_player_total_score(uint64_t session_id,
                                             double *out_total);
DbStatus wamble_query_get_player_rating(uint64_t session_id,
                                        double *out_rating);
DbStatus wamble_query_get_session_games_played(uint64_t session_id,
                                               int *out_games);

wamble_socket_t create_and_bind_socket(int port);
int receive_message(wamble_socket_t sockfd, struct WambleMsg *msg,
                    struct sockaddr_in *cliaddr);
void send_ack(wamble_socket_t sockfd, const struct WambleMsg *msg,
              const struct sockaddr_in *cliaddr);
int send_reliable_message(wamble_socket_t sockfd, const struct WambleMsg *msg,
                          const struct sockaddr_in *cliaddr, int timeout_ms,
                          int max_retries);
int send_unreliable_packet(wamble_socket_t sockfd, const struct WambleMsg *msg,
                           const struct sockaddr_in *cliaddr);
ServerStatus handle_message(wamble_socket_t sockfd, const struct WambleMsg *msg,
                            const struct sockaddr_in *cliaddr, int trust_tier);

typedef struct WambleWsGateway WambleWsGateway;
WambleWsGateway *ws_gateway_start(const char *profile_name, int ws_port,
                                  int udp_port, const char *ws_path,
                                  int max_clients, WsGatewayStatus *out_status);
void ws_gateway_stop(WambleWsGateway *gateway);
int ws_gateway_matches(const WambleWsGateway *gateway, int ws_port,
                       int udp_port, const char *ws_path);

typedef enum {
  SPECTATOR_INIT_OK = 0,
  SPECTATOR_INIT_ERR_NO_CAPACITY = -1,
  SPECTATOR_INIT_ERR_ALLOC = -2,
} SpectatorInitStatus;

SpectatorInitStatus spectator_manager_init(void);
void spectator_manager_shutdown(void);
void spectator_manager_tick(void);
typedef enum {
  SPECTATOR_OK_SUMMARY = 0,
  SPECTATOR_OK_FOCUS = 1,
  SPECTATOR_OK_STOP = 2,
  SPECTATOR_ERR_VISIBILITY = -1,
  SPECTATOR_ERR_BUSY = -2,
  SPECTATOR_ERR_FULL = -3,
  SPECTATOR_ERR_FOCUS_DISABLED = -4,
  SPECTATOR_ERR_NOT_AVAILABLE = -5,
} SpectatorRequestStatus;

typedef struct SpectatorUpdate {
  uint8_t token[TOKEN_LENGTH];
  uint64_t board_id;
  char fen[FEN_MAX_LENGTH];
  struct sockaddr_in addr;
} SpectatorUpdate;

SpectatorRequestStatus spectator_handle_request(
    const struct WambleMsg *msg, const struct sockaddr_in *cliaddr,
    int trust_tier, SpectatorState *out_state, uint64_t *out_focus_board_id);

int spectator_collect_updates(struct SpectatorUpdate *out, int max);
int spectator_collect_notifications(struct SpectatorUpdate *out, int max);

static inline int tokens_equal(const uint8_t *token1, const uint8_t *token2) {
  for (int i = 0; i < TOKEN_LENGTH; i++) {
    if (token1[i] != token2[i]) {
      return 0;
    }
  }
  return 1;
}

#endif
