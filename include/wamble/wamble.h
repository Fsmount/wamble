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

#ifdef WAMBLE_PLATFORM_WINDOWS
#define wamble_getpid() GetCurrentProcessId()
#else
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

static inline char *wamble_strdup(const char *s) {
  const char *src = s ? s : "";
  size_t n = strlen(src);
  char *out = (char *)malloc(n + 1);
  if (!out)
    return NULL;
  memcpy(out, src, n + 1);
  return out;
}

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
typedef struct WamblePolicyDecision WamblePolicyDecision;

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
  int timeout_ms;
  int max_retries;
  int max_message_size;
  int buffer_size;
  int max_client_sessions;
  int rate_limit_requests_per_sec;
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
  int db_port;
  char *db_user;
  char *db_pass;
  char *db_name;
  char *global_db_host;
  int global_db_port;
  char *global_db_user;
  char *global_db_pass;
  char *global_db_name;
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
  int prediction_mode;
  int prediction_gated_percent;
  int prediction_streak_cap;
  int prediction_max_pending;
  int prediction_view_depth_limit;
  double prediction_base_points;
  double prediction_streak_multiplier;
  double prediction_penalty_incorrect;
  char *prediction_match_policy;

  char *spectator_summary_mode;

  char *state_dir;
  char *websocket_path;
  int chess960_interval;
} WambleConfig;

typedef enum {
  CONFIG_LOAD_OK = 0,
  CONFIG_LOAD_DEFAULTS = 1,
  CONFIG_LOAD_PROFILE_NOT_FOUND = -1,
  CONFIG_LOAD_IO_ERROR = -2,
} ConfigLoadStatus;

#define WAMBLE_DEFAULT_RUNTIME_EXPORT_NAME "__wamble_default_runtime__"

ConfigLoadStatus config_load(const char *filename, const char *profile,
                             char *status_msg, size_t status_msg_size);
void *config_create_snapshot(void);
int config_restore_snapshot(const void *snapshot);
void config_free_snapshot(void *snapshot);

struct WambleProfile {
  char *name;
  char *group;
  char *tos_text;
  WambleConfig config;
  int abstract;
  int advertise;
  int visibility;
  int db_isolated;
};

int config_profile_count(void);
const WambleProfile *config_get_profile(int index);
const WambleProfile *config_find_profile(const char *name);
const char *config_profile_group(const char *name);

typedef struct WamblePolicyRuleSpec {
  char *identity_selector;
  char *action;
  char *resource;
  char *effect;
  int permission_level;
  char *reason;
  char *policy_version;
  int64_t not_before_at;
  int64_t not_after_at;
  char *context_key;
  char *context_value;
} WamblePolicyRuleSpec;

typedef enum {
  WAMBLE_TREATMENT_VALUE_NONE = 0,
  WAMBLE_TREATMENT_VALUE_STRING = 1,
  WAMBLE_TREATMENT_VALUE_INT = 2,
  WAMBLE_TREATMENT_VALUE_DOUBLE = 3,
  WAMBLE_TREATMENT_VALUE_BOOL = 4,
  WAMBLE_TREATMENT_VALUE_FACT_REF = 5,
} WambleTreatmentValueType;

typedef struct WambleTreatmentValueSpec {
  WambleTreatmentValueType type;
  char *string_value;
  int64_t int_value;
  double double_value;
  int bool_value;
  char *fact_key;
} WambleTreatmentValueSpec;

typedef struct WambleTreatmentGroupSpec {
  char *group_key;
  int priority;
  int is_default;
} WambleTreatmentGroupSpec;

typedef struct WambleTreatmentRulePredicateSpec {
  char *fact_key;
  char *op;
  WambleTreatmentValueSpec value;
} WambleTreatmentRulePredicateSpec;

typedef struct WambleTreatmentRuleSpec {
  char *identity_selector;
  char *profile_scope;
  char *group_key;
  int priority;
  int predicate_count;
  WambleTreatmentRulePredicateSpec *predicates;
} WambleTreatmentRuleSpec;

typedef struct WambleTreatmentEdgeSpec {
  char *source_group_key;
  char *target_group_key;
} WambleTreatmentEdgeSpec;

typedef struct WambleTreatmentOutputSpec {
  char *group_key;
  char *hook_name;
  char *output_kind;
  char *output_key;
  WambleTreatmentValueSpec value;
} WambleTreatmentOutputSpec;

typedef struct WambleFact {
  char key[128];
  WambleTreatmentValueType value_type;
  char string_value[256];
  int64_t int_value;
  double double_value;
  int bool_value;
} WambleFact;

typedef struct WambleTreatmentAssignment {
  uint64_t group_id;
  uint64_t rule_id;
  uint64_t snapshot_revision_id;
  time_t assigned_at;
  char group_key[128];
} WambleTreatmentAssignment;

typedef struct WambleTreatmentAction {
  char hook_name[64];
  char output_kind[32];
  char output_key[128];
  WambleTreatmentValueType value_type;
  char string_value[256];
  int64_t int_value;
  double double_value;
  int bool_value;
} WambleTreatmentAction;

int config_policy_rule_count(void);
const WamblePolicyRuleSpec *config_policy_rule_get(int index);
int config_has_policy_eval(void);
int config_policy_eval(const char *identity_selector, const char *action,
                       const char *resource, const char *profile_name,
                       const char *profile_group, const char *context_key,
                       const char *context_value, int64_t now_epoch_seconds,
                       WamblePolicyDecision *out);
int config_treatment_group_count(void);
const WambleTreatmentGroupSpec *config_treatment_group_get(int index);
int config_treatment_rule_count(void);
const WambleTreatmentRuleSpec *config_treatment_rule_get(int index);
int config_treatment_edge_count(void);
const WambleTreatmentEdgeSpec *config_treatment_edge_get(int index);
int config_treatment_output_count(void);
const WambleTreatmentOutputSpec *config_treatment_output_get(int index);

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

struct WamblePolicyDecision {
  int allowed;
  int permission_level;
  uint64_t global_identity_id;
  uint64_t rule_id;
  uint64_t snapshot_revision_id;
  char effect[8];
  char action[128];
  char resource[256];
  char scope[256];
  char reason[256];
  char policy_version[64];
};

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
  PREDICTION_MODE_DISABLED = 0,
  PREDICTION_MODE_NEXT_SELF_MOVE = 1,
  PREDICTION_MODE_STREAK = 2,
  PREDICTION_MODE_GATED = 3,
} PredictionMode;

typedef enum {
  PREDICTION_OK = 0,
  PREDICTION_NONE = 1,
  PREDICTION_ERR_DISABLED = -1,
  PREDICTION_ERR_INVALID = -2,
  PREDICTION_ERR_NOT_ALLOWED = -3,
  PREDICTION_ERR_LIMIT = -4,
  PREDICTION_ERR_DUPLICATE = -5,
  PREDICTION_ERR_NOT_FOUND = -6,
} PredictionStatus;

typedef enum {
  PREDICTION_MANAGER_OK = 0,
  PREDICTION_MANAGER_ERR_ALLOC = -1,
  PREDICTION_MANAGER_ERR_DB_LOAD = -2,
} PredictionManagerStatus;

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
  SERVER_ERR_FORBIDDEN = -11,
} ServerStatus;

typedef enum {
  WAMBLE_RUNTIME_EVENT_WS_GATEWAY = 1,
  WAMBLE_RUNTIME_EVENT_PREDICTION_MANAGER = 2,
  WAMBLE_RUNTIME_EVENT_TRUST_DECISION = 3,
  WAMBLE_RUNTIME_EVENT_PROFILE_ADMIN = 4,
  WAMBLE_RUNTIME_EVENT_SERVER_PROTOCOL = 5,
} WambleRuntimeEventKind;

typedef struct WambleRuntimeEvent {
  WambleRuntimeEventKind kind;
  int code;
  char profile[64];
} WambleRuntimeEvent;

ProfileStartStatus start_profile_listeners(int *out_started);
void stop_profile_listeners(void);
ProfileStartStatus reconcile_profile_listeners(void);
int profile_runtime_pump_inline(void);
void wamble_runtime_event_publish(WambleRuntimeEventKind kind, int code,
                                  const char *profile_name);
int wamble_runtime_event_take(WambleRuntimeEvent *out_event);
const char *wamble_runtime_profile_key(void);
typedef enum {
  PROFILE_ADMIN_STATUS_NONE = 0,
  PROFILE_ADMIN_STATUS_SPECTATOR_FOCUS_DISABLED_FALLBACK = 1,
  PROFILE_ADMIN_STATUS_SPECTATOR_BOARD_FINISHED_FALLBACK = 2,
  PROFILE_ADMIN_STATUS_SPECTATOR_STOPPED_BY_ZERO_CAP = 3,
} ProfileAdminStatus;
typedef enum {
  SERVER_PROTOCOL_STATUS_NONE = 0,
  SERVER_PROTOCOL_STATUS_FRAGMENTATION_SINGLE_PACKET = 1,
  SERVER_PROTOCOL_STATUS_FRAGMENTATION_MULTI_PACKET = 2,
  SERVER_PROTOCOL_STATUS_FRAGMENTATION_PREPARE_FAILED = 3,
  SERVER_PROTOCOL_STATUS_FRAGMENTATION_SEND_FAILED = 4,
  SERVER_PROTOCOL_STATUS_RATE_LIMIT_DENIED = 5,
  SERVER_PROTOCOL_STATUS_POLICY_DENIED = 6,
  SERVER_PROTOCOL_STATUS_PROFILE_DISCOVERY_OVERRIDE_EXPOSED = 7,
  SERVER_PROTOCOL_STATUS_PROFILE_INFO_NOT_FOUND = 8,
  SERVER_PROTOCOL_STATUS_PROFILE_INFO_HIDDEN = 9,
  SERVER_PROTOCOL_STATUS_CLIENT_HELLO_UNSUPPORTED_VERSION = 10,
  SERVER_PROTOCOL_STATUS_LOGIN_CHALLENGE_ISSUED = 11,
  SERVER_PROTOCOL_STATUS_LOGIN_SUCCESS = 12,
  SERVER_PROTOCOL_STATUS_LOGIN_FAILED = 13,
  SERVER_PROTOCOL_STATUS_MOVE_REJECTED = 14,
  SERVER_PROTOCOL_STATUS_SPECTATE_DENIED = 15,
  SERVER_PROTOCOL_STATUS_UNKNOWN_PLAYER = 16,
  SERVER_PROTOCOL_STATUS_UNKNOWN_BOARD = 17,
  SERVER_PROTOCOL_STATUS_UNKNOWN_CTRL = 18,
  SERVER_PROTOCOL_STATUS_LEGAL_MOVES_INVALID_REQUEST = 19,
  SERVER_PROTOCOL_STATUS_PREDICTION_REJECTED = 20,
} ServerProtocolStatus;
typedef enum {
  PROFILE_TRUST_DECISION_DENIED = 0,
  PROFILE_TRUST_DECISION_ALLOWED = 1,
  PROFILE_TRUST_DECISION_UNRESOLVED = 2,
} ProfileTrustDecisionStatus;

int state_save_to_file(const char *path);
int state_load_from_file(const char *path);
int wamble_runtime_state_path(char *out, size_t out_size, const char *name);

ProfileExportStatus profile_export_inherited_sockets(char *out_buf,
                                                     size_t out_buf_size,
                                                     int *out_count);
ProfileExportStatus profile_prepare_state_save_and_inherit(
    char *out_state_map, size_t out_state_map_size, int *out_count);

static inline uint64_t timespec_to_millis(const struct timespec *ts) {
  if (!ts)
    return 0;
  return ((uint64_t)ts->tv_sec * 1000ULL) +
         ((uint64_t)ts->tv_nsec / 1000000ULL);
}

static inline uint64_t timespec_to_nanos(const struct timespec *ts) {
  if (!ts)
    return 0;
  return ((uint64_t)ts->tv_sec * 1000000000ULL) + (uint64_t)ts->tv_nsec;
}

static inline uint64_t wamble_now_mono_millis(void) {
#if defined(WAMBLE_PLATFORM_WINDOWS)
  LARGE_INTEGER freq, counter;
  if (QueryPerformanceFrequency(&freq) && QueryPerformanceCounter(&counter)) {
    return (uint64_t)((counter.QuadPart * 1000ULL) / (uint64_t)freq.QuadPart);
  }
  return (uint64_t)GetTickCount64();
#else
  struct timespec ts;
#ifdef CLOCK_MONOTONIC
  if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
    return timespec_to_millis(&ts);
#endif
  if (clock_gettime(CLOCK_REALTIME, &ts) == 0)
    return timespec_to_millis(&ts);
  return (uint64_t)time(NULL) * 1000ULL;
#endif
}

static inline time_t wamble_now_wall(void) { return time(NULL); }

static inline uint64_t wamble_now_nanos(void) {
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
    return timespec_to_nanos(&ts);
#endif
  if (clock_gettime(CLOCK_REALTIME, &ts) == 0)
    return timespec_to_nanos(&ts);
  return (uint64_t)time(NULL) * 1000000000ULL;
#else
  return (uint64_t)time(NULL) * 1000000000ULL;
#endif
}

static inline void wamble_sleep_ms(int ms) {
  if (ms <= 0)
    return;
#if defined(WAMBLE_PLATFORM_WINDOWS)
  Sleep((DWORD)ms);
#else
  struct timeval tv;
  tv.tv_sec = ms / 1000;
  tv.tv_usec = (ms % 1000) * 1000;
  select(0, NULL, NULL, NULL, &tv);
#endif
}

static inline int gmtime_w(struct tm *out_tm, const time_t *timer) {
#if defined(WAMBLE_PLATFORM_WINDOWS)
  return (gmtime_s(out_tm, timer) == 0) ? 1 : 0;
#elif defined(WAMBLE_PLATFORM_POSIX)
#if defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L
  return (gmtime_r(timer, out_tm) != NULL) ? 1 : 0;
#else
  struct tm *tmp = gmtime(timer);
  if (!tmp)
    return 0;
  *out_tm = *tmp;
  return 1;
#endif
#else
  (void)out_tm;
  (void)timer;
  return 0;
#endif
}

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
#define PROFILE_NAME_MAX_LENGTH 256
#define TOKEN_LENGTH 16
#define STATUS_MAX_LENGTH 17
#define WAMBLE_PUBLIC_KEY_LENGTH 32
#define WAMBLE_LOGIN_SIGNATURE_LENGTH 64
#define WAMBLE_LOGIN_CHALLENGE_LENGTH 32
#define WAMBLE_MAX_PAYLOAD 1200
#define WAMBLE_HEADER_WIRE_SIZE (1 + 1 + 1 + 1 + TOKEN_LENGTH + 8 + 4 + 2)
#define WAMBLE_MAX_PACKET_SIZE (WAMBLE_HEADER_WIRE_SIZE + WAMBLE_MAX_PAYLOAD)
#define WAMBLE_FRAGMENT_HASH_LENGTH 32
#define WAMBLE_FRAGMENT_VERSION 1
#define WAMBLE_FRAGMENT_HASH_BLAKE2B_256 1
#define WAMBLE_FRAGMENT_WIRE_HEADER_LENGTH                                     \
  (1 + 1 + 2 + 2 + 4 + 4 + WAMBLE_FRAGMENT_HASH_LENGTH + 2)
#define WAMBLE_FRAGMENT_DATA_MAX                                               \
  (WAMBLE_MAX_PAYLOAD - WAMBLE_FRAGMENT_WIRE_HEADER_LENGTH)

static inline NetworkStatus wamble_wire_packet_size(const uint8_t *packet,
                                                    size_t packet_cap,
                                                    size_t *out_packet_len) {
  if (!packet || !out_packet_len)
    return NET_ERR_INVALID;
  if (packet_cap < WAMBLE_HEADER_WIRE_SIZE)
    return NET_ERR_TRUNCATED;
  if (packet[3] != 0)
    return NET_ERR_INVALID;
  uint16_t payload_len =
      (uint16_t)(((uint16_t)packet[WAMBLE_HEADER_WIRE_SIZE - 2] << 8) |
                 packet[WAMBLE_HEADER_WIRE_SIZE - 1]);
  if (payload_len > WAMBLE_MAX_PAYLOAD)
    return NET_ERR_INVALID;
  size_t total = WAMBLE_HEADER_WIRE_SIZE + (size_t)payload_len;
  if (total > packet_cap)
    return NET_ERR_TRUNCATED;
  *out_packet_len = total;
  return NET_OK;
}

struct WambleMove;

typedef struct {
  DbStatus status;
  char fen[FEN_MAX_LENGTH];
  char status_text[STATUS_MAX_LENGTH];
  time_t created_at;
  time_t last_assignment_time;
  time_t last_move_time;
  time_t reservation_time;
  char last_mover_treatment_group[128];
  bool reserved_for_white;
  int mode_variant_id;
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

typedef struct {
  uint64_t id;
  uint64_t board_id;
  uint64_t parent_prediction_id;
  uint8_t player_token[TOKEN_LENGTH];
  char predicted_move_uci[MAX_UCI_LENGTH];
  char status[STATUS_MAX_LENGTH];
  int move_number;
  int depth;
  int correct_streak;
  double points_awarded;
  time_t created_at;
} DbPredictionRow;

typedef struct {
  DbStatus status;
  const DbPredictionRow *rows;
  int count;
} DbPredictionsResult;

typedef struct {
  uint32_t rank;
  uint64_t session_id;
  double score;
  double rating;
  uint32_t games_played;
} DbLeaderboardEntry;

typedef struct {
  DbStatus status;
  const DbLeaderboardEntry *rows;
  int count;
  uint32_t self_rank;
} DbLeaderboardResult;

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
#define WAMBLE_CTRL_LOGIN_CHALLENGE 0x0E
#define WAMBLE_CTRL_LOGOUT 0x0F
#define WAMBLE_CTRL_LOGIN_SUCCESS 0x10
#define WAMBLE_CTRL_LOGIN_FAILED 0x11
#define WAMBLE_CTRL_GET_PLAYER_STATS 0x12
#define WAMBLE_CTRL_PLAYER_STATS_DATA 0x13

#define WAMBLE_CTRL_GET_PROFILE_INFO 0x14
#define WAMBLE_CTRL_PROFILES_LIST 0x15

#define WAMBLE_CTRL_SPECTATE_STOP 0x16

#define WAMBLE_CTRL_GET_LEGAL_MOVES 0x17
#define WAMBLE_CTRL_LEGAL_MOVES 0x18
#define WAMBLE_CTRL_GET_LEADERBOARD 0x19
#define WAMBLE_CTRL_LEADERBOARD_DATA 0x1A
#define WAMBLE_CTRL_SUBMIT_PREDICTION 0x1B
#define WAMBLE_CTRL_GET_PREDICTIONS 0x1C
#define WAMBLE_CTRL_PREDICTION_DATA 0x1D

#define WAMBLE_CTRL_GET_PROFILE_TOS 0x1E
#define WAMBLE_CTRL_PROFILE_TOS_DATA 0x1F

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
  char prev_castling[9];
  int prev_halfmove_clock;
  int prev_fullmove_number;
  int moving_piece_color;
  int is_castling;
  int castle_rook_from;
  int castle_rook_to;
  int castle_king_to;
} MoveInfo;

typedef enum {
  GAME_MODE_STANDARD = 0,
  GAME_MODE_CHESS960,
} GameMode;

static inline const char *game_mode_to_str(GameMode mode) {
  return (mode == GAME_MODE_CHESS960) ? "chess960" : "standard";
}

static inline GameMode game_mode_from_str(const char *s) {
  if (s && s[0] == 'c')
    return GAME_MODE_CHESS960;
  return GAME_MODE_STANDARD;
}

typedef struct {
  Bitboard pieces[12];
  Bitboard occupied[2];
  char turn;
  char castling[9];
  char en_passant[3];
  int halfmove_clock;
  int fullmove_number;
  GameMode game_mode;
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
#define WAMBLE_ERR_ACCESS_DENIED 1001

#define WAMBLE_FLAG_UNRELIABLE 0x80
#define WAMBLE_FLAG_BOARD_IS_960 0x01
#define WAMBLE_FLAG_MODE_FILTER_CHESS960 0x02
#define WAMBLE_FLAG_MODE_FILTER_STANDARD 0x04

static inline size_t wamble_build_login_signature_message(
    uint8_t *out, size_t out_size, const uint8_t token[TOKEN_LENGTH],
    const uint8_t public_key[WAMBLE_PUBLIC_KEY_LENGTH],
    const uint8_t challenge[WAMBLE_LOGIN_CHALLENGE_LENGTH]) {
  static const uint8_t context[] = "wamble.login.v1";
  size_t context_len = sizeof(context) - 1;
  size_t need = context_len + 1 + TOKEN_LENGTH + WAMBLE_PUBLIC_KEY_LENGTH +
                WAMBLE_LOGIN_CHALLENGE_LENGTH;
  if (!out || !token || !public_key || !challenge || out_size < need)
    return 0;
  size_t off = 0;
  memcpy(out + off, context, context_len);
  off += context_len;
  out[off++] = (uint8_t)WAMBLE_PROTO_VERSION;
  memcpy(out + off, token, TOKEN_LENGTH);
  off += TOKEN_LENGTH;
  memcpy(out + off, public_key, WAMBLE_PUBLIC_KEY_LENGTH);
  off += WAMBLE_PUBLIC_KEY_LENGTH;
  memcpy(out + off, challenge, WAMBLE_LOGIN_CHALLENGE_LENGTH);
  off += WAMBLE_LOGIN_CHALLENGE_LENGTH;
  return off;
}

#define WAMBLE_MAX_LEGAL_MOVES 218
#define WAMBLE_MAX_LEADERBOARD_ENTRIES 16
#define WAMBLE_MAX_PREDICTION_ENTRIES 16
#define WAMBLE_LEADERBOARD_SCORE 1
#define WAMBLE_LEADERBOARD_RATING 2
#define WAMBLE_PREDICTION_STATUS_PENDING 0
#define WAMBLE_PREDICTION_STATUS_CORRECT 1
#define WAMBLE_PREDICTION_STATUS_INCORRECT 2
#define WAMBLE_PREDICTION_STATUS_EXPIRED 3

typedef struct {
  uint8_t from;
  uint8_t to;
  int8_t promotion;
} WambleNetMove;

typedef struct {
  uint32_t rank;
  uint64_t session_id;
  double score;
  double rating;
  uint32_t games_played;
} WambleLeaderboardEntry;

typedef struct {
  uint64_t id;
  uint64_t parent_id;
  uint8_t token[TOKEN_LENGTH];
  double points_awarded;
  uint16_t target_ply;
  uint8_t depth;
  uint8_t status;
  uint8_t uci_len;
  char uci[MAX_UCI_LENGTH];
} WamblePredictionEntry;

struct WambleMsg {
  uint8_t ctrl;
  uint8_t flags;
  uint8_t header_version;
  uint8_t token[TOKEN_LENGTH];
  uint64_t board_id;
  uint32_t seq_num;
  uint8_t uci_len;
  char uci[MAX_UCI_LENGTH];
  uint8_t profile_name_len;
  char profile_name[PROFILE_NAME_MAX_LENGTH];
  uint16_t profile_info_len;
  char profile_info[FEN_MAX_LENGTH];
  uint8_t fragment_version;
  uint8_t fragment_hash_algo;
  uint16_t fragment_chunk_index;
  uint16_t fragment_chunk_count;
  uint32_t fragment_total_len;
  uint32_t fragment_transfer_id;
  uint8_t fragment_hash[WAMBLE_FRAGMENT_HASH_LENGTH];
  uint16_t fragment_data_len;
  uint8_t fragment_data[WAMBLE_FRAGMENT_DATA_MAX];
  uint16_t profiles_list_len;
  char profiles_list[FEN_MAX_LENGTH];
  char fen[FEN_MAX_LENGTH];
  uint16_t error_code;
  char error_reason[FEN_MAX_LENGTH];
  uint8_t login_pubkey[WAMBLE_PUBLIC_KEY_LENGTH];
  uint8_t login_signature[WAMBLE_LOGIN_SIGNATURE_LENGTH];
  uint8_t login_challenge[WAMBLE_LOGIN_CHALLENGE_LENGTH];
  uint8_t login_has_signature;
  double player_stats_score;
  uint32_t player_stats_games_played;
  uint32_t player_stats_chess960_games_played;
  uint8_t move_square;
  uint8_t move_count;
  WambleNetMove moves[WAMBLE_MAX_LEGAL_MOVES];
  uint8_t leaderboard_type;
  uint8_t leaderboard_limit;
  uint8_t leaderboard_count;
  uint32_t leaderboard_self_rank;
  WambleLeaderboardEntry leaderboard[WAMBLE_MAX_LEADERBOARD_ENTRIES];
  uint64_t prediction_parent_id;
  uint8_t prediction_depth;
  uint8_t prediction_limit;
  uint8_t prediction_count;
  WamblePredictionEntry predictions[WAMBLE_MAX_PREDICTION_ENTRIES];
};

#define WAMBLE_DUP_WINDOW 1024

typedef enum {
  WAMBLE_FRAGMENT_INTEGRITY_UNKNOWN = 0,
  WAMBLE_FRAGMENT_INTEGRITY_OK = 1,
  WAMBLE_FRAGMENT_INTEGRITY_MISMATCH = 2,
} WambleFragmentIntegrity;

typedef enum {
  WAMBLE_FRAGMENT_REASSEMBLY_ERR_INVALID = -2,
  WAMBLE_FRAGMENT_REASSEMBLY_ERR_NOMEM = -1,
  WAMBLE_FRAGMENT_REASSEMBLY_IGNORED = 0,
  WAMBLE_FRAGMENT_REASSEMBLY_IN_PROGRESS = 1,
  WAMBLE_FRAGMENT_REASSEMBLY_COMPLETE = 2,
  WAMBLE_FRAGMENT_REASSEMBLY_COMPLETE_BAD_HASH = 3,
} WambleFragmentReassemblyResult;

typedef struct WambleFragmentReassembly {
  uint8_t active;
  uint8_t ctrl;
  uint8_t hash_algo;
  uint16_t chunk_count;
  uint16_t received_chunks;
  uint32_t total_len;
  uint32_t transfer_id;
  uint8_t expected_hash[WAMBLE_FRAGMENT_HASH_LENGTH];
  WambleFragmentIntegrity integrity;
  uint8_t *data;
  size_t data_capacity;
  uint8_t *chunk_seen;
  size_t chunk_seen_capacity;
} WambleFragmentReassembly;

typedef struct WamblePlayer {
  uint8_t token[TOKEN_LENGTH];
  uint8_t public_key[WAMBLE_PUBLIC_KEY_LENGTH];
  bool has_persistent_identity;
  time_t last_seen_time;
  double score;
  double prediction_score;
  double rating;
  int games_played;
  int chess960_games_played;
} WamblePlayer;

typedef struct WamblePersistentPlayerStats {
  double score;
  double prediction_score;
  double rating;
  int games_played;
  int chess960_games_played;
} WamblePersistentPlayerStats;

typedef union {
  int chess960_position_id;
} WambleModeParams;

typedef struct WambleBoard {
  char fen[FEN_MAX_LENGTH];
  Board board;
  uint64_t id;
  BoardState state;
  GameResult result;
  time_t last_move_time;
  time_t creation_time;
  time_t last_assignment_time;
  char last_mover_treatment_group[128];
  uint8_t reservation_player_token[TOKEN_LENGTH];
  bool reserved_for_white;
  time_t reservation_time;
  WambleModeParams mode_params;
} WambleBoard;

static inline double
wamble_treatment_action_number(const WambleTreatmentAction *action, int *ok) {
  if (ok)
    *ok = 0;
  if (!action)
    return 0.0;
  if (action->value_type == WAMBLE_TREATMENT_VALUE_INT) {
    if (ok)
      *ok = 1;
    return (double)action->int_value;
  }
  if (action->value_type == WAMBLE_TREATMENT_VALUE_DOUBLE) {
    if (ok)
      *ok = 1;
    return action->double_value;
  }
  return 0.0;
}

static inline int wamble_collect_board_treatment_facts(const WambleBoard *board,
                                                       WambleFact *facts,
                                                       int max_facts) {
  int fact_count = 0;
  if (!board || !facts || max_facts <= 0)
    return 0;
  if (fact_count < max_facts) {
    snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
             "board.id");
    facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_INT;
    facts[fact_count].int_value = (int64_t)board->id;
    fact_count++;
  }
  if (fact_count < max_facts) {
    snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
             "board.fen");
    facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_STRING;
    snprintf(facts[fact_count].string_value,
             sizeof(facts[fact_count].string_value), "%s", board->fen);
    fact_count++;
  }
  if (fact_count < max_facts) {
    snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
             "board.move_count");
    facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_INT;
    facts[fact_count].int_value = board->board.fullmove_number;
    fact_count++;
  }
  if (fact_count < max_facts) {
    snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
             "board.is_chess960");
    facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_BOOL;
    facts[fact_count].bool_value =
        (board->board.game_mode == GAME_MODE_CHESS960) ? 1 : 0;
    fact_count++;
  }
  if (fact_count < max_facts) {
    snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
             "board.chess960_position_id");
    facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_INT;
    facts[fact_count].int_value =
        (int64_t)board->mode_params.chess960_position_id;
    fact_count++;
  }
  return fact_count;
}

int validate_and_apply_move_status(WambleBoard *wamble_board,
                                   WamblePlayer *player, const char *uci_move,
                                   MoveApplyStatus *out_status);

int get_legal_moves_for_square(const Board *board, int square, Move *moves,
                               int max_moves);

int parse_fen_to_bitboard(const char *fen, Board *board);
int chess960_gen_fen(int pos, char *buf, size_t buf_size);

static inline void wamble_strip_fen_history(const char *fen, char *out,
                                            size_t out_size) {
  if (!out || out_size == 0)
    return;
  out[0] = '\0';
  if (!fen || !fen[0])
    return;
  int spaces = 0;
  size_t i = 0;
  while (fen[i] && i < out_size - 1) {
    if (fen[i] == ' ') {
      spaces++;
      if (spaces == 2)
        break;
    }
    out[i] = fen[i];
    i++;
  }
  out[i] = '\0';
}

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

typedef struct WamblePrediction {
  uint64_t id;
  uint64_t board_id;
  uint64_t parent_id;
  uint8_t player_token[TOKEN_LENGTH];
  char predicted_move_uci[MAX_UCI_LENGTH];
  char status[STATUS_MAX_LENGTH];
  int target_ply;
  int depth;
  int correct_streak;
  double points_awarded;
  time_t created_at;
} WamblePrediction;

typedef struct WamblePredictionView {
  uint64_t id;
  uint64_t parent_id;
  uint64_t board_id;
  uint8_t player_token[TOKEN_LENGTH];
  char predicted_move_uci[MAX_UCI_LENGTH];
  char status[STATUS_MAX_LENGTH];
  int target_ply;
  int depth;
  double points_awarded;
  time_t created_at;
} WamblePredictionView;

void board_manager_init(void);
void board_manager_tick(void);
WambleBoard *find_board_for_player(WamblePlayer *player);
void board_move_played(uint64_t board_id);
void board_game_completed(uint64_t board_id, GameResult result);
bool board_is_reserved_for_player(uint64_t board_id,
                                  const uint8_t *player_token);
void board_release_reservation(uint64_t board_id);
void update_player_ratings(WambleBoard *board);
WambleBoard *get_board_by_id(uint64_t board_id);
int board_manager_export(WambleBoard *out, int max, int *out_count,
                         uint64_t *out_next_id);
int board_manager_import(const WambleBoard *in, int count, uint64_t next_id);

ScoringStatus calculate_and_distribute_pot(uint64_t board_id);
int scoring_apply_prediction_points(const uint8_t *token, double points);

void player_manager_init(void);
WamblePlayer *create_new_player(void);
WamblePlayer *attach_persistent_identity(const uint8_t *token,
                                         const uint8_t *public_key);
int detach_persistent_identity(const uint8_t *token);
void format_token_for_url(const uint8_t *token, char *url_buffer);
int decode_token_from_url(const char *url_string, uint8_t *token_buffer);
void player_manager_tick(void);

WamblePlayer *get_player_by_token(const uint8_t *token);
void discard_player_by_token(const uint8_t *token);
void network_init_thread_state(void);
int network_get_session_treatment_group(const uint8_t *token, char *out_group,
                                        size_t out_group_size);

void cleanup_expired_sessions(void);

void rng_init(void);
void rng_bytes(uint8_t *out, size_t len);
double rng_double(void);
int wamble_ed25519_verify(const uint8_t *signature, const uint8_t *public_key,
                          const uint8_t *message, size_t message_size);

PredictionManagerStatus prediction_manager_init(void);
PredictionStatus prediction_submit(WambleBoard *board,
                                   const uint8_t *player_token,
                                   const char *predicted_move_uci,
                                   int trust_tier);
PredictionStatus prediction_submit_with_parent(WambleBoard *board,
                                               const uint8_t *player_token,
                                               const char *predicted_move_uci,
                                               uint64_t parent_prediction_id,
                                               int trust_tier,
                                               uint64_t *out_prediction_id);
PredictionStatus prediction_resolve_move(WambleBoard *board,
                                         const char *actual_move_uci);
PredictionStatus prediction_collect_tree(uint64_t board_id,
                                         const uint8_t *requester_token,
                                         int trust_tier, int max_depth,
                                         WamblePredictionView *out, int max_out,
                                         int *out_count);
void prediction_expire_board(uint64_t board_id);

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
                                    int timeout_seconds,
                                    bool reserved_for_white);
void wamble_emit_remove_reservation(uint64_t board_id);
void wamble_emit_record_game_result(uint64_t board_id, char winning_side,
                                    int move_count, int duration_seconds,
                                    const char *termination_reason);
void wamble_emit_update_board_move_meta(uint64_t board_id,
                                        const char *group_key);
void wamble_emit_update_board_reservation_meta(uint64_t board_id,
                                               time_t reservation_time,
                                               bool reserved_for_white);
void wamble_emit_update_session_last_seen(const uint8_t *token);
void wamble_emit_create_session(const uint8_t *token, uint64_t player_id);
void wamble_emit_link_session_to_pubkey(const uint8_t *token,
                                        const uint8_t *public_key);
void wamble_emit_unlink_session_identity(const uint8_t *token);
void wamble_emit_record_payout(uint64_t board_id, const uint8_t *token,
                               double points);
void wamble_emit_update_player_rating(const uint8_t *token, double rating);
void wamble_emit_resolve_prediction(uint64_t board_id, const uint8_t *token,
                                    int move_number, const char *status,
                                    double points_awarded);
void wamble_emit_create_board(uint64_t board_id, const char *fen,
                              const char *status, int mode_variant_id);
void wamble_emit_record_move(uint64_t board_id, const uint8_t *token,
                             const char *move_uci, int move_number);

DbBoardIdList wamble_query_list_boards_by_status(const char *status);
DbBoardResult wamble_query_get_board(uint64_t board_id);
DbMovesResult wamble_query_get_moves_for_board(uint64_t board_id);
DbPredictionsResult wamble_query_get_pending_predictions(void);
DbStatus wamble_query_get_longest_game_moves(int *out_max_moves);
DbStatus wamble_query_get_active_session_count(int *out_count);
DbStatus wamble_query_get_max_board_id(uint64_t *out_max_id);
DbStatus wamble_query_get_session_by_token(const uint8_t *token,
                                           uint64_t *out_session);
DbStatus wamble_query_create_session(const uint8_t *token, uint64_t player_id,
                                     uint64_t *out_session);
DbStatus wamble_query_create_prediction(uint64_t board_id, uint64_t session_id,
                                        uint64_t parent_prediction_id,
                                        const char *predicted_move_uci,
                                        int move_number, int correct_streak,
                                        uint64_t *out_prediction_id);
DbStatus wamble_query_get_persistent_session_by_token(const uint8_t *token,
                                                      uint64_t *out_session);
DbStatus wamble_query_get_player_total_score(uint64_t session_id,
                                             double *out_total);
DbStatus wamble_query_get_player_prediction_score(uint64_t session_id,
                                                  double *out_total);
DbStatus wamble_query_get_player_rating(uint64_t session_id,
                                        double *out_rating);
DbStatus wamble_query_get_session_games_played(uint64_t session_id,
                                               int *out_games);
DbStatus wamble_query_get_session_chess960_games_played(uint64_t session_id,
                                                        int *out_games);
DbStatus wamble_query_get_persistent_player_stats(
    const uint8_t *public_key, WamblePersistentPlayerStats *out_stats);
DbLeaderboardResult wamble_query_get_leaderboard(uint64_t requester_session_id,
                                                 uint8_t leaderboard_type,
                                                 int limit);
DbStatus
wamble_query_get_session_treatment_assignment(const uint8_t *token,
                                              WambleTreatmentAssignment *out);
DbStatus wamble_query_resolve_policy_decision(
    const uint8_t *token, const char *profile, const char *action,
    const char *resource, const char *context_key, const char *context_value,
    WamblePolicyDecision *out);
DbStatus wamble_query_resolve_treatment_actions(
    const uint8_t *token, const char *profile, const char *hook_name,
    const char *opponent_group_key, const WambleFact *facts, int fact_count,
    WambleTreatmentAction *out, int max_out, int *out_count);
int wamble_query_treatment_edge_allows(const char *profile,
                                       const char *source_group_key,
                                       const char *target_group_key);

wamble_socket_t create_and_bind_socket(int port);
int receive_message(wamble_socket_t sockfd, struct WambleMsg *msg,
                    struct sockaddr_in *cliaddr);
void wamble_fragment_reassembly_init(WambleFragmentReassembly *reassembly);
void wamble_fragment_reassembly_reset(WambleFragmentReassembly *reassembly);
void wamble_fragment_reassembly_free(WambleFragmentReassembly *reassembly);
WambleFragmentReassemblyResult
wamble_fragment_reassembly_push(WambleFragmentReassembly *reassembly,
                                const struct WambleMsg *msg);
void send_ack(wamble_socket_t sockfd, const struct WambleMsg *msg,
              const struct sockaddr_in *cliaddr);
int send_reliable_message(wamble_socket_t sockfd, const struct WambleMsg *msg,
                          const struct sockaddr_in *cliaddr, int timeout_ms,
                          int max_retries);
int send_unreliable_packet(wamble_socket_t sockfd, const struct WambleMsg *msg,
                           const struct sockaddr_in *cliaddr);
int wamble_socket_bound_port(wamble_socket_t sock);
ServerStatus handle_message(wamble_socket_t sockfd, const struct WambleMsg *msg,
                            const struct sockaddr_in *cliaddr, int trust_tier,
                            const char *profile_name);

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
  uint8_t flags;
} SpectatorUpdate;

SpectatorRequestStatus
spectator_handle_request(const struct WambleMsg *msg,
                         const struct sockaddr_in *cliaddr, int trust_tier,
                         int capacity_bypass, SpectatorState *out_state,
                         uint64_t *out_focus_board_id);
void spectator_discard_by_token(const uint8_t *token);

int spectator_collect_updates(struct SpectatorUpdate *out, int max);
int spectator_collect_notifications(struct SpectatorUpdate *out, int max);

static inline int tokens_equal(const uint8_t *token1, const uint8_t *token2) {
  if (!token1 || !token2)
    return token1 == token2;
  for (int i = 0; i < TOKEN_LENGTH; i++) {
    if (token1[i] != token2[i]) {
      return 0;
    }
  }
  return 1;
}

static inline uint32_t wamble_token_hash32(const uint8_t *token) {
  uint32_t h = 2166136261u;
  if (!token)
    return h;
  for (int i = 0; i < TOKEN_LENGTH; i++) {
    h ^= token[i];
    h *= 16777619u;
  }
  return h;
}

#endif
