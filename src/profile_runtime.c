#include "../include/wamble/wamble.h"
#include "../include/wamble/wamble_db.h"
#include <stdlib.h>
#include <string.h>
int receive_message_packet(const uint8_t *packet, size_t packet_len,
                           struct WambleMsg *msg,
                           const struct sockaddr_in *cliaddr);
int ws_gateway_pop_packet(WambleWsGateway *gateway, uint8_t *packet,
                          size_t packet_cap, size_t *out_packet_len,
                          struct sockaddr_in *out_cliaddr);
void ws_gateway_flush_outbound(WambleWsGateway *gateway);
#if defined(_MSC_VER) && !defined(strtoull)
#define strtoull _strtoui64
#endif
#if defined(WAMBLE_PLATFORM_POSIX)
#include <fcntl.h>
#include <unistd.h>
#endif
#if defined(WAMBLE_PLATFORM_WINDOWS)
#include <io.h>
#include <process.h>
#include <windows.h>
#endif

typedef struct RunningProfile {
  char *name;
  wamble_thread_t thread;
  wamble_socket_t sockfd;
  WambleConfig cfg;
  WambleConfig pending_cfg;
  int has_pending_cfg;
  int should_stop;
  int needs_update;
  char *state_path;
  int ready_for_exec;
  int run_inline;
  int runtime_ready;
  WambleIntentBuffer intents_buf;
  const WambleQueryService *qs;
  time_t last_cleanup;
  time_t last_tick;
  uint64_t last_flush_ms;
  uint64_t ws_next_retry_ms;
  int ws_retry_enabled;
  WambleWsGateway *ws_gateway;
} RunningProfile;

static RunningProfile *g_running = NULL;
static int g_running_count = 0;
static wamble_mutex_t g_mutex;
static int g_mutex_initialized = 0;
static int g_prepare_exec = 0;
static WAMBLE_THREAD_LOCAL char g_runtime_profile_key[128];
enum { RUNTIME_EVENT_QUEUE_CAP = 256 };
static WambleRuntimeEvent g_runtime_event_queue[RUNTIME_EVENT_QUEUE_CAP];
static int g_runtime_event_head = 0;
static int g_runtime_event_tail = 0;
static int g_runtime_event_count = 0;

static void free_running(RunningProfile *rp);
static void profile_runtime_shutdown(RunningProfile *rp);
static int profile_has_inline_runtime_locked(void);
static void profile_runtime_set_profile_key(const char *profile_name);
static int profile_runtime_enabled(const WambleProfile *p);
static char *profile_runtime_snapshot_template(const RunningProfile *rp);

static int consume_fail_next_restart_bind(void) { return 0; }
static int consume_fail_next_restart_start(void) { return 0; }

static void ensure_mutex_init(void) {
  if (!g_mutex_initialized) {
    wamble_mutex_init(&g_mutex);
    g_mutex_initialized = 1;
    g_runtime_event_head = 0;
    g_runtime_event_tail = 0;
    g_runtime_event_count = 0;
  }
}

const char *wamble_runtime_profile_key(void) {
  return g_runtime_profile_key[0] ? g_runtime_profile_key : "__default__";
}

static void profile_runtime_set_profile_key(const char *profile_name) {
  snprintf(g_runtime_profile_key, sizeof(g_runtime_profile_key), "%s",
           (profile_name && profile_name[0]) ? profile_name : "__default__");
}

void wamble_runtime_event_publish(WambleRuntimeEventKind kind, int code,
                                  const char *profile_name) {
  ensure_mutex_init();
  wamble_mutex_lock(&g_mutex);
  if (g_runtime_event_count >= RUNTIME_EVENT_QUEUE_CAP) {
    g_runtime_event_head = (g_runtime_event_head + 1) % RUNTIME_EVENT_QUEUE_CAP;
    g_runtime_event_count--;
  }
  WambleRuntimeEvent *ev = &g_runtime_event_queue[g_runtime_event_tail];
  ev->kind = kind;
  ev->code = code;
  snprintf(ev->profile, sizeof(ev->profile), "%s",
           (profile_name && profile_name[0]) ? profile_name : "default");
  g_runtime_event_tail = (g_runtime_event_tail + 1) % RUNTIME_EVENT_QUEUE_CAP;
  g_runtime_event_count++;
  wamble_mutex_unlock(&g_mutex);
}

int wamble_runtime_event_take(WambleRuntimeEvent *out_event) {
  ensure_mutex_init();
  if (out_event)
    memset(out_event, 0, sizeof(*out_event));

  wamble_mutex_lock(&g_mutex);
  if (g_runtime_event_count > 0) {
    WambleRuntimeEvent ev = g_runtime_event_queue[g_runtime_event_head];
    g_runtime_event_head = (g_runtime_event_head + 1) % RUNTIME_EVENT_QUEUE_CAP;
    g_runtime_event_count--;
    if (out_event)
      *out_event = ev;
    wamble_mutex_unlock(&g_mutex);
    return 1;
  }
  wamble_mutex_unlock(&g_mutex);
  return 0;
}

static void publish_prediction_manager_status(PredictionManagerStatus status,
                                              const char *profile_name) {
  wamble_runtime_event_publish(WAMBLE_RUNTIME_EVENT_PREDICTION_MANAGER,
                               (int)status, profile_name);
}

static void publish_ws_gateway_status(WsGatewayStatus status,
                                      const char *profile_name) {
  wamble_runtime_event_publish(WAMBLE_RUNTIME_EVENT_WS_GATEWAY, (int)status,
                               profile_name);
}

enum {
  PERSIST_FLUSH_BATCH = 128,
  PERSIST_FLUSH_INTERVAL_MS = 200,
  PERSIST_FLUSH_EAGER_COUNT = 128,
  PERSIST_FLUSH_MAX_BATCHES_PER_CYCLE = 4,
};

static int profile_runtime_batch_limit_for_pending(int pending) {
  if (pending >= PERSIST_FLUSH_BATCH * 8)
    return PERSIST_FLUSH_BATCH * 4;
  if (pending >= PERSIST_FLUSH_BATCH * 2)
    return PERSIST_FLUSH_BATCH * 2;
  return PERSIST_FLUSH_BATCH;
}

static int profile_runtime_config_max_intents(const RunningProfile *rp,
                                              int pending) {
  int cfg_limit = (rp && rp->cfg.persistence_max_intents > 0)
                      ? rp->cfg.persistence_max_intents
                      : PERSIST_FLUSH_BATCH;
  int adaptive = profile_runtime_batch_limit_for_pending(pending);
  return (cfg_limit < adaptive) ? cfg_limit : adaptive;
}

static int profile_runtime_config_max_payload_bytes(const RunningProfile *rp) {
  if (rp && rp->cfg.persistence_max_payload_bytes > 0)
    return rp->cfg.persistence_max_payload_bytes;
  return 64 * 1024;
}

static int profile_runtime_flush_intents(RunningProfile *rp, int max_batches) {
  if (!rp || max_batches <= 0)
    return 1;
  wamble_set_query_service(rp->qs);
  wamble_set_intent_buffer(&rp->intents_buf);
  uint64_t now_ms = wamble_now_mono_millis();
  for (int i = 0; i < max_batches; i++) {
    int attempted = 0;
    int failures = 0;
    int batch_limit =
        profile_runtime_config_max_intents(rp, rp->intents_buf.count);
    int payload_limit = profile_runtime_config_max_payload_bytes(rp);
    wamble_persistence_clear_status();
    PersistenceStatus st = wamble_apply_intents_with_db_checked(
        &rp->intents_buf, batch_limit, payload_limit, NULL, &attempted,
        &failures);
    int pending = rp->intents_buf.count;
    rp->last_flush_ms = now_ms;
    if (pending <= 0)
      return 1;
    if (st == PERSISTENCE_STATUS_OK || st == PERSISTENCE_STATUS_EMPTY) {
      if (pending <= 0 || attempted <= 0)
        break;
      continue;
    }
    if (attempted <= 0 || st == PERSISTENCE_STATUS_APPLY_FAIL)
      break;
  }
  return rp->intents_buf.count <= 0;
}

static char *wamble_strndup_local(const char *src, size_t len) {
  char *out = (char *)malloc(len + 1);
  if (!out)
    return NULL;
  memcpy(out, src, len);
  out[len] = '\0';
  return out;
}

static char *wamble_strdup_local(const char *src) {
  if (!src)
    return NULL;
  size_t len = strlen(src);
  return wamble_strndup_local(src, len);
}

typedef int (*EnvMapCallback)(const char *key, const char *value, void *ctx);

static int parse_env_map(const char *map, EnvMapCallback cb, void *ctx) {
  if (!map || !*map)
    return 0;
  const char *cursor = map;
  while (*cursor) {
    const char *next = strchr(cursor, ',');
    size_t seg_len = next ? (size_t)(next - cursor) : strlen(cursor);
    const char *eq = memchr(cursor, '=', seg_len);
    if (eq && eq > cursor && (size_t)(eq - cursor) < seg_len - 1) {
      size_t key_len = (size_t)(eq - cursor);
      size_t value_len = seg_len - key_len - 1;
      char *key = wamble_strndup_local(cursor, key_len);
      char *val = wamble_strndup_local(eq + 1, value_len);
      if (!key || !val) {
        free(key);
        free(val);
        return -1;
      }
      int stop = cb(key, val, ctx);
      free(key);
      free(val);
      if (stop != 0)
        return stop;
    }
    if (!next)
      break;
    cursor = next + 1;
  }
  return 0;
}

typedef struct {
  const char *key;
  char *result;
} FindCtx;

static int find_value_cb(const char *key, const char *value, void *opaque) {
  FindCtx *ctx = (FindCtx *)opaque;
  if (strcmp(key, ctx->key) == 0) {
    ctx->result = wamble_strdup_local(value);
    return 1;
  }
  return 0;
}

static char *find_value_in_map(const char *map, const char *target_key) {
  if (!map || !target_key)
    return NULL;
  FindCtx ctx = {target_key, NULL};
  parse_env_map(map, find_value_cb, &ctx);
  return ctx.result;
}

typedef struct {
  const char *state_map;
  int capacity;
  ProfileStartStatus status;
} AdoptEnvContext;

static void *profile_thread_main(void *arg);
static void free_running(RunningProfile *rp);
static int copy_profile_config_for_runtime(RunningProfile *rp,
                                           const WambleProfile *p);
static int copy_default_config_for_runtime(RunningProfile *rp);

static void runtime_cfg_free_owned(WambleConfig *cfg) {
  if (!cfg)
    return;
  free(cfg->db_host);
  free(cfg->db_user);
  free(cfg->db_pass);
  free(cfg->db_name);
  free(cfg->global_db_host);
  free(cfg->global_db_user);
  free(cfg->global_db_pass);
  free(cfg->global_db_name);
  free(cfg->prediction_match_policy);
  free(cfg->spectator_summary_mode);
  free(cfg->state_dir);
  free(cfg->websocket_path);
  cfg->db_host = NULL;
  cfg->db_user = NULL;
  cfg->db_pass = NULL;
  cfg->db_name = NULL;
  cfg->global_db_host = NULL;
  cfg->global_db_user = NULL;
  cfg->global_db_pass = NULL;
  cfg->global_db_name = NULL;
  cfg->prediction_match_policy = NULL;
  cfg->spectator_summary_mode = NULL;
  cfg->state_dir = NULL;
  cfg->websocket_path = NULL;
}

static int runtime_cfg_dup_from(WambleConfig *dst, const WambleConfig *src) {
  if (!dst || !src)
    return -1;
  memset(dst, 0, sizeof(*dst));
  *dst = *src;
  dst->db_host = wamble_strdup_local(src->db_host);
  dst->db_user = wamble_strdup_local(src->db_user);
  dst->db_pass = wamble_strdup_local(src->db_pass);
  dst->db_name = wamble_strdup_local(src->db_name);
  dst->global_db_host = wamble_strdup_local(src->global_db_host);
  dst->global_db_user = wamble_strdup_local(src->global_db_user);
  dst->global_db_pass = wamble_strdup_local(src->global_db_pass);
  dst->global_db_name = wamble_strdup_local(src->global_db_name);
  dst->prediction_match_policy =
      wamble_strdup_local(src->prediction_match_policy);
  dst->spectator_summary_mode =
      wamble_strdup_local(src->spectator_summary_mode);
  dst->state_dir = wamble_strdup_local(src->state_dir);
  dst->websocket_path = wamble_strdup_local(src->websocket_path);
  if (!dst->db_host || !dst->db_user || !dst->db_pass || !dst->db_name ||
      !dst->global_db_host || !dst->global_db_user || !dst->global_db_pass ||
      !dst->global_db_name ||
      (src->prediction_match_policy && !dst->prediction_match_policy) ||
      (src->spectator_summary_mode && !dst->spectator_summary_mode) ||
      (src->state_dir && !dst->state_dir) || !dst->websocket_path) {
    runtime_cfg_free_owned(dst);
    return -1;
  }
  return 0;
}

static int adopt_profile_from_env(const char *name, const char *value,
                                  void *opaque) {
  AdoptEnvContext *ctx = (AdoptEnvContext *)opaque;
  if (!ctx || ctx->status != PROFILE_START_OK)
    return 0;
  if (g_running_count >= ctx->capacity)
    return 0;

  char *endptr = NULL;
  unsigned long long handle = strtoull(value, &endptr, 10);
  if (!value || value[0] == '\0' || (endptr && *endptr != '\0'))
    return 0;

  wamble_socket_t sock = (wamble_socket_t)handle;
  if (sock == WAMBLE_INVALID_SOCKET)
    return 0;

  RunningProfile *rp = &g_running[g_running_count];
  int is_default_runtime =
      (strcmp(name, WAMBLE_DEFAULT_RUNTIME_EXPORT_NAME) == 0);
  if (is_default_runtime) {
    if (copy_default_config_for_runtime(rp) != 0) {
      free_running(rp);
      ctx->status = PROFILE_START_THREAD_ERROR;
      return 1;
    }
  } else {
    const WambleProfile *p = config_find_profile(name);
    if (!p || !profile_runtime_enabled(p))
      return 0;
    if (copy_profile_config_for_runtime(rp, p) != 0) {
      free_running(rp);
      ctx->status = PROFILE_START_THREAD_ERROR;
      return 1;
    }
  }

  rp->sockfd = sock;
  rp->should_stop = 0;
  rp->needs_update = 0;
  rp->state_path = find_value_in_map(ctx->state_map, name);
  rp->ready_for_exec = 0;

  int buffer_size = rp->cfg.buffer_size;
  (void)setsockopt(rp->sockfd, SOL_SOCKET, SO_RCVBUF,
                   (const char *)&buffer_size, sizeof(buffer_size));
  (void)setsockopt(rp->sockfd, SOL_SOCKET, SO_SNDBUF,
                   (const char *)&buffer_size, sizeof(buffer_size));
  (void)wamble_set_nonblocking(rp->sockfd);

  rp->run_inline = (ctx->capacity == 1) ? 1 : 0;
  rp->thread = 0;
  if (!rp->run_inline) {
    if (wamble_thread_create(&rp->thread, profile_thread_main, rp) != 0) {
      wamble_close_socket(rp->sockfd);
      rp->sockfd = WAMBLE_INVALID_SOCKET;
      free_running(rp);
      ctx->status = PROFILE_START_THREAD_ERROR;
      return 1;
    }
  }

  g_running_count++;
  return 0;
}

static void detach_running_profiles(RunningProfile **out_profiles,
                                    int *out_count) {
  ensure_mutex_init();
  wamble_mutex_lock(&g_mutex);
  RunningProfile *profiles = g_running;
  int count = g_running_count;
  if (profiles) {
    for (int i = 0; i < count; i++) {
      profiles[i].should_stop = 1;
    }
  }
  g_running = NULL;
  g_running_count = 0;
  g_prepare_exec = 0;
  wamble_mutex_unlock(&g_mutex);
  if (out_profiles)
    *out_profiles = profiles;
  else if (profiles)
    free(profiles);
  if (out_count)
    *out_count = count;
}

static void join_and_cleanup_profiles(RunningProfile *profiles, int count,
                                      int close_sockets) {
  if (!profiles)
    return;
  if (count <= 0) {
    free(profiles);
    return;
  }
  for (int i = 0; i < count; i++) {
    if (profiles[i].thread)
      wamble_thread_join(profiles[i].thread, NULL);
    else if (profiles[i].run_inline)
      profile_runtime_shutdown(&profiles[i]);
    if (close_sockets && profiles[i].sockfd != WAMBLE_INVALID_SOCKET) {
      wamble_close_socket(profiles[i].sockfd);
      profiles[i].sockfd = WAMBLE_INVALID_SOCKET;
    }
    free_running(&profiles[i]);
  }
  free(profiles);
}

static int db_same(const WambleConfig *a, const WambleConfig *b) {
  return strcmp(a->db_host, b->db_host) == 0 &&
         strcmp(a->db_user, b->db_user) == 0 &&
         strcmp(a->db_name, b->db_name) == 0;
}

static int cfg_str_eq(const char *a, const char *b) {
  const char *lhs = a ? a : "";
  const char *rhs = b ? b : "";
  return strcmp(lhs, rhs) == 0;
}

typedef struct Prebound {
  int profile_index;
  wamble_socket_t sockfd;
} Prebound;

typedef struct RestartSpec {
  char *name;
  WambleConfig cfg;
} RestartSpec;

static void close_prebound_entries(Prebound *pb, int start, int count) {
  if (!pb)
    return;
  if (start < 0)
    start = 0;
  for (int i = start; i < count; i++) {
    if (pb[i].sockfd != WAMBLE_INVALID_SOCKET) {
      wamble_close_socket(pb[i].sockfd);
      pb[i].sockfd = WAMBLE_INVALID_SOCKET;
    }
  }
}

static void mark_profiles_stop(RunningProfile *profiles, int count) {
  if (!profiles || count <= 0)
    return;
  for (int i = 0; i < count; i++) {
    profiles[i].should_stop = 1;
  }
}

static int copy_named_config_for_runtime(RunningProfile *rp, const char *name,
                                         const WambleConfig *cfg) {
  if (!rp || !cfg)
    return -1;
  memset(rp, 0, sizeof(*rp));
  if (name) {
    rp->name = wamble_strdup(name);
    if (!rp->name)
      return -1;
  }
  if (runtime_cfg_dup_from(&rp->cfg, cfg) != 0) {
    free(rp->name);
    rp->name = NULL;
    return -1;
  }
  return 0;
}

static int copy_profile_config_for_runtime(RunningProfile *rp,
                                           const WambleProfile *p) {
  if (!rp || !p || !p->name)
    return -1;
  return copy_named_config_for_runtime(rp, p->name, &p->config);
}

static int copy_default_config_for_runtime(RunningProfile *rp) {
  if (!rp)
    return -1;
  return copy_named_config_for_runtime(rp, NULL, get_config());
}

static void free_restart_specs(RestartSpec *specs, int count) {
  if (!specs)
    return;
  for (int i = 0; i < count; i++) {
    free(specs[i].name);
    runtime_cfg_free_owned(&specs[i].cfg);
  }
  free(specs);
}

static int snapshot_restart_specs_from_running(const RunningProfile *running,
                                               int count,
                                               RestartSpec **out_specs) {
  if (out_specs)
    *out_specs = NULL;
  if (!running || count <= 0)
    return 0;

  RestartSpec *specs = calloc((size_t)count, sizeof(*specs));
  if (!specs)
    return -1;
  for (int i = 0; i < count; i++) {
    if (running[i].name) {
      specs[i].name = wamble_strdup(running[i].name);
      if (!specs[i].name) {
        free_restart_specs(specs, count);
        return -1;
      }
    }
    if (runtime_cfg_dup_from(&specs[i].cfg, &running[i].cfg) != 0) {
      free_restart_specs(specs, count);
      return -1;
    }
  }
  if (out_specs)
    *out_specs = specs;
  return 0;
}

static wamble_socket_t create_prebound_socket(const WambleConfig *cfg,
                                              ProfileStartStatus *out_status) {
  if (!cfg) {
    if (out_status)
      *out_status = PROFILE_START_SOCKET_ERROR;
    return WAMBLE_INVALID_SOCKET;
  }
  if (consume_fail_next_restart_bind()) {
    if (out_status)
      *out_status = PROFILE_START_BIND_ERROR;
    return WAMBLE_INVALID_SOCKET;
  }
  wamble_socket_t sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd == WAMBLE_INVALID_SOCKET) {
    if (out_status)
      *out_status = PROFILE_START_SOCKET_ERROR;
    return WAMBLE_INVALID_SOCKET;
  }
  int optval = 1;
  (void)setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&optval,
                   sizeof(optval));
  int buffer_size = cfg->buffer_size;
  (void)setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (const char *)&buffer_size,
                   sizeof(buffer_size));
  (void)setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const char *)&buffer_size,
                   sizeof(buffer_size));

  struct sockaddr_in servaddr;
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = INADDR_ANY;
  servaddr.sin_port = htons((uint16_t)cfg->port);
  if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
    wamble_close_socket(sockfd);
    if (out_status)
      *out_status = PROFILE_START_BIND_ERROR;
    return WAMBLE_INVALID_SOCKET;
  }
  (void)wamble_set_nonblocking(sockfd);
  if (out_status)
    *out_status = PROFILE_START_OK;
  return sockfd;
}

static ProfileStartStatus start_running_slot(RunningProfile *rp, Prebound *pb,
                                             int i, int count,
                                             int inline_single_ok);

static ProfileStartStatus start_running_from_prebound(Prebound *pb, int count,
                                                      RunningProfile **out_run,
                                                      int *out_count,
                                                      int inline_single_ok) {
  if (out_run)
    *out_run = NULL;
  if (out_count)
    *out_count = 0;
  if (!pb || count <= 0)
    return PROFILE_START_OK;

  RunningProfile *running = calloc((size_t)count, sizeof(RunningProfile));
  if (!running)
    return PROFILE_START_THREAD_ERROR;

  for (int i = 0; i < count; i++) {
    running[i].sockfd = WAMBLE_INVALID_SOCKET;
    running[i].thread = 0;
  }

  for (int i = 0; i < count; i++) {
    const WambleProfile *p = config_get_profile(pb[i].profile_index);
    RunningProfile *rp = &running[i];
    if (!p || copy_profile_config_for_runtime(rp, p) != 0) {
      close_prebound_entries(pb, i, count);
      join_and_cleanup_profiles(running, count, 1);
      return PROFILE_START_THREAD_ERROR;
    }

    ProfileStartStatus slot_st =
        start_running_slot(rp, pb, i, count, inline_single_ok);
    if (slot_st != PROFILE_START_OK) {
      close_prebound_entries(pb, i + 1, count);
      if (slot_st == PROFILE_START_THREAD_ERROR)
        mark_profiles_stop(running, i);
      join_and_cleanup_profiles(running, count, 1);
      return slot_st;
    }
  }

  if (out_run)
    *out_run = running;
  if (out_count)
    *out_count = count;
  return PROFILE_START_OK;
}

static ProfileStartStatus start_running_slot(RunningProfile *rp, Prebound *pb,
                                             int i, int count,
                                             int inline_single_ok) {
  if (!rp || !pb || i < 0 || count <= 0)
    return PROFILE_START_THREAD_ERROR;

  rp->sockfd = pb[i].sockfd;
  pb[i].sockfd = WAMBLE_INVALID_SOCKET;
  rp->should_stop = 0;
  rp->needs_update = 0;
  rp->state_path = NULL;
  rp->ready_for_exec = 0;

  if (rp->sockfd == WAMBLE_INVALID_SOCKET)
    return PROFILE_START_NO_SOCKET;
  if (consume_fail_next_restart_start())
    return PROFILE_START_THREAD_ERROR;

  rp->run_inline = (inline_single_ok && count == 1) ? 1 : 0;
  rp->thread = 0;
  if (!rp->run_inline &&
      wamble_thread_create(&rp->thread, profile_thread_main, rp) != 0) {
    return PROFILE_START_THREAD_ERROR;
  }
  return PROFILE_START_OK;
}

static ProfileStartStatus
start_running_from_restart_specs(Prebound *pb, const RestartSpec *specs,
                                 int count, RunningProfile **out_run,
                                 int *out_count, int inline_single_ok) {
  if (out_run)
    *out_run = NULL;
  if (out_count)
    *out_count = 0;
  if (!pb || !specs || count <= 0)
    return PROFILE_START_OK;

  RunningProfile *running = calloc((size_t)count, sizeof(RunningProfile));
  if (!running)
    return PROFILE_START_THREAD_ERROR;

  for (int i = 0; i < count; i++) {
    running[i].sockfd = WAMBLE_INVALID_SOCKET;
    running[i].thread = 0;
  }

  for (int i = 0; i < count; i++) {
    RunningProfile *rp = &running[i];
    if (copy_named_config_for_runtime(rp, specs[i].name, &specs[i].cfg) != 0) {
      close_prebound_entries(pb, i, count);
      join_and_cleanup_profiles(running, count, 1);
      return PROFILE_START_THREAD_ERROR;
    }

    ProfileStartStatus slot_st =
        start_running_slot(rp, pb, i, count, inline_single_ok);
    if (slot_st != PROFILE_START_OK) {
      close_prebound_entries(pb, i + 1, count);
      if (slot_st == PROFILE_START_THREAD_ERROR)
        mark_profiles_stop(running, i);
      join_and_cleanup_profiles(running, count, 1);
      return slot_st;
    }
  }

  if (out_run)
    *out_run = running;
  if (out_count)
    *out_count = count;
  return PROFILE_START_OK;
}

static ProfileStartStatus start_default_runtime(RunningProfile **out_run,
                                                int *out_count,
                                                int inline_single_ok) {
  if (out_run)
    *out_run = NULL;
  if (out_count)
    *out_count = 0;

  RunningProfile *running = calloc(1, sizeof(RunningProfile));
  if (!running)
    return PROFILE_START_THREAD_ERROR;
  running[0].sockfd = WAMBLE_INVALID_SOCKET;

  if (copy_default_config_for_runtime(&running[0]) != 0) {
    join_and_cleanup_profiles(running, 1, 1);
    return PROFILE_START_THREAD_ERROR;
  }

  running[0].sockfd = create_and_bind_socket(running[0].cfg.port);
  if (running[0].sockfd == WAMBLE_INVALID_SOCKET) {
    join_and_cleanup_profiles(running, 1, 1);
    return PROFILE_START_NO_SOCKET;
  }
  running[0].should_stop = 0;
  running[0].needs_update = 0;
  running[0].state_path = NULL;
  running[0].ready_for_exec = 0;

  running[0].run_inline = inline_single_ok ? 1 : 0;
  running[0].thread = 0;
  if (!running[0].run_inline &&
      wamble_thread_create(&running[0].thread, profile_thread_main,
                           &running[0]) != 0) {
    join_and_cleanup_profiles(running, 1, 1);
    return PROFILE_START_THREAD_ERROR;
  }

  if (out_run)
    *out_run = running;
  if (out_count)
    *out_count = 1;
  return PROFILE_START_OK;
}

static Prebound *preflight_and_bind_all(int *out_count,
                                        ProfileStartStatus *out_status) {
  int total = config_profile_count();
  if (total <= 0) {
    if (out_count)
      *out_count = 0;
    if (out_status)
      *out_status = PROFILE_START_NONE;
    return NULL;
  }

  const WambleProfile **profiles = calloc((size_t)total, sizeof(*profiles));
  int *profile_idx = calloc((size_t)total, sizeof(*profile_idx));
  if (!profiles || !profile_idx) {
    free(profiles);
    free(profile_idx);
    if (out_status)
      *out_status = PROFILE_START_THREAD_ERROR;
    if (out_count)
      *out_count = 0;
    return NULL;
  }
  int count = 0;
  for (int i = 0; i < total; i++) {
    const WambleProfile *p = config_get_profile(i);
    if (!p || !profile_runtime_enabled(p))
      continue;
    profiles[count] = p;
    profile_idx[count] = i;
    count++;
  }

  for (int i = 0; i < count; i++) {
    const WambleProfile *pi = profiles[i];
    for (int j = i + 1; j < count; j++) {
      const WambleProfile *pj = profiles[j];
      if (pi->config.port == pj->config.port) {
        if (out_status)
          *out_status = PROFILE_START_CONFLICT;
        if (out_count)
          *out_count = 0;
        free(profiles);
        free(profile_idx);
        return NULL;
      }
      if (pi->config.websocket_enabled && pj->config.websocket_enabled) {
        int pws = (pi->config.websocket_port > 0) ? pi->config.websocket_port
                                                  : pi->config.port;
        int qws = (pj->config.websocket_port > 0) ? pj->config.websocket_port
                                                  : pj->config.port;
        if (pws == qws) {
          if (out_status)
            *out_status = PROFILE_START_CONFLICT;
          if (out_count)
            *out_count = 0;
          free(profiles);
          free(profile_idx);
          return NULL;
        }
      }
      if (pi->db_isolated && pj->db_isolated &&
          db_same(&pi->config, &pj->config)) {
        if (out_status)
          *out_status = PROFILE_START_CONFLICT;
        if (out_count)
          *out_count = 0;
        free(profiles);
        free(profile_idx);
        return NULL;
      }
    }
  }

  Prebound *pb = calloc((size_t)count, sizeof(Prebound));
  if (!pb) {
    free(profiles);
    free(profile_idx);
    if (out_status)
      *out_status = PROFILE_START_THREAD_ERROR;
    if (out_count)
      *out_count = 0;
    return NULL;
  }
  int pb_count = 0;
  for (int i = 0; i < count; i++) {
    const WambleProfile *p = profiles[i];
    ProfileStartStatus socket_status = PROFILE_START_OK;
    wamble_socket_t sockfd = create_prebound_socket(&p->config, &socket_status);
    if (sockfd == WAMBLE_INVALID_SOCKET) {
      for (int k = 0; k < pb_count; k++)
        wamble_close_socket(pb[k].sockfd);
      if (out_status)
        *out_status = socket_status;
      free(pb);
      free(profiles);
      free(profile_idx);
      if (out_count)
        *out_count = 0;
      return NULL;
    }
    pb[pb_count].profile_index = profile_idx[i];
    pb[pb_count].sockfd = sockfd;
    pb_count++;
  }
  free(profiles);
  free(profile_idx);
  if (out_count)
    *out_count = pb_count;
  if (out_status)
    *out_status =
        (pb_count > 0) ? PROFILE_START_OK : PROFILE_START_DEFAULT_RUNTIME;
  return pb;
}

static Prebound *
preflight_and_bind_restart_specs(const RestartSpec *specs, int count,
                                 ProfileStartStatus *out_status) {
  if (out_status)
    *out_status = PROFILE_START_OK;
  if (!specs || count <= 0)
    return NULL;

  Prebound *pb = calloc((size_t)count, sizeof(*pb));
  if (!pb) {
    if (out_status)
      *out_status = PROFILE_START_THREAD_ERROR;
    return NULL;
  }
  for (int i = 0; i < count; i++) {
    pb[i].profile_index = -1;
    pb[i].sockfd = WAMBLE_INVALID_SOCKET;
  }

  for (int i = 0; i < count; i++) {
    ProfileStartStatus socket_status = PROFILE_START_OK;
    pb[i].sockfd = create_prebound_socket(&specs[i].cfg, &socket_status);
    if (pb[i].sockfd == WAMBLE_INVALID_SOCKET) {
      close_prebound_entries(pb, 0, count);
      free(pb);
      if (out_status)
        *out_status = socket_status;
      return NULL;
    }
  }
  return pb;
}

static ProfileStartStatus
restore_running_from_restart_specs(const RestartSpec *specs, int count,
                                   int inline_single_ok) {
  ProfileStartStatus st = PROFILE_START_OK;
  Prebound *pb = preflight_and_bind_restart_specs(specs, count, &st);
  if (st != PROFILE_START_OK)
    return st;

  RunningProfile *restored = NULL;
  int restored_count = 0;
  st = start_running_from_restart_specs(pb, specs, count, &restored,
                                        &restored_count, inline_single_ok);
  free(pb);
  if (st != PROFILE_START_OK)
    return st;

  wamble_mutex_lock(&g_mutex);
  g_running = restored;
  g_running_count = restored_count;
  wamble_mutex_unlock(&g_mutex);
  return PROFILE_START_OK;
}

static int profile_runtime_enabled(const WambleProfile *p) {
  if (!p || !p->name)
    return 0;
  if (p->abstract)
    return 0;
  if (p->advertise)
    return 1;

  int rc = config_policy_rule_count();
  char exact[256];
  char selector[256];
  snprintf(exact, sizeof(exact), "profile:%s", p->name);
  selector[0] = '\0';
  if (p->group && p->group[0]) {
    snprintf(selector, sizeof(selector), "profile_selector:%s", p->group);
  }

  for (int i = 0; i < rc; i++) {
    const WamblePolicyRuleSpec *r = config_policy_rule_get(i);
    if (!r || !r->action || !r->resource || !r->effect)
      continue;
    if (strcmp(r->action, "profile.discover.override") != 0)
      continue;
    if (strcmp(r->effect, "allow") != 0)
      continue;
    if (strcmp(r->resource, "*") == 0 || strcmp(r->resource, exact) == 0)
      return 1;
    if (selector[0] && strcmp(r->resource, selector) == 0)
      return 1;
  }
  return 0;
}

static char *profile_runtime_snapshot_template(const RunningProfile *rp) {
  const char *base = NULL;
#if defined(WAMBLE_PLATFORM_POSIX)
  const char sep = '/';
  const char *fallback = "/tmp";
#else
  const char sep = '\\';
  const char *fallback = ".";
#endif
  if (rp && rp->cfg.state_dir && rp->cfg.state_dir[0])
    base = rp->cfg.state_dir;
  if (!base || !base[0])
    base = fallback;
  const char *leaf = "wamble_state_prof_XXXXXX";
  size_t base_len = strlen(base);
  int need_sep =
      (base_len > 0 && base[base_len - 1] != '/' && base[base_len - 1] != '\\')
          ? 1
          : 0;
  size_t total = base_len + (size_t)need_sep + strlen(leaf) + 1;
  char *tmpl = (char *)malloc(total);
  if (!tmpl)
    return NULL;
  snprintf(tmpl, total, "%s%s%s", base, need_sep ? (char[2]){sep, '\0'} : "",
           leaf);
  return tmpl;
}

static void profile_runtime_prepare_exec_snapshot(RunningProfile *rp) {
#if defined(WAMBLE_PLATFORM_POSIX)
  int should_prepare = 0;
  wamble_mutex_lock(&g_mutex);
  if (g_prepare_exec && !rp->ready_for_exec)
    should_prepare = 1;
  wamble_mutex_unlock(&g_mutex);
  if (!should_prepare)
    return;

  if (!profile_runtime_flush_intents(rp, 64))
    return;
  char *tmpl = profile_runtime_snapshot_template(rp);
  if (!tmpl)
    return;
  int tfd = wamble_mkstemp(tmpl);
  if (tfd >= 0)
    close(tfd);
  if (state_save_to_file(tmpl) == 0) {
    wamble_mutex_lock(&g_mutex);
    if (rp->state_path)
      free(rp->state_path);
    rp->state_path = wamble_strdup(tmpl);
    int flags = fcntl(rp->sockfd, F_GETFD);
    if (flags >= 0)
      (void)fcntl(rp->sockfd, F_SETFD, flags & ~FD_CLOEXEC);
    rp->ready_for_exec = 1;
    wamble_mutex_unlock(&g_mutex);
  }
  free(tmpl);
#elif defined(WAMBLE_PLATFORM_WINDOWS)
  int should_prepare = 0;
  wamble_mutex_lock(&g_mutex);
  if (g_prepare_exec && !rp->ready_for_exec)
    should_prepare = 1;
  wamble_mutex_unlock(&g_mutex);
  if (!should_prepare)
    return;

  if (!profile_runtime_flush_intents(rp, 64))
    return;
  char *tmpl = profile_runtime_snapshot_template(rp);
  if (!tmpl)
    return;
  int tfd = wamble_mkstemp(tmpl);
  if (tfd >= 0)
    _close(tfd);
  if (state_save_to_file(tmpl) == 0) {
    wamble_mutex_lock(&g_mutex);
    if (rp->state_path)
      free(rp->state_path);
    rp->state_path = wamble_strdup(tmpl);
    HANDLE handle = (HANDLE)rp->sockfd;
    SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    rp->ready_for_exec = 1;
    wamble_mutex_unlock(&g_mutex);
  }
  free(tmpl);
#else
  (void)rp;
#endif
}

static void profile_runtime_poll_messages(RunningProfile *rp) {
  if (rp->ws_gateway) {
    uint8_t packet[WAMBLE_MAX_PACKET_SIZE];
    size_t packet_len = 0;
    struct sockaddr_in ws_cliaddr;
    for (int drained_ws = 0; drained_ws < 256; drained_ws++) {
      int ws_rc = ws_gateway_pop_packet(rp->ws_gateway, packet, sizeof(packet),
                                        &packet_len, &ws_cliaddr);
      if (ws_rc <= 0)
        break;
      struct WambleMsg msg;
      int n = receive_message_packet(packet, packet_len, &msg, &ws_cliaddr);
      if (n <= 0)
        continue;
      (void)handle_message(rp->sockfd, &msg, &ws_cliaddr, 0, rp->name);
    }
  }

  fd_set rfds;
  struct timeval tv;
  FD_ZERO(&rfds);
  FD_SET(rp->sockfd, &rfds);
  tv.tv_sec = 0;
  tv.tv_usec = get_config()->select_timeout_usec;

  int ready =
#ifdef WAMBLE_PLATFORM_WINDOWS
      select(0, &rfds, NULL, NULL, &tv);
#else
      select(rp->sockfd + 1, &rfds, NULL, NULL, &tv);
#endif
  if (!(ready > 0 && FD_ISSET(rp->sockfd, &rfds)))
    return;

  for (int drained = 0; drained < 64; drained++) {
    struct WambleMsg msg;
    struct sockaddr_in cliaddr;
    int n = receive_message(rp->sockfd, &msg, &cliaddr);
    if (n <= 0)
      break;
    (void)handle_message(rp->sockfd, &msg, &cliaddr, 0, rp->name);
  }

  if (rp->ws_gateway)
    ws_gateway_flush_outbound(rp->ws_gateway);
}

static void send_spectator_batch(wamble_socket_t sockfd,
                                 SpectatorUpdate *events, int count,
                                 uint8_t ctrl) {
  for (int i = 0; i < count; i++) {
    struct WambleMsg out = {0};
    out.ctrl = ctrl;
    memcpy(out.token, events[i].token, TOKEN_LENGTH);
    out.board_id = events[i].board_id;
    out.seq_num = 0;
    out.flags = events[i].flags ? events[i].flags : WAMBLE_FLAG_UNRELIABLE;
    {
      size_t __len = strnlen(events[i].fen, FEN_MAX_LENGTH - 1);
      memcpy(out.fen, events[i].fen, __len);
      out.fen[__len] = '\0';
    }
    (void)send_unreliable_packet(sockfd, &out, &events[i].addr);
  }
}

static void profile_runtime_send_spectator_updates(RunningProfile *rp) {
  int cap = get_config()->max_client_sessions;
  if (cap < 1)
    cap = 1;
  SpectatorUpdate *events =
      (SpectatorUpdate *)malloc(sizeof(SpectatorUpdate) * (size_t)cap);
  if (!events)
    return;
  int nupd = spectator_collect_updates(events, cap);
  send_spectator_batch(rp->sockfd, events, nupd, WAMBLE_CTRL_SPECTATE_UPDATE);
  int nnot = spectator_collect_notifications(events, cap);
  send_spectator_batch(rp->sockfd, events, nnot,
                       WAMBLE_CTRL_SERVER_NOTIFICATION);
  free(events);
}

static int profile_ws_is_enabled(const RunningProfile *rp) {
  if (!rp || rp->cfg.websocket_enabled == 0)
    return 0;
  if (!rp->cfg.websocket_path || rp->cfg.websocket_path[0] == '\0')
    return 0;
  return 1;
}

static int profile_ws_port(const RunningProfile *rp) {
  if (!rp)
    return 0;
  return (rp->cfg.websocket_port > 0) ? rp->cfg.websocket_port : rp->cfg.port;
}

static WsGatewayStatus profile_ws_reconcile(RunningProfile *rp) {
  if (!rp)
    return WS_GATEWAY_OK;
  if (!profile_ws_is_enabled(rp)) {
    if (rp->ws_gateway) {
      ws_gateway_stop(rp->ws_gateway);
      rp->ws_gateway = NULL;
    }
    rp->ws_next_retry_ms = 0;
    rp->ws_retry_enabled = 0;
    return WS_GATEWAY_OK;
  }

  if (rp->ws_gateway) {
    int cur_udp = wamble_socket_bound_port(rp->sockfd);
    if (cur_udp <= 0)
      cur_udp = rp->cfg.port;
    if (ws_gateway_matches(rp->ws_gateway, profile_ws_port(rp), cur_udp,
                           rp->cfg.websocket_path)) {
      return WS_GATEWAY_OK;
    }
    ws_gateway_stop(rp->ws_gateway);
    rp->ws_gateway = NULL;
  }

  int udp_port = wamble_socket_bound_port(rp->sockfd);
  if (udp_port <= 0)
    udp_port = rp->cfg.port;
  WsGatewayStatus ws_status = WS_GATEWAY_OK;
  rp->ws_gateway = ws_gateway_start(
      rp->name ? rp->name : "default", profile_ws_port(rp), udp_port,
      rp->cfg.websocket_path, rp->cfg.max_client_sessions, &ws_status);
  if (!rp->ws_gateway) {
    publish_ws_gateway_status(ws_status, rp->name);
    if (ws_status == WS_GATEWAY_ERR_CONFIG) {
      rp->ws_retry_enabled = 0;
      rp->ws_next_retry_ms = 0;
    } else {
      rp->ws_retry_enabled = 1;
      rp->ws_next_retry_ms = wamble_now_mono_millis() + 5000u;
    }
    return ws_status;
  }
  rp->ws_next_retry_ms = 0;
  rp->ws_retry_enabled = 1;
  return WS_GATEWAY_OK;
}

static int profile_runtime_init(RunningProfile *rp) {
  if (!rp || rp->runtime_ready)
    return 0;
  profile_runtime_set_profile_key(rp->name);
  set_thread_config(&rp->cfg);
  network_init_thread_state();
  ensure_mutex_init();

  wamble_intents_init(&rp->intents_buf);
  rp->qs = wamble_get_db_query_service();
  wamble_set_query_service(rp->qs);
  wamble_set_intent_buffer(&rp->intents_buf);

  if (!wamble_get_query_service()) {
    wamble_intents_free(&rp->intents_buf);
    wamble_set_intent_buffer(NULL);
    return -1;
  }

  player_manager_init();
  board_manager_init();
  {
    PredictionManagerStatus st = prediction_manager_init();
    if (st != PREDICTION_MANAGER_OK)
      publish_prediction_manager_status(st, rp->name);
  }
  rp->ws_retry_enabled = 1;
  rp->last_cleanup = wamble_now_wall();
  rp->last_tick = rp->last_cleanup;
  rp->last_flush_ms = 0;
  profile_runtime_flush_intents(rp, 64);

  if (rp->state_path && rp->state_path[0]) {
    if (state_load_from_file(rp->state_path) == 0) {
#if defined(WAMBLE_PLATFORM_POSIX) || defined(WAMBLE_PLATFORM_WINDOWS)
      wamble_unlink(rp->state_path);
#endif
    }
    free(rp->state_path);
    rp->state_path = NULL;
  }
  if (rp->sockfd == WAMBLE_INVALID_SOCKET) {
    profile_runtime_flush_intents(rp, 64);
    wamble_intents_free(&rp->intents_buf);
    wamble_set_intent_buffer(NULL);
    return -1;
  }
  (void)profile_ws_reconcile(rp);
  rp->runtime_ready = 1;
  return 0;
}

static void profile_runtime_shutdown(RunningProfile *rp) {
  if (!rp || !rp->runtime_ready)
    return;
  wamble_set_query_service(rp->qs);
  wamble_set_intent_buffer(&rp->intents_buf);
  profile_runtime_flush_intents(rp, 64);
  wamble_intents_free(&rp->intents_buf);
  wamble_set_intent_buffer(NULL);
  if (rp->ws_gateway) {
    ws_gateway_stop(rp->ws_gateway);
    rp->ws_gateway = NULL;
  }
  db_cleanup_thread();
  rp->runtime_ready = 0;
}

static void profile_runtime_step(RunningProfile *rp) {
  if (!rp || rp->should_stop)
    return;
  if (!rp->runtime_ready) {
    if (profile_runtime_init(rp) != 0) {
      rp->should_stop = 1;
      return;
    }
  }

  profile_runtime_prepare_exec_snapshot(rp);
  if (rp->needs_update) {
    rp->needs_update = 0;
    if (rp->has_pending_cfg) {
      runtime_cfg_free_owned(&rp->cfg);
      rp->cfg = rp->pending_cfg;
      memset(&rp->pending_cfg, 0, sizeof(rp->pending_cfg));
      rp->has_pending_cfg = 0;
    }
    set_thread_config(&rp->cfg);
    profile_runtime_set_profile_key(rp->name);
    rp->ws_retry_enabled = 1;
    (void)profile_ws_reconcile(rp);
  }
  if (profile_ws_is_enabled(rp) && !rp->ws_gateway && rp->ws_retry_enabled) {
    uint64_t now_ms_retry = wamble_now_mono_millis();
    if (rp->ws_next_retry_ms == 0 || now_ms_retry >= rp->ws_next_retry_ms) {
      (void)profile_ws_reconcile(rp);
    }
  }
  profile_runtime_poll_messages(rp);
  time_t now = wamble_now_wall();
  if (now - rp->last_cleanup > get_config()->cleanup_interval_sec) {
    cleanup_expired_sessions();
    rp->last_cleanup = now;
  }
  if (now - rp->last_tick > 1) {
    player_manager_tick();
    board_manager_tick();
    spectator_manager_tick();
    rp->last_tick = now;
  }
  {
    uint64_t now_ms = wamble_now_mono_millis();
    int pending = rp->intents_buf.count;
    if (pending > 0 &&
        (pending >= PERSIST_FLUSH_EAGER_COUNT ||
         (now_ms - rp->last_flush_ms) >= PERSIST_FLUSH_INTERVAL_MS)) {
      profile_runtime_flush_intents(rp, PERSIST_FLUSH_MAX_BATCHES_PER_CYCLE);
    }
  }
  profile_runtime_send_spectator_updates(rp);
  if (rp->ws_gateway)
    ws_gateway_flush_outbound(rp->ws_gateway);
}

static void profile_runtime_run(RunningProfile *rp) {
  if (profile_runtime_init(rp) != 0)
    return;
  while (!rp->should_stop) {
    profile_runtime_step(rp);
  }

  wamble_close_socket(rp->sockfd);
  rp->sockfd = WAMBLE_INVALID_SOCKET;
  profile_runtime_shutdown(rp);
}

static void *profile_thread_main(void *arg) {
  RunningProfile *rp = (RunningProfile *)arg;
  profile_runtime_run(rp);
  return NULL;
}

ProfileStartStatus start_profile_listeners(int *out_started) {
  ensure_mutex_init();

#if defined(WAMBLE_PLATFORM_POSIX) || defined(WAMBLE_PLATFORM_WINDOWS)
  const char *inherited = getenv("WAMBLE_PROFILES_INHERITED");
  if (inherited && *inherited) {
    int capacity = 1;
    for (const char *p = inherited; *p; ++p) {
      if (*p == ',')
        capacity++;
    }
    if (capacity < 1)
      capacity = 1;

    g_running = calloc((size_t)capacity, sizeof(RunningProfile));
    g_running_count = 0;

    const char *state_map = getenv("WAMBLE_STATE_FILES");
    AdoptEnvContext actx = {.state_map = state_map,
                            .capacity = capacity,
                            .status = PROFILE_START_OK};
    int parse_rc = parse_env_map(inherited, adopt_profile_from_env, &actx);
    if (parse_rc < 0 || actx.status != PROFILE_START_OK) {
      RunningProfile *started = NULL;
      int started_count = 0;
      detach_running_profiles(&started, &started_count);
      join_and_cleanup_profiles(started, started_count, 1);
      if (out_started)
        *out_started = 0;
      return (actx.status != PROFILE_START_OK) ? actx.status
                                               : PROFILE_START_THREAD_ERROR;
    }

    if (g_running_count > 0) {
      if (out_started)
        *out_started = g_running_count;
      return PROFILE_START_OK;
    }

    free(g_running);
    g_running = NULL;
    g_running_count = 0;
    if (out_started)
      *out_started = 0;
  }
#endif
  int count = 0;
  ProfileStartStatus st = PROFILE_START_OK;
  Prebound *pb = preflight_and_bind_all(&count, &st);
  if (st != PROFILE_START_OK && st != PROFILE_START_DEFAULT_RUNTIME &&
      st != PROFILE_START_NONE) {
    if (out_started)
      *out_started = 0;
    if (pb)
      free(pb);
    return st;
  }
  RunningProfile *started = NULL;
  int started_count = 0;
  if (st == PROFILE_START_OK) {
    st = start_running_from_prebound(pb, count, &started, &started_count, 1);
    free(pb);
    if (st != PROFILE_START_OK) {
      if (out_started)
        *out_started = 0;
      return st;
    }
  } else {
    if (pb)
      free(pb);
    st = start_default_runtime(&started, &started_count, 1);
    if (st != PROFILE_START_OK) {
      if (out_started)
        *out_started = 0;
      return st;
    }
  }
  g_running = started;
  g_running_count = started_count;
  if (out_started)
    *out_started = g_running_count;
  return PROFILE_START_OK;
}

static void free_running(RunningProfile *rp) {
  if (!rp)
    return;
  free(rp->name);
  runtime_cfg_free_owned(&rp->cfg);
  runtime_cfg_free_owned(&rp->pending_cfg);
  free(rp->state_path);
  if (rp->ws_gateway) {
    ws_gateway_stop(rp->ws_gateway);
    rp->ws_gateway = NULL;
  }
  rp->state_path = NULL;
  rp->ready_for_exec = 0;
  rp->run_inline = 0;
  rp->runtime_ready = 0;
  rp->qs = NULL;
}

static int profile_has_inline_runtime_locked(void) {
  return (g_running_count == 1 && g_running && g_running[0].run_inline &&
          !g_running[0].thread)
             ? 1
             : 0;
}

int profile_runtime_pump_inline(void) {
  if (!profile_has_inline_runtime_locked())
    return 0;
  profile_runtime_step(&g_running[0]);
  return 1;
}

static int count_configured_profiles(void) {
  int total = config_profile_count();
  int configured = 0;
  for (int i = 0; i < total; i++) {
    const WambleProfile *p = config_get_profile(i);
    if (profile_runtime_enabled(p))
      configured++;
  }
  return configured;
}

static const WambleProfile *find_profile_by_name(const char *name) {
  if (!name || !*name)
    return NULL;
  int total = config_profile_count();
  for (int i = 0; i < total; i++) {
    const WambleProfile *p = config_get_profile(i);
    if (!profile_runtime_enabled(p))
      continue;
    if (strcmp(p->name, name) == 0)
      return p;
  }
  return NULL;
}

static int running_profiles_match_configured(int desired_profiles) {
  if (g_running_count != desired_profiles)
    return 0;
  for (int i = 0; i < g_running_count; i++) {
    if (!g_running[i].name)
      return 0;
    if (!find_profile_by_name(g_running[i].name))
      return 0;
  }
  return 1;
}

static int runtime_cfg_socket_identity_equals(const WambleConfig *a,
                                              const WambleConfig *b) {
  if (!a || !b)
    return 0;
  return a->port == b->port;
}

static int runtime_cfg_requires_restart(const WambleConfig *a,
                                        const WambleConfig *b) {
  if (!a || !b)
    return 1;
  return a->buffer_size != b->buffer_size ||
         a->max_client_sessions != b->max_client_sessions ||
         a->max_boards != b->max_boards || a->min_boards != b->min_boards ||
         a->max_players != b->max_players ||
         !cfg_str_eq(a->db_host, b->db_host) ||
         !cfg_str_eq(a->db_user, b->db_user) ||
         !cfg_str_eq(a->db_pass, b->db_pass) ||
         !cfg_str_eq(a->db_name, b->db_name) ||
         !cfg_str_eq(a->global_db_host, b->global_db_host) ||
         !cfg_str_eq(a->global_db_user, b->global_db_user) ||
         !cfg_str_eq(a->global_db_pass, b->global_db_pass) ||
         !cfg_str_eq(a->global_db_name, b->global_db_name);
}

static int runtime_cfg_equals(const WambleConfig *a, const WambleConfig *b) {
  if (!a || !b)
    return 0;
  return a->port == b->port && a->websocket_enabled == b->websocket_enabled &&
         a->websocket_port == b->websocket_port &&
         a->experiment_enabled == b->experiment_enabled &&
         a->experiment_seed == b->experiment_seed &&
         a->timeout_ms == b->timeout_ms && a->max_retries == b->max_retries &&
         a->max_message_size == b->max_message_size &&
         a->buffer_size == b->buffer_size &&
         a->max_client_sessions == b->max_client_sessions &&
         a->rate_limit_requests_per_sec == b->rate_limit_requests_per_sec &&
         a->session_timeout == b->session_timeout &&
         a->max_boards == b->max_boards && a->min_boards == b->min_boards &&
         a->cleanup_interval_sec == b->cleanup_interval_sec &&
         a->inactivity_timeout == b->inactivity_timeout &&
         a->reservation_timeout == b->reservation_timeout &&
         a->default_rating == b->default_rating &&
         a->max_players == b->max_players &&
         a->token_expiration == b->token_expiration &&
         a->max_pot == b->max_pot &&
         a->max_moves_per_board == b->max_moves_per_board &&
         a->max_contributors == b->max_contributors &&
         a->select_timeout_usec == b->select_timeout_usec &&
         a->max_token_attempts == b->max_token_attempts &&
         a->max_token_local_attempts == b->max_token_local_attempts &&
         a->persistence_max_intents == b->persistence_max_intents &&
         a->persistence_max_payload_bytes == b->persistence_max_payload_bytes &&
         a->new_player_early_phase_mult == b->new_player_early_phase_mult &&
         a->new_player_mid_phase_mult == b->new_player_mid_phase_mult &&
         a->new_player_end_phase_mult == b->new_player_end_phase_mult &&
         a->experienced_player_early_phase_mult ==
             b->experienced_player_early_phase_mult &&
         a->experienced_player_mid_phase_mult ==
             b->experienced_player_mid_phase_mult &&
         a->experienced_player_end_phase_mult ==
             b->experienced_player_end_phase_mult &&
         a->log_level == b->log_level && cfg_str_eq(a->db_host, b->db_host) &&
         cfg_str_eq(a->db_user, b->db_user) &&
         cfg_str_eq(a->db_pass, b->db_pass) &&
         cfg_str_eq(a->db_name, b->db_name) &&
         cfg_str_eq(a->global_db_host, b->global_db_host) &&
         cfg_str_eq(a->global_db_user, b->global_db_user) &&
         cfg_str_eq(a->global_db_pass, b->global_db_pass) &&
         cfg_str_eq(a->global_db_name, b->global_db_name) &&
         a->max_spectators == b->max_spectators &&
         a->spectator_visibility == b->spectator_visibility &&
         a->spectator_summary_hz == b->spectator_summary_hz &&
         a->spectator_focus_hz == b->spectator_focus_hz &&
         a->spectator_max_focus_per_session ==
             b->spectator_max_focus_per_session &&
         cfg_str_eq(a->spectator_summary_mode, b->spectator_summary_mode) &&
         cfg_str_eq(a->state_dir, b->state_dir) &&
         cfg_str_eq(a->websocket_path, b->websocket_path);
}

static int running_profiles_can_refresh_in_place(int desired_profiles) {
  if (!running_profiles_match_configured(desired_profiles))
    return 0;
  for (int i = 0; i < g_running_count; i++) {
    const WambleProfile *p_match = find_profile_by_name(g_running[i].name);
    if (!p_match)
      return 0;
    if (!runtime_cfg_socket_identity_equals(&g_running[i].cfg,
                                            &p_match->config))
      return 0;
    if (runtime_cfg_requires_restart(&g_running[i].cfg, &p_match->config))
      return 0;
  }
  return 1;
}

static int running_profiles_require_same_socket_restart(int desired_profiles) {
  if (!running_profiles_match_configured(desired_profiles))
    return 0;
  for (int i = 0; i < g_running_count; i++) {
    const WambleProfile *p_match = find_profile_by_name(g_running[i].name);
    if (!p_match)
      return 0;
    if (!runtime_cfg_socket_identity_equals(&g_running[i].cfg,
                                            &p_match->config))
      return 0;
  }
  for (int i = 0; i < g_running_count; i++) {
    const WambleProfile *p_match = find_profile_by_name(g_running[i].name);
    if (p_match &&
        runtime_cfg_requires_restart(&g_running[i].cfg, &p_match->config)) {
      return 1;
    }
  }
  return 0;
}

static int default_runtime_can_refresh_in_place(void) {
  if (g_running_count != 1 || !g_running)
    return 0;
  if (g_running[0].name != NULL)
    return 0;
  return runtime_cfg_socket_identity_equals(&g_running[0].cfg, get_config()) &&
         !runtime_cfg_requires_restart(&g_running[0].cfg, get_config());
}

static void refresh_running_profile_configs(void) {
  for (int i = 0; i < g_running_count; i++) {
    const WambleProfile *p_match = find_profile_by_name(g_running[i].name);
    if (!p_match)
      continue;

    if (runtime_cfg_equals(&g_running[i].cfg, &p_match->config)) {
      continue;
    }

    WambleConfig next_cfg = {0};
    if (runtime_cfg_dup_from(&next_cfg, &p_match->config) != 0)
      continue;
    if (g_running[i].has_pending_cfg)
      runtime_cfg_free_owned(&g_running[i].pending_cfg);
    g_running[i].pending_cfg = next_cfg;
    g_running[i].has_pending_cfg = 1;
    g_running[i].needs_update = 1;
  }
}

static void refresh_default_runtime_config(void) {
  if (g_running_count != 1 || !g_running || g_running[0].name != NULL)
    return;
  if (runtime_cfg_equals(&g_running[0].cfg, get_config()))
    return;

  WambleConfig next_cfg = {0};
  if (runtime_cfg_dup_from(&next_cfg, get_config()) != 0)
    return;
  if (g_running[0].has_pending_cfg)
    runtime_cfg_free_owned(&g_running[0].pending_cfg);
  g_running[0].pending_cfg = next_cfg;
  g_running[0].has_pending_cfg = 1;
  g_running[0].needs_update = 1;
}

void stop_profile_listeners(void) {
  RunningProfile *profiles = NULL;
  int count = 0;
  detach_running_profiles(&profiles, &count);
  join_and_cleanup_profiles(profiles, count, 1);
}

ProfileStartStatus reconcile_profile_listeners(void) {
  ensure_mutex_init();
  wamble_mutex_lock(&g_mutex);

  int desired_profiles = count_configured_profiles();

  if (desired_profiles == 0) {
    if (default_runtime_can_refresh_in_place()) {
      refresh_default_runtime_config();
      wamble_mutex_unlock(&g_mutex);
      return PROFILE_START_OK;
    }
    RestartSpec *old_specs = NULL;
    if (snapshot_restart_specs_from_running(g_running, g_running_count,
                                            &old_specs) != 0) {
      wamble_mutex_unlock(&g_mutex);
      return PROFILE_START_THREAD_ERROR;
    }
    RunningProfile *old = g_running;
    int old_count = g_running_count;
    mark_profiles_stop(old, old_count);
    g_running = NULL;
    g_running_count = 0;
    g_prepare_exec = 0;
    wamble_mutex_unlock(&g_mutex);
    join_and_cleanup_profiles(old, old_count, 1);
    RunningProfile *new_running = NULL;
    int new_count = 0;
    ProfileStartStatus dst = start_default_runtime(&new_running, &new_count, 1);
    if (dst != PROFILE_START_OK) {
      (void)restore_running_from_restart_specs(old_specs, old_count, 1);
      free_restart_specs(old_specs, old_count);
      return dst;
    }
    free_restart_specs(old_specs, old_count);
    wamble_mutex_lock(&g_mutex);
    g_running = new_running;
    g_running_count = new_count;
    wamble_mutex_unlock(&g_mutex);
    return PROFILE_START_OK;
  }

  if (running_profiles_can_refresh_in_place(desired_profiles)) {
    refresh_running_profile_configs();
    wamble_mutex_unlock(&g_mutex);
    return PROFILE_START_OK;
  }

  if (running_profiles_require_same_socket_restart(desired_profiles)) {
    RestartSpec *old_specs = NULL;
    if (snapshot_restart_specs_from_running(g_running, g_running_count,
                                            &old_specs) != 0) {
      wamble_mutex_unlock(&g_mutex);
      return PROFILE_START_THREAD_ERROR;
    }
    RunningProfile *old = g_running;
    int old_count = g_running_count;
    mark_profiles_stop(old, old_count);
    g_running = NULL;
    g_running_count = 0;
    g_prepare_exec = 0;
    wamble_mutex_unlock(&g_mutex);

    join_and_cleanup_profiles(old, old_count, 1);

    int new_count = 0;
    ProfileStartStatus st = PROFILE_START_OK;
    Prebound *pb = preflight_and_bind_all(&new_count, &st);
    if (st != PROFILE_START_OK) {
      if (pb)
        free(pb);
      (void)restore_running_from_restart_specs(old_specs, old_count, 1);
      free_restart_specs(old_specs, old_count);
      return st;
    }

    RunningProfile *new_running = NULL;
    int started_count = 0;
    st = start_running_from_prebound(pb, new_count, &new_running,
                                     &started_count, 1);
    free(pb);
    if (st != PROFILE_START_OK) {
      (void)restore_running_from_restart_specs(old_specs, old_count, 1);
      free_restart_specs(old_specs, old_count);
      return st;
    }

    free_restart_specs(old_specs, old_count);
    wamble_mutex_lock(&g_mutex);
    g_running = new_running;
    g_running_count = started_count;
    wamble_mutex_unlock(&g_mutex);
    return PROFILE_START_OK;
  }

  int new_count = 0;
  ProfileStartStatus st = PROFILE_START_OK;
  Prebound *pb = preflight_and_bind_all(&new_count, &st);
  if (st != PROFILE_START_OK) {
    wamble_mutex_unlock(&g_mutex);
    return st;
  }
  RestartSpec *old_specs = NULL;
  if (snapshot_restart_specs_from_running(g_running, g_running_count,
                                          &old_specs) != 0) {
    close_prebound_entries(pb, 0, new_count);
    free(pb);
    wamble_mutex_unlock(&g_mutex);
    return PROFILE_START_THREAD_ERROR;
  }
  RunningProfile *old = g_running;
  int old_count = g_running_count;
  mark_profiles_stop(old, old_count);
  g_running = NULL;
  g_running_count = 0;
  g_prepare_exec = 0;
  wamble_mutex_unlock(&g_mutex);

  join_and_cleanup_profiles(old, old_count, 1);

  RunningProfile *new_running = NULL;
  int started_count = 0;
  st = start_running_from_prebound(pb, new_count, &new_running, &started_count,
                                   1);
  if (st != PROFILE_START_OK) {
    free(pb);
    (void)restore_running_from_restart_specs(old_specs, old_count, 1);
    free_restart_specs(old_specs, old_count);
    return st;
  }

  free(pb);
  free_restart_specs(old_specs, old_count);

  wamble_mutex_lock(&g_mutex);
  g_running = new_running;
  g_running_count = started_count;
  wamble_mutex_unlock(&g_mutex);
  return PROFILE_START_OK;
}

ProfileExportStatus profile_export_inherited_sockets(char *out_buf,
                                                     size_t out_buf_size,
                                                     int *out_count) {
#if defined(WAMBLE_PLATFORM_POSIX) || defined(WAMBLE_PLATFORM_WINDOWS)
  ensure_mutex_init();
  if (out_count)
    *out_count = 0;
  if (!out_buf || out_buf_size == 0)
    return PROFILE_EXPORT_BUFFER_TOO_SMALL;
  out_buf[0] = '\0';
  int written = 0;
  int count = 0;
  for (int i = 0; i < g_running_count; i++) {
    RunningProfile *rp = &g_running[i];
    if (rp->sockfd == WAMBLE_INVALID_SOCKET)
      continue;

    char part[128];
    const char *export_name =
        rp->name ? rp->name : WAMBLE_DEFAULT_RUNTIME_EXPORT_NAME;
    unsigned long long sock_val = (unsigned long long)rp->sockfd;
    snprintf(part, sizeof(part), "%s=%llu", export_name, sock_val);
    size_t need = strlen(part);
    size_t sep = (written > 0) ? 1u : 0u;
    if ((size_t)written + sep + need >= out_buf_size) {
      out_buf[written] = '\0';
      return PROFILE_EXPORT_BUFFER_TOO_SMALL;
    }
    if (sep) {
      out_buf[written++] = ',';
    }
    memcpy(out_buf + written, part, need);
    written += (int)need;
    out_buf[written] = '\0';
    count++;
  }
  if (out_count)
    *out_count = count;
  return (count > 0) ? PROFILE_EXPORT_OK : PROFILE_EXPORT_EMPTY;
#else
  (void)out_buf;
  (void)out_buf_size;
  (void)out_count;
  return PROFILE_EXPORT_NOT_READY;
#endif
}

ProfileExportStatus profile_prepare_state_save_and_inherit(
    char *out_state_map, size_t out_state_map_size, int *out_count) {
#if defined(WAMBLE_PLATFORM_POSIX) || defined(WAMBLE_PLATFORM_WINDOWS)
  ensure_mutex_init();
  if (out_count)
    *out_count = 0;
  if (!out_state_map || out_state_map_size == 0)
    return PROFILE_EXPORT_BUFFER_TOO_SMALL;
  out_state_map[0] = '\0';

  wamble_mutex_lock(&g_mutex);
  for (int i = 0; i < g_running_count; i++) {
    g_running[i].ready_for_exec = 0;
  }
  g_prepare_exec = 1;
  wamble_mutex_unlock(&g_mutex);

  const int max_wait_ms = 2000;
  int elapsed = 0;
  int ready = 0;
  while (elapsed < max_wait_ms) {
    int all_ready = 1;
    int inline_pending = 0;
    wamble_mutex_lock(&g_mutex);
    for (int i = 0; i < g_running_count; i++) {
      if (!g_running[i].ready_for_exec) {
        all_ready = 0;
        if (g_running[i].run_inline)
          inline_pending = 1;
        break;
      }
    }
    wamble_mutex_unlock(&g_mutex);
    if (all_ready) {
      ready = 1;
      break;
    }
    if (inline_pending && profile_has_inline_runtime_locked())
      profile_runtime_prepare_exec_snapshot(&g_running[0]);
#ifdef _WIN32
    Sleep(10);
#else
    struct timespec ts = {.tv_sec = 0, .tv_nsec = 10 * 1000 * 1000};
    nanosleep(&ts, NULL);
#endif
    elapsed += 10;
  }

  int written = 0;
  int count = 0;
  wamble_mutex_lock(&g_mutex);
  if (!ready) {
    g_prepare_exec = 0;
    wamble_mutex_unlock(&g_mutex);
    out_state_map[0] = '\0';
    return PROFILE_EXPORT_NOT_READY;
  }
  for (int i = 0; i < g_running_count; i++) {
    if (!g_running[i].state_path)
      continue;
    char part[512];
    const char *export_name = g_running[i].name
                                  ? g_running[i].name
                                  : WAMBLE_DEFAULT_RUNTIME_EXPORT_NAME;
    snprintf(part, sizeof(part), "%s=%s", export_name, g_running[i].state_path);
    size_t need = strlen(part);
    size_t sep = (written > 0) ? 1u : 0u;
    if ((size_t)written + sep + need >= out_state_map_size) {
      g_prepare_exec = 0;
      out_state_map[written] = '\0';
      wamble_mutex_unlock(&g_mutex);
      return PROFILE_EXPORT_BUFFER_TOO_SMALL;
    }
    if (sep)
      out_state_map[written++] = ',';
    memcpy(out_state_map + written, part, need);
    written += (int)need;
    out_state_map[written] = '\0';
    count++;
  }
  if ((size_t)written < out_state_map_size)
    out_state_map[written] = '\0';
  g_prepare_exec = 0;
  wamble_mutex_unlock(&g_mutex);
  if (out_count)
    *out_count = count;
  if (count == 0)
    return PROFILE_EXPORT_EMPTY;
  return PROFILE_EXPORT_OK;
#else
  (void)out_state_map;
  (void)out_state_map_size;
  (void)out_count;
  return PROFILE_EXPORT_NOT_READY;
#endif
}
