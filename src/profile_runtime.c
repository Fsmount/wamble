#include "../include/wamble/wamble.h"
#include <stdlib.h>
#include <string.h>
#if defined(_MSC_VER) && !defined(strtoull)
#define strtoull _strtoui64
#endif
#if defined(WAMBLE_PLATFORM_POSIX) && !defined(TEST_PROFILE_RUNTIME)
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
  int should_stop;
  int needs_update;
  char *state_path;
  int ready_for_exec;
} RunningProfile;

static RunningProfile *g_running = NULL;
static int g_running_count = 0;
static wamble_mutex_t g_mutex;
static int g_mutex_initialized = 0;
static int g_prepare_exec = 0;

static void free_running(RunningProfile *rp);

static void ensure_mutex_init(void) {
  if (!g_mutex_initialized) {
    wamble_mutex_init(&g_mutex);
    g_mutex_initialized = 1;
  }
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

static int adopt_profile_from_env(const char *name, const char *value,
                                  void *opaque) {
  AdoptEnvContext *ctx = (AdoptEnvContext *)opaque;
  if (!ctx || ctx->status != PROFILE_START_OK)
    return 0;
  if (g_running_count >= ctx->capacity)
    return 0;

  const WambleProfile *p = config_find_profile(name);
  if (!p || !p->advertise)
    return 0;

  char *endptr = NULL;
  unsigned long long handle = strtoull(value, &endptr, 10);
  if (!value || value[0] == '\0' || (endptr && *endptr != '\0'))
    return 0;

  wamble_socket_t sock = (wamble_socket_t)handle;
  if (sock == WAMBLE_INVALID_SOCKET)
    return 0;

  RunningProfile *rp = &g_running[g_running_count];
  rp->name = wamble_strdup_local(p->name);
  rp->cfg = p->config;
  rp->cfg.db_host = wamble_strdup_local(p->config.db_host);
  rp->cfg.db_user = wamble_strdup_local(p->config.db_user);
  rp->cfg.db_pass = wamble_strdup_local(p->config.db_pass);
  rp->cfg.db_name = wamble_strdup_local(p->config.db_name);
  if (!rp->name || !rp->cfg.db_host || !rp->cfg.db_user || !rp->cfg.db_pass ||
      !rp->cfg.db_name) {
    free(rp->name);
    free(rp->cfg.db_host);
    free(rp->cfg.db_user);
    free(rp->cfg.db_pass);
    free(rp->cfg.db_name);
    if (rp->state_path) {
      free(rp->state_path);
      rp->state_path = NULL;
    }
    rp->name = NULL;
    rp->cfg.db_host = NULL;
    rp->cfg.db_user = NULL;
    rp->cfg.db_pass = NULL;
    rp->cfg.db_name = NULL;
    ctx->status = PROFILE_START_THREAD_ERROR;
    return 1;
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

  if (wamble_thread_create(&rp->thread, profile_thread_main, rp) != 0) {
    wamble_close_socket(rp->sockfd);
    rp->sockfd = WAMBLE_INVALID_SOCKET;
    free_running(rp);
    ctx->status = PROFILE_START_THREAD_ERROR;
    return 1;
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

typedef struct Prebound {
  int profile_index;
  wamble_socket_t sockfd;
} Prebound;

static Prebound *preflight_and_bind_all(int *out_count,
                                        ProfileStartStatus *out_status) {
  int count = config_profile_count();
  if (count <= 0) {
    if (out_count)
      *out_count = 0;
    if (out_status)
      *out_status = PROFILE_START_NONE;
    return NULL;
  }

  for (int i = 0; i < count; i++) {
    const WambleProfile *pi = config_get_profile(i);
    if (!pi || !pi->advertise)
      continue;
    for (int j = i + 1; j < count; j++) {
      const WambleProfile *pj = config_get_profile(j);
      if (!pj || !pj->advertise)
        continue;
      if (pi->config.port == pj->config.port) {
        if (out_status)
          *out_status = PROFILE_START_CONFLICT;
        if (out_count)
          *out_count = 0;
        return NULL;
      }
      if (pi->db_isolated && pj->db_isolated &&
          db_same(&pi->config, &pj->config)) {
        if (out_status)
          *out_status = PROFILE_START_CONFLICT;
        if (out_count)
          *out_count = 0;
        return NULL;
      }
    }
  }

  Prebound *pb = calloc((size_t)count, sizeof(Prebound));
  int pb_count = 0;
  for (int i = 0; i < count; i++) {
    const WambleProfile *p = config_get_profile(i);
    if (!p || !p->advertise)
      continue;
    wamble_socket_t sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == WAMBLE_INVALID_SOCKET) {
      if (out_status)
        *out_status = PROFILE_START_SOCKET_ERROR;
      for (int k = 0; k < pb_count; k++)
        wamble_close_socket(pb[k].sockfd);
      free(pb);
      if (out_count)
        *out_count = 0;
      return NULL;
    }
    int optval = 1;
    (void)setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&optval,
                     sizeof(optval));
    int buffer_size = p->config.buffer_size;
    (void)setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (const char *)&buffer_size,
                     sizeof(buffer_size));
    (void)setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const char *)&buffer_size,
                     sizeof(buffer_size));

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons((uint16_t)p->config.port);
    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) <
        0) {
      for (int k = 0; k < pb_count; k++)
        wamble_close_socket(pb[k].sockfd);
      if (out_status)
        *out_status = PROFILE_START_BIND_ERROR;
      free(pb);
      if (out_count)
        *out_count = 0;
      return NULL;
    }

    (void)wamble_set_nonblocking(sockfd);
    pb[pb_count].profile_index = i;
    pb[pb_count].sockfd = sockfd;
    pb_count++;
  }
  if (out_count)
    *out_count = pb_count;
  if (out_status)
    *out_status = (pb_count > 0) ? PROFILE_START_OK : PROFILE_START_NONE;
  return pb;
}

static void *profile_thread_main(void *arg) {
  RunningProfile *rp = (RunningProfile *)arg;
  set_thread_config(&rp->cfg);
  network_init_thread_state();
  ensure_mutex_init();

#ifndef TEST_PROFILE_RUNTIME
  player_manager_init();
  board_manager_init();

#endif

#ifndef TEST_PROFILE_RUNTIME
  if (rp->state_path && rp->state_path[0]) {
    if (state_load_from_file(rp->state_path) == 0) {
#if defined(WAMBLE_PLATFORM_POSIX) || defined(WAMBLE_PLATFORM_WINDOWS)
      wamble_unlink(rp->state_path);
#endif
    }
    free(rp->state_path);
    rp->state_path = NULL;
  }
#endif
  if (rp->sockfd == WAMBLE_INVALID_SOCKET) {
    return NULL;
  }

  time_t last_cleanup = wamble_now_wall();
  time_t last_tick = wamble_now_wall();
  while (!rp->should_stop) {

#if defined(WAMBLE_PLATFORM_POSIX)
    int should_prepare = 0;
    wamble_mutex_lock(&g_mutex);
    if (g_prepare_exec && !rp->ready_for_exec)
      should_prepare = 1;
    wamble_mutex_unlock(&g_mutex);
#if defined(TEST_PROFILE_RUNTIME)
    if (should_prepare) {
      wamble_mutex_lock(&g_mutex);
      rp->ready_for_exec = 1;
      wamble_mutex_unlock(&g_mutex);
    }
#else
    if (should_prepare) {
      char tmpl[] = "/tmp/wamble_state_prof_XXXXXX";
      int tfd = wamble_mkstemp(tmpl);
      if (tfd >= 0)
        close(tfd);
      if (state_save_to_file(tmpl) == 0) {
        wamble_mutex_lock(&g_mutex);
        if (rp->state_path)
          free(rp->state_path);
        rp->state_path = strdup(tmpl);
        int flags = fcntl(rp->sockfd, F_GETFD);
        if (flags >= 0)
          (void)fcntl(rp->sockfd, F_SETFD, flags & ~FD_CLOEXEC);
        rp->ready_for_exec = 1;
        wamble_mutex_unlock(&g_mutex);
      }
    }
#endif
#elif defined(WAMBLE_PLATFORM_WINDOWS)
    int should_prepare = 0;
    wamble_mutex_lock(&g_mutex);
    if (g_prepare_exec && !rp->ready_for_exec)
      should_prepare = 1;
    wamble_mutex_unlock(&g_mutex);
#if defined(TEST_PROFILE_RUNTIME)
    if (should_prepare) {
      wamble_mutex_lock(&g_mutex);
      rp->ready_for_exec = 1;
      wamble_mutex_unlock(&g_mutex);
    }
#else
    if (should_prepare) {
      char tmpl[] = "wamble_state_prof_XXXXXX";
      int tfd = wamble_mkstemp(tmpl);
      if (tfd >= 0)
        _close(tfd);
      if (state_save_to_file(tmpl) == 0) {
        wamble_mutex_lock(&g_mutex);
        if (rp->state_path)
          free(rp->state_path);
        rp->state_path = strdup(tmpl);
        HANDLE handle = (HANDLE)rp->sockfd;
        SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
        rp->ready_for_exec = 1;
        wamble_mutex_unlock(&g_mutex);
      }
    }
#endif
#endif
    if (rp->needs_update) {
      rp->needs_update = 0;
      set_thread_config(&rp->cfg);
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
    if (ready > 0 && FD_ISSET(rp->sockfd, &rfds)) {
      struct WambleMsg msg;
      struct sockaddr_in cliaddr;
      int n = receive_message(rp->sockfd, &msg, &cliaddr);
      if (n > 0) {
        handle_message(rp->sockfd, &msg, &cliaddr);
      }
    }

    time_t now = wamble_now_wall();
    if (now - last_cleanup > get_config()->cleanup_interval_sec) {
      cleanup_expired_sessions();
      last_cleanup = now;
    }
    if (now - last_tick > 1) {
#ifndef TEST_PROFILE_RUNTIME
      board_manager_tick();
      spectator_manager_tick();
#endif
      last_tick = now;
    }

#ifndef TEST_PROFILE_RUNTIME
    int cap = get_config()->max_client_sessions;
    if (cap < 1)
      cap = 1;
    SpectatorUpdate *events =
        (SpectatorUpdate *)malloc(sizeof(SpectatorUpdate) * (size_t)cap);
    if (events) {
      int nupd = spectator_collect_updates(events, cap);
      for (int i = 0; i < nupd; i++) {
        struct WambleMsg out = {0};
        out.ctrl = WAMBLE_CTRL_SPECTATE_UPDATE;
        memcpy(out.token, events[i].token, TOKEN_LENGTH);
        out.board_id = events[i].board_id;
        out.seq_num = 0;
        out.flags = WAMBLE_FLAG_UNRELIABLE;
        {
          size_t __len = strnlen(events[i].fen, FEN_MAX_LENGTH - 1);
          memcpy(out.fen, events[i].fen, __len);
          out.fen[__len] = '\0';
        }
        (void)send_unreliable_packet(rp->sockfd, &out, &events[i].addr);
      }
      int nnot = spectator_collect_notifications(events, cap);
      for (int i = 0; i < nnot; i++) {
        struct WambleMsg out = {0};
        out.ctrl = WAMBLE_CTRL_SERVER_NOTIFICATION;
        memcpy(out.token, events[i].token, TOKEN_LENGTH);
        out.board_id = events[i].board_id;
        out.seq_num = 0;
        out.flags = WAMBLE_FLAG_UNRELIABLE;
        {
          size_t __len = strnlen(events[i].fen, FEN_MAX_LENGTH - 1);
          memcpy(out.fen, events[i].fen, __len);
          out.fen[__len] = '\0';
        }
        (void)send_unreliable_packet(rp->sockfd, &out, &events[i].addr);
      }
      free(events);
    }
#endif
  }

  wamble_close_socket(rp->sockfd);
  rp->sockfd = WAMBLE_INVALID_SOCKET;
  db_cleanup_thread();
  return NULL;
}

ProfileStartStatus start_profile_listeners(int *out_started) {
  ensure_mutex_init();

#if !defined(TEST_PROFILE_RUNTIME) &&                                          \
    (defined(WAMBLE_PLATFORM_POSIX) || defined(WAMBLE_PLATFORM_WINDOWS))
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
    return PROFILE_START_NONE;
  }
#endif
  int count = 0;
  ProfileStartStatus st = PROFILE_START_OK;
  Prebound *pb = preflight_and_bind_all(&count, &st);
  if (st != PROFILE_START_OK) {
    if (out_started)
      *out_started = 0;
    if (pb)
      free(pb);
    return st;
  }
  g_running = calloc((size_t)count, sizeof(RunningProfile));
  g_running_count = count;
  for (int i = 0; i < count; i++) {
    const WambleProfile *p = config_get_profile(pb[i].profile_index);
    RunningProfile *rp = &g_running[i];
    rp->name = strdup(p->name);
    rp->cfg = p->config;

    rp->cfg.db_host = strdup(p->config.db_host);
    rp->cfg.db_user = strdup(p->config.db_user);
    rp->cfg.db_pass = strdup(p->config.db_pass);
    rp->cfg.db_name = strdup(p->config.db_name);
    rp->sockfd = pb[i].sockfd;
    rp->should_stop = 0;
    rp->needs_update = 0;
    if (rp->sockfd == WAMBLE_INVALID_SOCKET) {
      for (int k = 0; k <= i; k++) {
        if (g_running[k].sockfd != WAMBLE_INVALID_SOCKET)
          wamble_close_socket(g_running[k].sockfd);
        free_running(&g_running[k]);
      }
      free(g_running);
      g_running = NULL;
      g_running_count = 0;
      free(pb);
      if (out_started)
        *out_started = 0;
      return PROFILE_START_NO_SOCKET;
    }
    if (wamble_thread_create(&rp->thread, profile_thread_main, rp) != 0) {
      for (int k = 0; k <= i; k++) {
        if (g_running[k].sockfd != WAMBLE_INVALID_SOCKET)
          wamble_close_socket(g_running[k].sockfd);
        free_running(&g_running[k]);
      }
      free(g_running);
      g_running = NULL;
      g_running_count = 0;
      free(pb);
      if (out_started)
        *out_started = 0;
      return PROFILE_START_THREAD_ERROR;
    }
  }
  free(pb);
  if (out_started)
    *out_started = g_running_count;
  return PROFILE_START_OK;
}

static void free_running(RunningProfile *rp) {
  if (!rp)
    return;
  free(rp->name);
  free(rp->cfg.db_host);
  free(rp->cfg.db_user);
  free(rp->cfg.db_pass);
  free(rp->cfg.db_name);
  free(rp->state_path);
  rp->state_path = NULL;
  rp->ready_for_exec = 0;
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

  int desired_total = config_profile_count();
  int desired_adv = 0;
  for (int i = 0; i < desired_total; i++) {
    const WambleProfile *p = config_get_profile(i);
    if (p && p->advertise)
      desired_adv++;
  }

  if (desired_adv == 0) {
    RunningProfile *old = g_running;
    int old_count = g_running_count;
    if (old) {
      for (int i = 0; i < old_count; i++)
        old[i].should_stop = 1;
    }
    g_running = NULL;
    g_running_count = 0;
    g_prepare_exec = 0;
    wamble_mutex_unlock(&g_mutex);
    join_and_cleanup_profiles(old, old_count, 1);
    return PROFILE_START_NONE;
  }

  int overlap_ok = 1;
  if (g_running_count != desired_adv)
    overlap_ok = 0;
  if (overlap_ok) {
    for (int i = 0; i < g_running_count; i++) {
      int found = 0;
      for (int j = 0; j < desired_total; j++) {
        const WambleProfile *p = config_get_profile(j);
        if (!p || !p->advertise)
          continue;
        if (p->name && g_running[i].name &&
            strcmp(p->name, g_running[i].name) == 0) {
          found = 1;
          break;
        }
      }
      if (!found) {
        overlap_ok = 0;
        break;
      }
    }
  }

  if (overlap_ok) {

    for (int i = 0; i < g_running_count; i++) {
      const WambleProfile *p_match = NULL;
      for (int j = 0; j < desired_total; j++) {
        const WambleProfile *p = config_get_profile(j);
        if (!p || !p->advertise)
          continue;
        if (p->name && strcmp(p->name, g_running[i].name) == 0) {
          p_match = p;
          break;
        }
      }
      if (!p_match)
        continue;

      free(g_running[i].cfg.db_host);
      free(g_running[i].cfg.db_user);
      free(g_running[i].cfg.db_pass);
      free(g_running[i].cfg.db_name);
      g_running[i].cfg = p_match->config;

      g_running[i].cfg.db_host = strdup(p_match->config.db_host);
      g_running[i].cfg.db_user = strdup(p_match->config.db_user);
      g_running[i].cfg.db_pass = strdup(p_match->config.db_pass);
      g_running[i].cfg.db_name = strdup(p_match->config.db_name);
      g_running[i].needs_update = 1;
    }
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
  RunningProfile *old = g_running;
  int old_count = g_running_count;
  if (old) {
    for (int i = 0; i < old_count; i++)
      old[i].should_stop = 1;
  }
  g_running = NULL;
  g_running_count = 0;
  g_prepare_exec = 0;
  wamble_mutex_unlock(&g_mutex);

  join_and_cleanup_profiles(old, old_count, 1);

  RunningProfile *new_running = NULL;
  if (new_count > 0) {
    new_running = calloc((size_t)new_count, sizeof(RunningProfile));
    if (!new_running) {
      for (int i = 0; i < new_count; i++)
        wamble_close_socket(pb[i].sockfd);
      free(pb);
      return PROFILE_START_THREAD_ERROR;
    }
    for (int i = 0; i < new_count; i++) {
      new_running[i].sockfd = WAMBLE_INVALID_SOCKET;
      new_running[i].thread = 0;
    }
    for (int i = 0; i < new_count; i++) {
      const WambleProfile *p = config_get_profile(pb[i].profile_index);
      RunningProfile *rp = &new_running[i];
      rp->name = strdup(p->name);
      rp->cfg = p->config;

      rp->cfg.db_host = strdup(p->config.db_host);
      rp->cfg.db_user = strdup(p->config.db_user);
      rp->cfg.db_pass = strdup(p->config.db_pass);
      rp->cfg.db_name = strdup(p->config.db_name);
      rp->sockfd = pb[i].sockfd;
      rp->should_stop = 0;
      rp->needs_update = 0;
      if (rp->sockfd == WAMBLE_INVALID_SOCKET) {
        join_and_cleanup_profiles(new_running, new_count, 1);
        for (int j = i + 1; j < new_count; j++)
          wamble_close_socket(pb[j].sockfd);
        free(pb);
        return PROFILE_START_NO_SOCKET;
      }
      if (wamble_thread_create(&rp->thread, profile_thread_main, rp) != 0) {
        for (int j = 0; j < i; j++) {
          new_running[j].should_stop = 1;
        }
        join_and_cleanup_profiles(new_running, new_count, 1);
        for (int j = i + 1; j < new_count; j++)
          wamble_close_socket(pb[j].sockfd);
        free(pb);
        return PROFILE_START_THREAD_ERROR;
      }
    }
  }

  free(pb);

  wamble_mutex_lock(&g_mutex);
  g_running = new_running;
  g_running_count = new_count;
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
    if (!rp->name || rp->sockfd == WAMBLE_INVALID_SOCKET)
      continue;

    char part[128];
    unsigned long long sock_val = (unsigned long long)rp->sockfd;
    snprintf(part, sizeof(part), "%s=%llu", rp->name, sock_val);
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

void profile_mark_sockets_inheritable(void) {
#if defined(WAMBLE_PLATFORM_POSIX)
  ensure_mutex_init();
  for (int i = 0; i < g_running_count; i++) {
    if (g_running[i].sockfd != WAMBLE_INVALID_SOCKET) {
      int flags = fcntl(g_running[i].sockfd, F_GETFD);
      if (flags >= 0) {
        (void)fcntl(g_running[i].sockfd, F_SETFD, flags & ~FD_CLOEXEC);
      }
    }
  }
#elif defined(WAMBLE_PLATFORM_WINDOWS)
  ensure_mutex_init();
  for (int i = 0; i < g_running_count; i++) {
    if (g_running[i].sockfd != WAMBLE_INVALID_SOCKET) {
      HANDLE h = (HANDLE)g_running[i].sockfd;
      SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    }
  }
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
    wamble_mutex_lock(&g_mutex);
    for (int i = 0; i < g_running_count; i++) {
      if (!g_running[i].ready_for_exec) {
        all_ready = 0;
        break;
      }
    }
    wamble_mutex_unlock(&g_mutex);
    if (all_ready) {
      ready = 1;
      break;
    }
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
    if (!g_running[i].name || !g_running[i].state_path)
      continue;
    char part[512];
    snprintf(part, sizeof(part), "%s=%s", g_running[i].name,
             g_running[i].state_path);
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
