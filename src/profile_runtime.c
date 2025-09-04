#define _POSIX_C_SOURCE 200809L
#include "../include/wamble/wamble.h"
#include <signal.h>
#include <string.h>

typedef struct RunningProfile {
  char *name;
  wamble_thread_t thread;
  int sockfd;
  WambleConfig cfg;
  int should_stop;
  int needs_update;
} RunningProfile;

static RunningProfile *g_running = NULL;
static int g_running_count = 0;
static wamble_mutex_t g_mutex;

static int db_same(const WambleConfig *a, const WambleConfig *b) {
  return strcmp(a->db_host, b->db_host) == 0 &&
         strcmp(a->db_user, b->db_user) == 0 &&
         strcmp(a->db_name, b->db_name) == 0;
}

typedef struct Prebound {
  int profile_index;
  int sockfd;
} Prebound;

static Prebound *preflight_and_bind_all(int *out_count) {
  int count = config_profile_count();
  if (count <= 0) {
    *out_count = 0;
    return NULL;
  }

  const WambleProfile *first_adv = NULL;
  for (int i = 0; i < count; i++) {
    const WambleProfile *pi = config_get_profile(i);
    if (!pi || !pi->advertise)
      continue;
    if (!first_adv)
      first_adv = pi;
    else {
    }
    for (int j = i + 1; j < count; j++) {
      const WambleProfile *pj = config_get_profile(j);
      if (!pj || !pj->advertise)
        continue;
      if (pi->config.port == pj->config.port) {
        LOG_FATAL("Profiles %s and %s share port %d", pi->name, pj->name,
                  pi->config.port);
      }
      if (pi->db_isolated && pj->db_isolated &&
          db_same(&pi->config, &pj->config)) {
        LOG_FATAL(
            "Profiles %s and %s both require isolated DB but share the same "
            "database (host/user/name)",
            pi->name, pj->name);
      }
    }
  }

  Prebound *pb = calloc((size_t)count, sizeof(Prebound));
  int pb_count = 0;
  for (int i = 0; i < count; i++) {
    const WambleProfile *p = config_get_profile(i);
    if (!p || !p->advertise)
      continue;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
      LOG_FATAL("socket() failed for profile %s: %s", p->name, strerror(errno));
    }
    int optval = 1;
    (void)setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    int buffer_size = p->config.buffer_size;
    (void)setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &buffer_size,
                     sizeof(buffer_size));
    (void)setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &buffer_size,
                     sizeof(buffer_size));

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(p->config.port);
    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) <
        0) {

      for (int k = 0; k < pb_count; k++)
        close(pb[k].sockfd);
      LOG_FATAL("bind() failed on port %d for profile %s: %s", p->config.port,
                p->name, strerror(errno));
    }
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags >= 0)
      (void)fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    pb[pb_count].profile_index = i;
    pb[pb_count].sockfd = sockfd;
    pb_count++;
  }
  *out_count = pb_count;
  return pb;
}

static void *profile_thread_main(void *arg) {
  RunningProfile *rp = (RunningProfile *)arg;
  set_thread_config(&rp->cfg);
  network_init_thread_state();
#ifndef TEST_PROFILE_RUNTIME

  player_manager_init();
  board_manager_init();
#endif
  if (rp->sockfd <= 0) {
    LOG_FATAL("Profile %s missing pre-bound socket", rp->name);
  }

  time_t last_cleanup = time(NULL);
  time_t last_tick = time(NULL);
  while (!rp->should_stop) {

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

    int ready = select(rp->sockfd + 1, &rfds, NULL, NULL, &tv);
    if (ready > 0 && FD_ISSET(rp->sockfd, &rfds)) {
      struct WambleMsg msg;
      struct sockaddr_in cliaddr;
      int n = receive_message(rp->sockfd, &msg, &cliaddr);
      if (n > 0) {
        handle_message(rp->sockfd, &msg, &cliaddr);
      }
    }

    time_t now = time(NULL);
    if (now - last_cleanup > get_config()->cleanup_interval_sec) {
      cleanup_expired_sessions();
      last_cleanup = now;
    }
    if (now - last_tick > 1) {
#ifndef TEST_PROFILE_RUNTIME
      board_manager_tick();
#endif
      last_tick = now;
    }
  }

  close(rp->sockfd);
  rp->sockfd = -1;
  if (db_cleanup_thread) {
    db_cleanup_thread();
  }
  return NULL;
}

int start_profile_listeners(void) {
  wamble_mutex_init(&g_mutex);
  int count;
  Prebound *pb = preflight_and_bind_all(&count);
  if (count <= 0) {
    free(pb);
    return 0;
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
    if (wamble_thread_create(&rp->thread, profile_thread_main, rp) != 0) {
      LOG_FATAL("Failed to start thread for profile %s", p->name);
    }
  }
  free(pb);
  return g_running_count;
}

static void free_running(RunningProfile *rp) {
  if (!rp)
    return;
  free(rp->name);
  free(rp->cfg.db_host);
  free(rp->cfg.db_user);
  free(rp->cfg.db_pass);
  free(rp->cfg.db_name);
}

void stop_profile_listeners(void) {
  wamble_mutex_lock(&g_mutex);
  for (int i = 0; i < g_running_count; i++) {
    g_running[i].should_stop = 1;
  }

  for (int i = 0; i < g_running_count; i++) {
    wamble_thread_join(g_running[i].thread, NULL);
  }

  for (int i = 0; i < g_running_count; i++) {
    if (g_running[i].sockfd >= 0) {
      close(g_running[i].sockfd);
      g_running[i].sockfd = -1;
    }
  }
  for (int i = 0; i < g_running_count; i++) {
    free_running(&g_running[i]);
  }
  free(g_running);
  g_running = NULL;
  g_running_count = 0;
  wamble_mutex_unlock(&g_mutex);
}

void reconcile_profile_listeners(void) {
  wamble_mutex_lock(&g_mutex);

  int desired_total = config_profile_count();
  int desired_adv = 0;
  for (int i = 0; i < desired_total; i++) {
    const WambleProfile *p = config_get_profile(i);
    if (p && p->advertise)
      desired_adv++;
  }

  if (desired_adv == 0) {
    for (int i = 0; i < g_running_count; i++)
      g_running[i].should_stop = 1;
    for (int i = 0; i < g_running_count; i++)
      wamble_thread_join(g_running[i].thread, NULL);
    for (int i = 0; i < g_running_count; i++)
      free_running(&g_running[i]);
    free(g_running);
    g_running = NULL;
    g_running_count = 0;
    wamble_mutex_unlock(&g_mutex);
    return;
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
            strcmp(p->name, g_running[i].name) == 0 &&
            p->config.port == g_running[i].cfg.port) {
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
    return;
  }

  int new_count;
  Prebound *pb = preflight_and_bind_all(&new_count);
  RunningProfile *old = g_running;
  int old_count = g_running_count;
  for (int i = 0; i < old_count; i++)
    old[i].should_stop = 1;
  for (int i = 0; i < old_count; i++)
    wamble_thread_join(old[i].thread, NULL);
  g_running = NULL;
  g_running_count = 0;
  if (new_count > 0) {
    g_running = calloc((size_t)new_count, sizeof(RunningProfile));
    g_running_count = new_count;
    for (int i = 0; i < new_count; i++) {
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
      if (wamble_thread_create(&rp->thread, profile_thread_main, rp) != 0) {
        LOG_FATAL("Failed to start thread for profile %s", p->name);
      }
    }
  }
  if (old) {
    for (int i = 0; i < old_count; i++)
      free_running(&old[i]);
    free(old);
  }
  free(pb);
  wamble_mutex_unlock(&g_mutex);
}
