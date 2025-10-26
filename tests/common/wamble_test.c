#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "wamble_test.h"
#include "wamble/wamble.h"

#if defined(__GNUC__)
__attribute__((weak)) void wamble_register_tests(void) {}
#else
void wamble_register_tests(void) {}
#endif

#include <errno.h>
#include <math.h>
#include <signal.h>
#include <stdarg.h>
#include <time.h>
#if defined(WAMBLE_PLATFORM_POSIX)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#endif

static int run_one_isolated(const wamble_test_case *tc, int timeout_ms,
                            double *duration_out);
static double monotime_sec(void);
#if defined(WAMBLE_PLATFORM_POSIX)
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif
#if defined(WAMBLE_PLATFORM_WINDOWS)
#include <windows.h>
#endif

WAMBLE_TEST_THREAD_LOCAL char g_wamble_test_fail_msg[1024];
WAMBLE_TEST_THREAD_LOCAL const char *g_wamble_test_fail_file = NULL;
WAMBLE_TEST_THREAD_LOCAL int g_wamble_test_fail_line = 0;

static wamble_test_case g_cases[1024];
static int g_case_count = 0;
static int g_verbose = 0;
static unsigned long g_seed = 0;

typedef struct {
  char *name;
  double last_ms;
  int has_last;
  int updated;
} timing_entry;

static timing_entry g_timings[1024];
static int g_timing_count = 0;
static int g_timings_loaded = 0;
static int g_timings_dirty = 0;
static const char *g_timing_path = "build/tests/.wamble_test_timings";

static void strip_newline(char *s) {
  if (!s)
    return;
  size_t len = strlen(s);
  if (len && s[len - 1] == '\n')
    s[len - 1] = '\0';
}

static timing_entry *timing_find(const char *name) {
  for (int i = 0; i < g_timing_count; i++) {
    if (strcmp(g_timings[i].name, name) == 0)
      return &g_timings[i];
  }
  return NULL;
}

static timing_entry *timing_add(const char *name) {
  if (g_timing_count >= (int)(sizeof(g_timings) / sizeof(g_timings[0])))
    return NULL;
  timing_entry *e = &g_timings[g_timing_count++];
  e->name = strdup(name);
  if (!e->name) {
    g_timing_count--;
    return NULL;
  }
  e->last_ms = 0.0;
  e->has_last = 0;
  e->updated = 0;
  return e;
}

static void timing_load(void) {
  if (g_timings_loaded)
    return;
  g_timings_loaded = 1;
  FILE *f = fopen(g_timing_path, "r");
  if (!f)
    return;
  char line[1024];
  while (fgets(line, sizeof(line), f)) {
    strip_newline(line);
    if (*line == '\0')
      continue;
    char *tab = strrchr(line, '\t');
    if (!tab)
      continue;
    *tab = '\0';
    const char *name = line;
    const char *val_str = tab + 1;
    if (!*name || !*val_str)
      continue;
    char *endptr = NULL;
    double val = strtod(val_str, &endptr);
    if (endptr == val_str)
      continue;
    timing_entry *e = timing_find(name);
    if (!e)
      e = timing_add(name);
    if (!e)
      continue;
    e->last_ms = val;
    e->has_last = 1;
    e->updated = 0;
  }
  fclose(f);
}

typedef struct {
  double ratio;
  double prev_ms;
  int has_prev;
} timing_result;

static timing_result timing_record(const char *name, double current_ms) {
  timing_load();
  timing_result result;
  result.prev_ms = 0.0;
  result.has_prev = 0;
  result.ratio = 1.0;

  timing_entry *entry = timing_find(name);
  if (!entry)
    entry = timing_add(name);
  if (entry) {
    if (entry->has_last && entry->last_ms > 0.0) {
      result.prev_ms = entry->last_ms;
      result.has_prev = 1;
      result.ratio = current_ms / entry->last_ms;
    }
    entry->last_ms = current_ms;
    entry->has_last = 1;
    entry->updated = 1;
    g_timings_dirty = 1;
  }
  return result;
}

static void timing_save(void) {
  if (!g_timings_dirty)
    return;
  if (wamble_test_ensure_dir("build") != 0)
    return;
  if (wamble_test_ensure_dir("build/tests") != 0)
    return;
  char tmp_path[256];
  snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", g_timing_path);
  FILE *f = fopen(tmp_path, "w");
  if (!f)
    return;
  for (int i = 0; i < g_timing_count; i++) {
    timing_entry *e = &g_timings[i];
    if (!e->name || !*e->name)
      continue;
    if (!e->has_last)
      continue;
    fprintf(f, "%s\t%.6f\n", e->name, e->last_ms);
  }
  fclose(f);
  rename(tmp_path, g_timing_path);
  g_timings_dirty = 0;
}

static void make_key(char *out, size_t out_sz, const char *name,
                     const char *suffix) {
  if (!suffix || !*suffix) {
    snprintf(out, out_sz, "%s", name);
  } else {
    snprintf(out, out_sz, "%s %s", name, suffix);
  }
}

typedef enum { TM_ISOLATED = 0, TM_CONCURRENT = 1, TM_BOTH = 2 } timing_mode_t;

#if defined(WAMBLE_PLATFORM_POSIX)
typedef struct {
  volatile int *stop;
} cpu_ctx;

static void *cpu_worker(void *arg) {
  cpu_ctx *c = (cpu_ctx *)arg;
  volatile double x = 0.0;
  while (!*(c->stop)) {
    for (int i = 0; i < 10000; i++)
      x += (double)i * 0.000001;
  }
  (void)x;
  return NULL;
}

typedef struct {
  volatile int *stop;
} net_ctx;

static void *net_worker(void *arg) {
  net_ctx *c = (net_ctx *)arg;
  uint8_t buf[64];
  for (int i = 0; i < (int)sizeof(buf); i++)
    buf[i] = (uint8_t)i;

  wamble_socket_t srv = create_and_bind_socket(0);
  if (srv != WAMBLE_INVALID_SOCKET) {
    wamble_socket_t cli = socket(AF_INET, SOCK_DGRAM, 0);
    if (cli != WAMBLE_INVALID_SOCKET) {
      struct sockaddr_in bindaddr;
      memset(&bindaddr, 0, sizeof(bindaddr));
      bindaddr.sin_family = AF_INET;
      bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      bindaddr.sin_port = 0;
      bind(cli, (struct sockaddr *)&bindaddr, sizeof(bindaddr));

      struct sockaddr_in dst;
      memset(&dst, 0, sizeof(dst));
      struct sockaddr_in srvbind;
      wamble_socklen_t sl = (wamble_socklen_t)sizeof(srvbind);
      if (getsockname(srv, (struct sockaddr *)&srvbind, &sl) == 0) {
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        dst.sin_port = srvbind.sin_port;

        while (!*(c->stop)) {
          sendto(cli, (const char *)buf, sizeof(buf), 0,
                 (struct sockaddr *)&dst, sizeof(dst));
          struct timespec ts = {.tv_sec = 0, .tv_nsec = 1000 * 1000};
          nanosleep(&ts, NULL);
        }
      }
      wamble_close_socket(cli);
    }
    wamble_close_socket(srv);
  }
  return NULL;
}

typedef struct {
  pthread_t *cpu_threads;
  int cpu_count;
  pthread_t net_thread;
  int have_net;
  volatile int stop;
} bg_runner;

static void bg_start(bg_runner *r, int cpu_threads, int with_net) {
  r->cpu_count = cpu_threads > 0 ? cpu_threads : 0;
  r->have_net = with_net ? 1 : 0;
  r->stop = 0;
  r->cpu_threads = NULL;
  if (r->cpu_count > 0) {
    r->cpu_threads =
        (pthread_t *)calloc((size_t)r->cpu_count, sizeof(pthread_t));
    for (int i = 0; i < r->cpu_count; i++) {
      cpu_ctx *ctx = (cpu_ctx *)malloc(sizeof(cpu_ctx));
      ctx->stop = &r->stop;
      pthread_create(&r->cpu_threads[i], NULL, cpu_worker, ctx);
    }
  }
  if (r->have_net) {
    net_ctx *nctx = (net_ctx *)malloc(sizeof(net_ctx));
    nctx->stop = &r->stop;
    pthread_create(&r->net_thread, NULL, net_worker, nctx);
  }
}

static void bg_stop(bg_runner *r) {
  r->stop = 1;
  if (r->have_net) {
    pthread_join(r->net_thread, NULL);
  }
  for (int i = 0; i < r->cpu_count; i++) {
    pthread_join(r->cpu_threads[i], NULL);
  }
  free(r->cpu_threads);
  r->cpu_threads = NULL;
}

static int run_one_concurrent(const wamble_test_case *tc, int timeout_ms,
                              double *duration_out, int cpu_threads,
                              int with_net) {

  double start = monotime_sec();
  int status = 0;
  pid_t pid = fork();
  if (pid < 0) {
    perror("fork");
    return -1;
  }
  if (pid == 0) {

    bg_runner r;
    bg_start(&r, cpu_threads, with_net);

    fprintf(stdout, "=== RUN %s%s%s timeout=%dms seed=%lu\n", tc->name,
            (tc->tags && *tc->tags) ? " tags=" : "",
            (tc->tags && *tc->tags) ? tc->tags : "",
            (timeout_ms > 0 ? timeout_ms
                            : (tc->timeout_ms > 0 ? tc->timeout_ms : 5000)),
            g_seed);
    if (g_seed != 0)
      srand((unsigned)g_seed);
    if (tc->setup)
      tc->setup();
    int rc = 1;
    if (tc->fn)
      rc = tc->fn();
    else if (tc->param_fn)
      rc = tc->param_fn(tc->param_data);
    if (rc != 0) {
      if (g_wamble_test_fail_file) {
        fprintf(stderr, "    FAIL %s:%d: %s\n", g_wamble_test_fail_file,
                g_wamble_test_fail_line, g_wamble_test_fail_msg);
      }
    }
    if (tc->teardown)
      tc->teardown();
    bg_stop(&r);
    _exit(rc == 0 ? 0 : 100);
  }

  int elapsed_ms = 0;
  int effective_timeout = timeout_ms > 0
                              ? timeout_ms
                              : (tc->timeout_ms > 0 ? tc->timeout_ms : 5000);
  while (1) {
    pid_t r = waitpid(pid, &status, WNOHANG);
    if (r == pid)
      break;
    if (r < 0) {
      perror("waitpid");
      kill(pid, SIGKILL);
      waitpid(pid, &status, 0);
      status = -1;
      break;
    }
    if (elapsed_ms >= effective_timeout) {
      kill(pid, SIGKILL);
      waitpid(pid, &status, 0);
      status = -2;
      break;
    }
    struct timespec req = {0};
    req.tv_sec = 0;
    req.tv_nsec = 5 * 1000 * 1000;
    nanosleep(&req, NULL);
    elapsed_ms += 5;
  }

  *duration_out = monotime_sec() - start;

  if (status == -1)
    return -1;
  if (status == -2)
    return -2;
  if (WIFEXITED(status)) {
    int code = WEXITSTATUS(status);
    return code == 0 ? 0 : 1;
  } else if (WIFSIGNALED(status)) {
    return 2;
  }
  return 1;
}
#else
static int run_one_concurrent(const wamble_test_case *tc, int timeout_ms,
                              double *duration_out, int cpu_threads,
                              int with_net) {
  (void)cpu_threads;
  (void)with_net;
  return run_one_isolated(tc, timeout_ms, duration_out);
}
#endif

void wamble_test_register_ex(const char *name, const char *tags,
                             wamble_test_fn fn, wamble_hook_fn setup,
                             wamble_hook_fn teardown, int timeout_ms) {
  if (g_case_count >= (int)(sizeof(g_cases) / sizeof(g_cases[0]))) {
    fprintf(stderr, "[harness] too many tests registered\n");
    exit(2);
  }
  g_cases[g_case_count].name = name;
  g_cases[g_case_count].tags = tags;
  g_cases[g_case_count].fn = fn;
  g_cases[g_case_count].setup = setup;
  g_cases[g_case_count].teardown = teardown;
  g_cases[g_case_count].timeout_ms = timeout_ms;
  g_case_count++;
}

void wamble_param_register(const char *base_name, const char *tags,
                           wamble_param_test_fn fn, const void *cases,
                           size_t case_size, int count, int timeout_ms,
                           wamble_hook_fn setup, wamble_hook_fn teardown) {
  for (int i = 0; i < count; i++) {
    const char *const *name_ptr =
        (const char *const *)((const char *)cases + (size_t)i * case_size);
    const char *case_name = name_ptr ? *name_ptr : NULL;
    char full[512];
    if (case_name && *case_name) {
      snprintf(full, sizeof(full), "%s :: %s", base_name, case_name);
    } else {
      snprintf(full, sizeof(full), "%s :: #%d", base_name, i);
    }
    if (g_case_count >= (int)(sizeof(g_cases) / sizeof(g_cases[0]))) {
      fprintf(stderr, "[harness] too many tests registered\n");
      exit(2);
    }
    g_cases[g_case_count].name = strdup(full);
    g_cases[g_case_count].tags = tags;
    g_cases[g_case_count].fn = NULL;
    g_cases[g_case_count].setup = setup;
    g_cases[g_case_count].teardown = teardown;
    g_cases[g_case_count].timeout_ms = timeout_ms;
    g_cases[g_case_count].param_data =
        (const char *)cases + (size_t)i * case_size;
    g_cases[g_case_count].param_fn = fn;
    g_case_count++;
  }
}

static int any_match(const char *name, const char **filters, int n) {
  for (int i = 0; i < n; i++) {
    if (strstr(name, filters[i]))
      return 1;
  }
  return 0;
}

static int tag_has_kv(const char *tags, const char *key, const char *val) {
  if (!tags || !key || !*key || !val || !*val)
    return 0;
  const char *p = tags;
  size_t klen = strlen(key);
  while ((p = strstr(p, key)) != NULL) {
    if (p != tags) {
      char prev = p[-1];
      if (prev != ' ' && prev != ',' && prev != ';' && prev != '\t' &&
          prev != '\n') {
        p += 1;
        continue;
      }
    }
    const char *q = p + klen;
    if (*q != '=' && *q != ':') {
      p += 1;
      continue;
    }
    q += 1;
    size_t vlen = strlen(val);
    if (strncmp(q, val, vlen) == 0) {
      char term = q[vlen];
      if (term == '\0' || term == ' ' || term == ',' || term == ';' ||
          term == '\t' || term == '\n')
        return 1;
    }
    p = q;
  }
  return 0;
}

static double monotime_sec(void) {
#if defined(WAMBLE_PLATFORM_POSIX)
  struct timespec ts;
#ifdef CLOCK_MONOTONIC
  clock_gettime(CLOCK_MONOTONIC, &ts);
#else
  clock_gettime(CLOCK_REALTIME, &ts);
#endif
  return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
#else

  return (double)wamble_now_wall();
#endif
}

static int run_one_isolated(const wamble_test_case *tc, int timeout_ms,
                            double *duration_out) {
  double start = monotime_sec();
#if defined(WAMBLE_PLATFORM_POSIX)
  int status = 0;
  pid_t pid = fork();
  if (pid < 0) {
    perror("fork");
    return -1;
  }
  if (pid == 0) {
    fprintf(stdout, "=== RUN %s%s%s timeout=%dms seed=%lu\n", tc->name,
            (tc->tags && *tc->tags) ? " tags=" : "",
            (tc->tags && *tc->tags) ? tc->tags : "",
            (timeout_ms > 0 ? timeout_ms
                            : (tc->timeout_ms > 0 ? tc->timeout_ms : 5000)),
            g_seed);
    if (g_seed != 0) {
      srand((unsigned)g_seed);
    }
    if (tc->setup)
      tc->setup();
    int rc = 1;
    if (tc->fn)
      rc = tc->fn();
    else if (tc->param_fn)
      rc = tc->param_fn(tc->param_data);
    if (rc != 0) {
      if (g_wamble_test_fail_file) {
        fprintf(stderr, "    FAIL %s:%d: %s\n", g_wamble_test_fail_file,
                g_wamble_test_fail_line, g_wamble_test_fail_msg);
      }
    }
    if (tc->teardown)
      tc->teardown();
    _exit(rc == 0 ? 0 : 100);
  }

  int elapsed_ms = 0;
  int timeout = timeout_ms > 0 ? timeout_ms
                               : (tc->timeout_ms > 0 ? tc->timeout_ms : 5000);
  while (1) {
    pid_t r = waitpid(pid, &status, WNOHANG);
    if (r == pid)
      break;
    if (r < 0) {
      perror("waitpid");
      kill(pid, SIGKILL);
      waitpid(pid, &status, 0);
      status = -1;
      break;
    }
    if (elapsed_ms >= timeout) {
      kill(pid, SIGKILL);
      waitpid(pid, &status, 0);
      status = -2;
      break;
    }
    struct timespec req = {0};
    req.tv_sec = 0;
    req.tv_nsec = 5 * 1000 * 1000;
    nanosleep(&req, NULL);
    elapsed_ms += 5;
  }

  *duration_out = monotime_sec() - start;

  if (status == -1)
    return -1;
  if (status == -2)
    return -2;
  if (WIFEXITED(status)) {
    int code = WEXITSTATUS(status);
    return code == 0 ? 0 : 1;
  } else if (WIFSIGNALED(status)) {
    return 2;
  }
  return 1;
#elif defined(WAMBLE_PLATFORM_WINDOWS)
  int index = (int)(tc - g_cases);
  char exe_path[MAX_PATH];
  DWORD n = GetModuleFileNameA(NULL, exe_path, (DWORD)sizeof exe_path);
  if (n == 0 || n >= sizeof exe_path) {
    *duration_out = 0.0;
    return -1;
  }
  int effective_timeout = timeout_ms > 0
                              ? timeout_ms
                              : (tc->timeout_ms > 0 ? tc->timeout_ms : 5000);
  char cmdline[512];
  if (g_seed != 0) {
    _snprintf(cmdline, sizeof cmdline,
              "\"%s\" --run-one %d --timeout-ms %d --seed %lu", exe_path, index,
              effective_timeout, g_seed);
  } else {
    _snprintf(cmdline, sizeof cmdline, "\"%s\" --run-one %d --timeout-ms %d",
              exe_path, index, effective_timeout);
  }
  STARTUPINFOA si;
  PROCESS_INFORMATION pi;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  ZeroMemory(&pi, sizeof(pi));
  if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si,
                      &pi)) {
    *duration_out = 0.0;
    return -1;
  }
  DWORD wait_rc = WaitForSingleObject(pi.hProcess, (DWORD)effective_timeout);
  int result;
  if (wait_rc == WAIT_TIMEOUT) {
    TerminateProcess(pi.hProcess, 137);
    result = -2;
  } else if (wait_rc == WAIT_FAILED) {
    result = -1;
  } else {
    DWORD exit_code = 1;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    if (exit_code == 0) {
      result = 0;
    } else if (exit_code == 100) {
      result = 1;
    } else {
      result = 2;
    }
  }
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  *duration_out = monotime_sec() - start;
  return result;
#endif
}

int wamble_test_main(int argc, char **argv) {
  const char *name_only[64];
  const char *name_skip[64];
  int name_only_n = 0, name_skip_n = 0;
  int list_only = 0;
  int timeout_ms = 0;
  const char *only_module[32];
  const char *skip_module[32];
  int only_module_n = 0, skip_module_n = 0;
  const char *only_suite[32];
  const char *skip_suite[32];
  int only_suite_n = 0, skip_suite_n = 0;
  timing_mode_t timing_mode = TM_ISOLATED;
  int bg_threads = 0;
  int bg_net = -1;

  int run_one = -1;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--list") == 0) {
      list_only = 1;
    } else if (strcmp(argv[i], "--run-one") == 0 && i + 1 < argc) {
      run_one = atoi(argv[++i]);
    } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      printf("Usage: %s [--list] [--verbose] [--timeout-ms N] [--seed N] "
             "[--name SUBSTR] [--not-name SUBSTR] "
             "[--module M1[,M2...]] [--not-module M1[,M2...]] "
             "[--suite S1[,S2...]] [--not-suite S1[,S2...]]\n",
             argv[0]);
      return 0;
    } else if (strcmp(argv[i], "--timeout-ms") == 0 && i + 1 < argc) {
      timeout_ms = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--timing-mode") == 0 && i + 1 < argc) {
      const char *m = argv[++i];
      if (strcmp(m, "both") == 0)
        timing_mode = TM_BOTH;
      else if (strcmp(m, "concurrent") == 0)
        timing_mode = TM_CONCURRENT;
      else
        timing_mode = TM_ISOLATED;
    } else if (strcmp(argv[i], "--bg-threads") == 0 && i + 1 < argc) {
      bg_threads = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--bg-net") == 0 && i + 1 < argc) {
      bg_net = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) {
      i++;
      char buf[1024];
      size_t w = 0;
      for (; i < argc; i++) {
        if (strncmp(argv[i], "--", 2) == 0)
          break;
        size_t len = strlen(argv[i]);
        if (w + len + 1 >= sizeof(buf))
          break;
        if (w > 0)
          buf[w++] = ' ';
        memcpy(&buf[w], argv[i], len);
        w += len;
      }
      buf[w] = '\0';
      name_only[name_only_n++] = strdup(buf);
      i--;
    } else if (strcmp(argv[i], "--not-name") == 0 && i + 1 < argc) {
      i++;
      char buf[1024];
      size_t w = 0;
      for (; i < argc; i++) {
        if (strncmp(argv[i], "--", 2) == 0)
          break;
        size_t len = strlen(argv[i]);
        if (w + len + 1 >= sizeof(buf))
          break;
        if (w > 0)
          buf[w++] = ' ';
        memcpy(&buf[w], argv[i], len);
        w += len;
      }
      buf[w] = '\0';
      name_skip[name_skip_n++] = strdup(buf);
      i--;
    } else if (strcmp(argv[i], "--module") == 0 && i + 1 < argc) {
      char *val = argv[++i];
      char *p = val;
      while (p && *p) {
        char *comma = strchr(p, ',');
        if (comma)
          *comma = '\0';
        if (*p)
          only_module[only_module_n++] = strdup(p);
        if (!comma)
          break;
        p = comma + 1;
      }
    } else if (strcmp(argv[i], "--not-module") == 0 && i + 1 < argc) {
      char *val = argv[++i];
      char *p = val;
      while (p && *p) {
        char *comma = strchr(p, ',');
        if (comma)
          *comma = '\0';
        if (*p)
          skip_module[skip_module_n++] = strdup(p);
        if (!comma)
          break;
        p = comma + 1;
      }
    } else if (strcmp(argv[i], "--suite") == 0 && i + 1 < argc) {
      char *val = argv[++i];
      char *p = val;
      while (p && *p) {
        char *comma = strchr(p, ',');
        if (comma)
          *comma = '\0';
        if (*p)
          only_suite[only_suite_n++] = strdup(p);
        if (!comma)
          break;
        p = comma + 1;
      }
    } else if ((strcmp(argv[i], "--not-suite") == 0 ||
                strcmp(argv[i], "--Suite") == 0) &&
               i + 1 < argc) {
      char *val = argv[++i];
      char *p = val;
      while (p && *p) {
        char *comma = strchr(p, ',');
        if (comma)
          *comma = '\0';
        if (*p)
          skip_suite[skip_suite_n++] = strdup(p);
        if (!comma)
          break;
        p = comma + 1;
      }
    } else if (strcmp(argv[i], "--verbose") == 0) {
      g_verbose = 1;
    } else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
      g_seed = strtoul(argv[++i], NULL, 10);
    }
  }

  extern void wamble_register_tests(void);

  wamble_register_tests();

  if (run_one >= 0) {
    if (run_one < 0 || run_one >= g_case_count) {
      return 100;
    }
    const wamble_test_case *tc = &g_cases[run_one];
    fprintf(stdout, "=== RUN %s%s%s timeout=%dms seed=%lu\n", tc->name,
            (tc->tags && *tc->tags) ? " tags=" : "",
            (tc->tags && *tc->tags) ? tc->tags : "",
            (timeout_ms > 0 ? timeout_ms
                            : (tc->timeout_ms > 0 ? tc->timeout_ms : 5000)),
            g_seed);
    if (g_seed != 0)
      srand((unsigned)g_seed);
    if (tc->setup)
      tc->setup();
    int rc = 1;
    if (tc->fn)
      rc = tc->fn();
    else if (tc->param_fn)
      rc = tc->param_fn(tc->param_data);
    if (rc != 0) {
      if (g_wamble_test_fail_file) {
        fprintf(stderr, "    FAIL %s:%d: %s\n", g_wamble_test_fail_file,
                g_wamble_test_fail_line, g_wamble_test_fail_msg);
      }
    }
    if (tc->teardown)
      tc->teardown();
    timing_save();
    return rc == 0 ? 0 : 100;
  }

  if (list_only) {
    for (int i = 0; i < g_case_count; i++) {
      printf("%s\n", g_cases[i].name);
    }
    return 0;
  }

  int passed = 0, failed = 0, crashed = 0, timedout = 0, skipped = 0;
  double total_time = 0.0;
  for (int i = 0; i < g_case_count; i++) {
    const wamble_test_case *tc = &g_cases[i];
    int include =
        (name_only_n == 0) || any_match(tc->name, name_only, name_only_n);
    int excluded =
        (name_skip_n > 0) && any_match(tc->name, name_skip, name_skip_n);
    if (only_module_n > 0) {
      int ok = 0;
      for (int m = 0; m < only_module_n; m++) {
        if (tag_has_kv(tc->tags, "module", only_module[m])) {
          ok = 1;
          break;
        }
      }
      if (!ok)
        include = 0;
    }
    if (skip_module_n > 0) {
      for (int m = 0; m < skip_module_n; m++) {
        if (tag_has_kv(tc->tags, "module", skip_module[m]))
          excluded = 1;
      }
    }
    if (only_suite_n > 0) {
      int ok = 0;
      for (int s = 0; s < only_suite_n; s++) {
        if (tag_has_kv(tc->tags, "suite", only_suite[s])) {
          ok = 1;
          break;
        }
      }
      if (!ok)
        include = 0;
    }
    if (skip_suite_n > 0) {
      for (int s = 0; s < skip_suite_n; s++) {
        if (tag_has_kv(tc->tags, "suite", skip_suite[s]))
          excluded = 1;
      }
    }
    if (!include || excluded) {
      skipped++;
      continue;
    }
    double dur_iso = 0.0, dur_conc = 0.0;
    if (g_verbose)
      printf("RUN  %s\n", tc->name);
    int rc = run_one_isolated(tc, timeout_ms, &dur_iso);
    total_time += dur_iso;
    int measure_conc = 0;
    int is_speed = tag_has_kv(tc->tags, "suite", "speed") ||
                   tag_has_kv(tc->tags, "suite", "performance");
    if (is_speed && (timing_mode == TM_BOTH || timing_mode == TM_CONCURRENT))
      measure_conc = 1;

    int rc_conc = 0;
    if (rc == 0 && measure_conc) {

      int with_net = 0;
      if (bg_net >= 0)
        with_net = bg_net ? 1 : 0;
      else if (tag_has_kv(tc->tags, "module", "network"))
        with_net = 1;
      int n_cpu = bg_threads > 0 ? bg_threads : (is_speed ? 2 : 0);
      rc_conc = run_one_concurrent(tc, timeout_ms, &dur_conc, n_cpu, with_net);
    }

    if (rc == 0) {
      double current_ms = dur_iso * 1000.0;
      timing_result tres_iso = timing_record(tc->name, current_ms);
      char last_iso[32];
      if (tres_iso.has_prev) {
        snprintf(last_iso, sizeof(last_iso), "%.2f ms", tres_iso.prev_ms);
      } else {
        snprintf(last_iso, sizeof(last_iso), "N/A");
      }
      double ratio_iso = tres_iso.has_prev ? tres_iso.ratio : 1.0;

      if (measure_conc && rc_conc == 0) {
        char key[1024];
        make_key(key, sizeof(key), tc->name, "[concurrent]");
        double current_conc_ms = dur_conc * 1000.0;
        timing_result tres_conc = timing_record(key, current_conc_ms);
        double ratio_conc = tres_conc.has_prev ? tres_conc.ratio : 1.0;

        passed++;
        if (g_verbose) {
          char last_conc[32];
          if (tres_conc.has_prev) {
            snprintf(last_conc, sizeof(last_conc), "%.2f ms",
                     tres_conc.prev_ms);
          } else {
            snprintf(last_conc, sizeof(last_conc), "N/A");
          }
          printf("PASS %s (iso %.2f ms | conc %.2f ms) x%.2f [conc x%.2f] "
                 "(last iso: %s | conc: %s)\n",
                 tc->name, current_ms, current_conc_ms, ratio_iso, ratio_conc,
                 last_iso, last_conc);
        } else {
          printf("PASS %s (%.2f ms) x%.2f [conc x%.2f]\n", tc->name, current_ms,
                 ratio_iso, ratio_conc);
        }
      } else if (measure_conc && rc_conc != 0) {
        failed++;
        printf("FAIL %s (concurrent run failed)\n", tc->name);
      } else {
        passed++;
        printf("PASS %s (%.2f ms) x%.2f (last run: %s)\n", tc->name, current_ms,
               ratio_iso, last_iso);
      }
    } else if (rc == -2) {
      timedout++;
      printf("TIMEOUT %s (%.2f ms)\n", tc->name, dur_iso * 1000.0);
    } else if (rc == 2) {
      crashed++;
      printf("CRASH %s (%.2f ms)\n", tc->name, dur_iso * 1000.0);
    } else {
      failed++;
      printf("FAIL %s (%.2f ms)\n", tc->name, dur_iso * 1000.0);
    }
  }

  int total_run = passed + failed + crashed + timedout;
  printf("\nSummary: %d run, %d passed, %d failed, %d crashed, %d timed out, "
         "%d skipped in %.2f ms\n",
         total_run, passed, failed, crashed, timedout, skipped,
         total_time * 1000.0);

  timing_save();

  return (failed || crashed || timedout) ? 1 : 0;
}

int main(int argc, char **argv) { return wamble_test_main(argc, argv); }
