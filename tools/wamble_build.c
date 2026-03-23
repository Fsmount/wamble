#define _XOPEN_SOURCE 700
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#if defined(_WIN32)
#define WAMBLE_BUILD_WINDOWS 1
#include <direct.h>
#include <io.h>
#include <process.h>
#include <windows.h>
#else
#include <dirent.h>
#include <spawn.h>
#include <strings.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

extern char **environ;

static int runv(const char *cwd, char *const argv[]) {
  fprintf(stderr, "[exec] %s", argv[0]);
  for (int i = 1; argv[i]; i++) {
    fprintf(stderr, " %s", argv[i]);
  }
  fprintf(stderr, "\n");

#if defined(WAMBLE_BUILD_WINDOWS)
  (void)cwd;
  int rc = _spawnvp(_P_WAIT, argv[0], (const char *const *)argv);
  if (rc != 0) {
    if (rc == -1) {
      perror("_spawnvp");
    } else {
      fprintf(stderr, "[err] command failed with exit code %d\n", rc);
    }
    return -1;
  }
  return 0;
#else
  pid_t pid;
  int rc;
  (void)cwd;
  if (cwd && *cwd) {
    pid = fork();
    if (pid == 0) {
      if (chdir(cwd) != 0) {
        perror("chdir");
        _exit(127);
      }
      execvp(argv[0], argv);
      perror("execvp");
      _exit(127);
    } else if (pid < 0) {
      perror("fork");
      return -1;
    }
  } else {
    rc = posix_spawnp(&pid, argv[0], NULL, NULL, argv, environ);
    if (rc != 0) {
      errno = rc;
      perror("posix_spawnp");
      return -1;
    }
  }

  int status = 0;
  if (waitpid(pid, &status, 0) < 0) {
    perror("waitpid");
    return -1;
  }
  if (WIFEXITED(status)) {
    int code = WEXITSTATUS(status);
    if (code != 0) {
      fprintf(stderr, "[err] command failed with exit code %d\n", code);
      return -1;
    }
    return 0;
  }
  if (WIFSIGNALED(status)) {
    fprintf(stderr, "[err] command terminated by signal %d\n",
            WTERMSIG(status));
    return -1;
  }
  return -1;
#endif
}

static int ensure_dir(const char *path) {
  struct stat st;
  if (stat(path, &st) == 0) {
    if (S_ISDIR(st.st_mode))
      return 0;
    fprintf(stderr, "[err] %s exists and is not a directory\n", path);
    return -1;
  }
#if defined(WAMBLE_BUILD_WINDOWS)
  if (_mkdir(path) != 0 && errno != EEXIST) {
    perror("_mkdir");
    return -1;
  }
#else
  if (mkdir(path, 0777) != 0 && errno != EEXIST) {
    perror("mkdir");
    return -1;
  }
#endif
  return 0;
}

static int has_suffix(const char *s, const char *suf) {
  size_t ls = strlen(s), lf = strlen(suf);
  return ls >= lf && strcmp(s + ls - lf, suf) == 0;
}

typedef int (*dir_entry_cb)(const char *name, int is_dir, void *ctx);

static int iterate_dir(const char *path, dir_entry_cb cb, void *ctx) {
#if defined(WAMBLE_BUILD_WINDOWS)
  char pattern[512];
  snprintf(pattern, sizeof pattern, "%s/*", path);
  WIN32_FIND_DATAA ffd;
  HANDLE h = FindFirstFileA(pattern, &ffd);
  if (h == INVALID_HANDLE_VALUE)
    return -1;
  int keep = 1;
  do {
    const char *name = ffd.cFileName;
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
      continue;
    int isdir = (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
    if (cb(name, isdir, ctx) != 0) {
      keep = 0;
      break;
    }
  } while (FindNextFileA(h, &ffd) != 0);
  FindClose(h);
  return keep ? 0 : -1;
#else
  DIR *d = opendir(path);
  if (!d) {
    return -1;
  }
  struct dirent *e;
  while ((e = readdir(d)) != NULL) {
    if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
      continue;
    char full[512];
    snprintf(full, sizeof full, "%s/%s", path, e->d_name);
    struct stat st;
    if (stat(full, &st) != 0)
      continue;
    int isdir = S_ISDIR(st.st_mode) ? 1 : 0;
    if (cb(e->d_name, isdir, ctx) != 0) {
      closedir(d);
      return -1;
    }
  }
  closedir(d);
  return 0;
#endif
}

typedef struct {
  char **data;
  int count;
  int cap;
} strvec;

static void sv_init(strvec *v) {
  v->data = NULL;
  v->count = 0;
  v->cap = 0;
}
static void sv_push(strvec *v, const char *s) {
  if (v->count + 1 >= v->cap) {
    int ncap = v->cap ? v->cap * 2 : 16;
    char **nd = realloc(v->data, (size_t)ncap * sizeof(char *));
    if (!nd) {
      fprintf(stderr, "[err] OOM\n");
      exit(1);
    }
    v->data = nd;
    v->cap = ncap;
  }
  v->data[v->count++] = strdup(s);
  v->data[v->count] = NULL;
}
static void sv_free(strvec *v) {
  for (int i = 0; i < v->count; i++)
    free(v->data[i]);
  free(v->data);
  v->data = NULL;
  v->count = v->cap = 0;
}

static int is_src_newer_than_obj(const char *src, const char *obj) {
  struct stat ss, os;
  if (stat(src, &ss) != 0)
    return 1;
  if (stat(obj, &os) != 0)
    return 1;
  if (ss.st_mtime > os.st_mtime)
    return 1;
  return 0;
}

static void append_warn_flags(strvec *v, int warn);
#if defined(WAMBLE_BUILD_WINDOWS)
static int strncasecmp_portable(const char *a, const char *b, size_t n) {
  return _strnicmp(a, b, (int)n);
}
#endif
static int is_msvc_cc(const char *cc) {
#if defined(WAMBLE_BUILD_WINDOWS)
  if (!cc || !*cc)
    return 0;
  const char *base = cc;
  const char *p = cc;
  while (*p) {
    if (*p == '/' || *p == '\\')
      base = p + 1;
    p++;
  }
  const char *ext = strrchr(base, '.');
  size_t len = ext ? (size_t)(ext - base) : strlen(base);
  if (len == 2 && (base[0] == 'c' || base[0] == 'C') &&
      (base[1] == 'l' || base[1] == 'L'))
    return 1;
  if (len == 8 && (strncasecmp_portable(base, "clang-cl", 8) == 0))
    return 1;
#else
  (void)cc;
#endif
  return 0;
}

typedef struct {
  const char *dir;
} clean_obj_ctx;

static int clean_obj_cb(const char *name, int is_dir, void *ctx) {
  const clean_obj_ctx *c = (const clean_obj_ctx *)ctx;
  const char *dir = (c && c->dir) ? c->dir : "build/obj";
  if (is_dir)
    return 0;
  if (has_suffix(name, ".o") || has_suffix(name, ".obj")) {
    char p[512];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    remove(p);
  }
  return 0;
}

#define COMPILE_SKIP_MAX 8

typedef struct {
  const char *cc;
  const char *src_dir;
  const char *obj_dir;
  int warn;
  int gnu99;         /* 1: -std=gnu99, 0: -std=c99 */
  int section_flags; /* 1: add -ffunction-sections -fdata-sections */
  int test_mode;     /* 1: add WAMBLE_TEST_ONLY / TEST_PROFILE_RUNTIME */
  int use_msvc;
  const char *skip[COMPILE_SKIP_MAX]; /* NULL terminated list of filenames */
  int err;
} compile_unit_ctx;

static int compile_unit_cb(const char *name, int is_dir, void *vctx) {
  compile_unit_ctx *c = (compile_unit_ctx *)vctx;
  char srcpath[512], objpath[512], base[256], fo_buf[600];
  const char *objext;
  size_t bl;
  struct stat st;
  int i;
  strvec ccargs;

  if (is_dir)
    return 0;
  if (!has_suffix(name, ".c"))
    return 0;
  for (i = 0; c->skip[i]; i++)
    if (strcmp(name, c->skip[i]) == 0)
      return 0;

  snprintf(srcpath, sizeof(srcpath), "%s/%s", c->src_dir, name);
  if (stat(srcpath, &st) != 0 || !S_ISREG(st.st_mode))
    return 0;

  snprintf(base, sizeof(base), "%s", name);
  bl = strlen(base);
  if (bl > 2 && base[bl - 2] == '.' && base[bl - 1] == 'c')
    base[bl - 2] = '\0';
  objext = c->use_msvc ? ".obj" : ".o";
  snprintf(objpath, sizeof(objpath), "%s/%s%s", c->obj_dir, base, objext);

  if (!is_src_newer_than_obj(srcpath, objpath)) {
    fprintf(stderr, "[skip] up-to-date %s\n", objpath);
    return 0;
  }

  sv_init(&ccargs);
  sv_push(&ccargs, (char *)c->cc);
#if defined(WAMBLE_BUILD_WINDOWS)
  if (c->use_msvc) {
    sv_push(&ccargs, "/nologo");
    sv_push(&ccargs, "/O2");
    if (c->warn)
      sv_push(&ccargs, "/W4");
    sv_push(&ccargs, "/Iinclude");
    if (c->test_mode) {
      sv_push(&ccargs, "/DTEST_PROFILE_RUNTIME");
      sv_push(&ccargs, "/DWAMBLE_TEST_ONLY");
    }
    sv_push(&ccargs, "/c");
    sv_push(&ccargs, srcpath);
    snprintf(fo_buf, sizeof(fo_buf), "/Fo%s", objpath);
    sv_push(&ccargs, fo_buf);
  } else
#endif
  {
    sv_push(&ccargs, "-O2");
    sv_push(&ccargs, c->gnu99 ? "-std=gnu99" : "-std=c99");
    if (c->section_flags) {
      sv_push(&ccargs, "-ffunction-sections");
      sv_push(&ccargs, "-fdata-sections");
    }
    append_warn_flags(&ccargs, c->warn);
    sv_push(&ccargs, "-Iinclude");
    if (c->test_mode) {
      sv_push(&ccargs, "-DTEST_PROFILE_RUNTIME");
      sv_push(&ccargs, "-DWAMBLE_TEST_ONLY");
    }
    sv_push(&ccargs, "-c");
    sv_push(&ccargs, srcpath);
    sv_push(&ccargs, "-o");
    sv_push(&ccargs, objpath);
  }
  if (runv(NULL, ccargs.data) != 0) {
    fprintf(stderr, "[err] failed compiling %s\n", srcpath);
    sv_free(&ccargs);
    c->err = 1;
    return -1;
  }
  sv_free(&ccargs);
  return 0;
}

typedef struct {
  strvec *vec;
  const char *dir_prefix;
  const char *suffix;
} collect_ctx;

static int collect_with_suffix_cb(const char *name, int is_dir, void *vctx) {
  collect_ctx *c = (collect_ctx *)vctx;
  if (is_dir)
    return 0;
  if (!has_suffix(name, c->suffix))
    return 0;
  char p[512];
  snprintf(p, sizeof p, "%s%s", c->dir_prefix ? c->dir_prefix : "", name);
  sv_push(c->vec, p);
  return 0;
}

typedef struct {
  strvec *args;
  int with_db;
} test_src_ctx;

static int append_tests_cb(const char *name, int is_dir, void *vctx) {
  test_src_ctx *t = (test_src_ctx *)vctx;
  if (is_dir)
    return 0;
  if (name[0] == '.')
    return 0;
  if (!has_suffix(name, ".c"))
    return 0;
  if (strncmp(name, "harness", 7) == 0 || strncmp(name, "common", 6) == 0)
    return 0;
  (void)t; // always include tests; DB is always enabled
  char tsrc[512];
  snprintf(tsrc, sizeof tsrc, "tests/%s", name);
  struct stat st;
  if (stat(tsrc, &st) != 0 || !S_ISREG(st.st_mode))
    return 0;
  sv_push(t->args, tsrc);
  return 0;
}

static int archive_obj_dir(const char *obj_dir, const char *obj_prefix,
                           const char *out_lib) {
  strvec ar;
  sv_init(&ar);
  sv_push(&ar, "ar");
  sv_push(&ar, "rcs");
  sv_push(&ar, (char *)out_lib);
  collect_ctx cc2 = {&ar, obj_prefix, ".o"};
  if (iterate_dir(obj_dir, collect_with_suffix_cb, &cc2) != 0) {
    fprintf(stderr, "[err] iterate_dir %s\n", obj_dir);
    sv_free(&ar);
    return -1;
  }
  if (runv(NULL, ar.data) != 0) {
    fprintf(stderr, "[err] failed to archive %s\n", out_lib);
    sv_free(&ar);
    return -1;
  }
  sv_free(&ar);
  return 0;
}

static int compile_objects_to_lib(const char *cc, int with_db, int warn,
                                  int test_mode) {
  (void)with_db;
  int msvc = is_msvc_cc(cc);
  compile_unit_ctx src_ctx = {cc, "src",     "build/obj", warn,  0,
                              0,  test_mode, msvc,        {NULL}};
  compile_unit_ctx tp_ctx = {cc, "thirdparty", "build/obj", 0, 0, 0,
                             0,  msvc,         {NULL}};
  if (iterate_dir("src", compile_unit_cb, &src_ctx) != 0 || src_ctx.err)
    return -1;
  if (iterate_dir("thirdparty", compile_unit_cb, &tp_ctx) != 0 || tp_ctx.err)
    return -1;
  if (!msvc)
    return archive_obj_dir("build/obj", "build/obj/", "build/libwamble.a");
  return 0;
}

static int compile_client_objects_to_lib(const char *cc, int warn) {
  int msvc = is_msvc_cc(cc);
  compile_unit_ctx ctx = {cc,   "client", "build/obj_client", warn, 0, 0, 0,
                          msvc, {NULL}};
  if (iterate_dir("client", compile_unit_cb, &ctx) != 0 || ctx.err)
    return -1;
  if (!msvc)
    return archive_obj_dir("build/obj_client", "build/obj_client/",
                           "build/libwamble_client.a");
  return 0;
}

static void append_warn_flags(strvec *v, int warn) {
  if (!warn)
    return;
  sv_push(v, "-Wall");
  sv_push(v, "-Wextra");
  sv_push(v, "-Wpedantic");
  sv_push(v, "-Wshadow");
  sv_push(v, "-Wconversion");
  sv_push(v, "-Wundef");
  sv_push(v, "-Wcast-align");
  sv_push(v, "-Wpointer-arith");
  sv_push(v, "-Wstrict-prototypes");
}

static int copy_file(const char *src, const char *dst) {
  FILE *in = fopen(src, "rb");
  if (!in) {
    perror(src);
    return -1;
  }
  FILE *out = fopen(dst, "wb");
  if (!out) {
    perror(dst);
    fclose(in);
    return -1;
  }
  char buf[4096];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
    if (fwrite(buf, 1, n, out) != n) {
      fclose(in);
      fclose(out);
      return -1;
    }
  }
  fclose(in);
  fclose(out);
  return 0;
}

static int path_join(char *out, size_t out_size, const char *a, const char *b) {
  int n = snprintf(out, out_size, "%s/%s", a, b);
  if (n < 0 || (size_t)n >= out_size) {
    fprintf(stderr, "[err] path too long: %s/%s\n", a, b);
    return -1;
  }
  return 0;
}

typedef struct {
  const char *src_dir;
  const char *dst_dir;
} copy_dir_ctx;

static int copy_dir_contents(const char *src_dir, const char *dst_dir);

static int has_c_extension(const char *name) {
  size_t len = strlen(name);
  return len >= 2 && name[len - 2] == '.' && name[len - 1] == 'c';
}

static int copy_dir_cb(const char *name, int is_dir, void *ctx) {
  const copy_dir_ctx *copy = (const copy_dir_ctx *)ctx;
  char src_path[512];
  char dst_path[512];

  if (path_join(src_path, sizeof(src_path), copy->src_dir, name) != 0)
    return -1;
  if (path_join(dst_path, sizeof(dst_path), copy->dst_dir, name) != 0)
    return -1;

  if (is_dir)
    return copy_dir_contents(src_path, dst_path);

  if (has_c_extension(name))
    return 0;

  if (copy_file(src_path, dst_path) != 0)
    return -1;
  fprintf(stderr, "[copy] %s -> %s\n", src_path, dst_path);
  return 0;
}

static int copy_dir_contents(const char *src_dir, const char *dst_dir) {
  copy_dir_ctx ctx;
  if (ensure_dir(dst_dir) != 0)
    return -1;
  ctx.src_dir = src_dir;
  ctx.dst_dir = dst_dir;
  return iterate_dir(src_dir, copy_dir_cb, &ctx);
}

int main(int argc, char **argv) {
  int build_tests = 0;
  int build_server = 0;
  int build_web = 0;
  int run_tests = 0;
  int with_db = 1;
  const char *cc = "c99";
  int clean = 0;
  int warn = 0;
  int list_tests = 0;
  strvec test_args;
  sv_init(&test_args);
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--") == 0) {
      for (int j = i + 1; j < argc; j++)
        sv_push(&test_args, argv[j]);
      break;
    } else if (strcmp(argv[i], "--tests") == 0) {
      build_tests = 1;
    } else if (strcmp(argv[i], "--server") == 0) {
      build_server = 1;
    } else if (strcmp(argv[i], "--run-tests") == 0) {
      run_tests = 1;
    } else if (strcmp(argv[i], "--with-no-db") == 0) {
      fprintf(stderr, "Error: --with-no-db is no longer supported. The project "
                      "always builds with DB enabled.\n");
      return 1;
    } else if (strcmp(argv[i], "--web") == 0) {
      build_web = 1;
    } else if (strcmp(argv[i], "--clean") == 0) {
      clean = 1;
    } else if (strcmp(argv[i], "--warn") == 0) {
      warn = 1;
    } else if (strncmp(argv[i], "--cc=", 5) == 0) {
      cc = argv[i] + 5;
    } else if (strcmp(argv[i], "--list-tests") == 0) {
      build_tests = 1;
      run_tests = 1;
      list_tests = 1;
    } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      printf("Usage: %s [--server] [--tests] [--run-tests] [--web] "
             "[--clean] "
             "[--warn] [--list-tests] [--cc=CC] [-- <test args>]\n",
             argv[0]);
      printf("  --server      Build the server binary (requires libpq "
             "installed)\n");
      printf("  --tests       Build unified test binary\n");
      printf("  --run-tests   Execute tests after building\n");
      printf("  --web         Build WASM web client (requires emcc)\n");
      printf("  --list-tests  Build tests and list them (no run)\n");
      printf("  --warn        Enable extra compiler warnings\n");
      printf("  --cc=CC       Use custom C compiler (default: c99 or $CC)\n");
      printf("  --clean       Remove build artifacts (lib, objs, bins)\n");
      printf("  --            Pass subsequent args to test runner\n");
      return 0;
    } else if (argv[i][0] == '-') {
      fprintf(stderr, "Unknown option: %s\n", argv[i]);
      fprintf(stderr, "Try --help for usage.\n");
      return 1;
    }
  }
  {
    const char *cc_env = getenv("CC");
    if (cc_env && *cc_env)
      cc = cc_env;
  }

  if (run_tests && !build_tests) {
    fprintf(stderr, "Error: --run-tests requires --tests.\n");
    return 1;
  }

  if (clean) {
    clean_obj_ctx obj_ctx = {"build/obj"};
    clean_obj_ctx client_obj_ctx = {"build/obj_client"};
    clean_obj_ctx web_obj_ctx = {"build/obj_web"};
    remove("build/libwamble.a");
    remove("build/libwamble.lib");
    remove("build/libwamble_client.a");
    remove("build/wamble");
    remove("build/wamble.exe");
    remove("build/tests/wamble_tests");
    remove("build/tests/wamble_tests.exe");
    iterate_dir("build/obj", clean_obj_cb, &obj_ctx);
    iterate_dir("build/obj_client", clean_obj_cb, &client_obj_ctx);
    iterate_dir("build/obj_web", clean_obj_cb, &web_obj_ctx);
  }
  if (ensure_dir("build") || ensure_dir("build/obj") ||
      ensure_dir("build/obj_client") || ensure_dir("build/obj_web") ||
      ensure_dir("build/tests") || ensure_dir("thirdparty"))
    return 1;

  {
    char prev_mode = '\0';
    FILE *f = fopen("build/.dbmode", "rb");
    if (f) {
      prev_mode = (char)fgetc(f);
      fclose(f);
    }
    char cur_mode = with_db ? '1' : '0';
    if (prev_mode != '\0' && prev_mode != cur_mode) {
      iterate_dir("build/obj", clean_obj_cb, NULL);
    }
    f = fopen("build/.dbmode", "wb");
    if (f) {
      fputc(cur_mode, f);
      fclose(f);
    }
  }

  if (build_server || build_tests) {
    int test_mode = (build_tests && !build_server) ? 1 : 0;
    {
      char prev_mode = '\0';
      FILE *f = fopen("build/.testmode", "rb");
      if (f) {
        prev_mode = (char)fgetc(f);
        fclose(f);
      }
      char cur_mode = test_mode ? '1' : '0';
      if (prev_mode != cur_mode) {
        clean_obj_ctx obj_ctx = {"build/obj"};
        iterate_dir("build/obj", clean_obj_cb, &obj_ctx);
      }
      f = fopen("build/.testmode", "wb");
      if (f) {
        fputc(cur_mode, f);
        fclose(f);
      }
    }
    if (compile_objects_to_lib(cc, with_db, warn, test_mode) != 0)
      return 1;
    if (compile_client_objects_to_lib(cc, warn) != 0)
      return 1;
  }

  if (build_server) {
    strvec link_args;
    sv_init(&link_args);
    int msvc = is_msvc_cc(cc);
#if !defined(WAMBLE_BUILD_WINDOWS)
    (void)msvc;
#endif
    sv_push(&link_args, (char *)cc);
#if defined(WAMBLE_BUILD_WINDOWS)
    if (msvc) {
      sv_push(&link_args, "/nologo");
      sv_push(&link_args, "/O2");
      if (warn)
        sv_push(&link_args, "/W4");
      sv_push(&link_args, "/Iinclude");
      sv_push(&link_args, "src/main.c");
      if (with_db)
        sv_push(&link_args, "src/database.c");
      collect_ctx lctx = {&link_args, "build/obj/", ".obj"};
      iterate_dir("build/obj", collect_with_suffix_cb, &lctx);
      collect_ctx lctx_client = {&link_args, "build/obj_client/", ".obj"};
      iterate_dir("build/obj_client", collect_with_suffix_cb, &lctx_client);
      sv_push(&link_args, "Ws2_32.lib");
      sv_push(&link_args, "Bcrypt.lib");
      if (with_db)
        sv_push(&link_args, "libpq.lib");
      char fe[256];
      snprintf(fe, sizeof fe, "/Fe:%s", "build/wamble.exe");
      sv_push(&link_args, fe);
    } else
#endif
    {
      sv_push(&link_args, "-O2");
      sv_push(&link_args, "-std=c99");
      append_warn_flags(&link_args, warn);
      sv_push(&link_args, "-Iinclude");
      sv_push(&link_args, "src/main.c");
      sv_push(&link_args, "src/database.c");
      sv_push(&link_args, "build/libwamble.a");
      sv_push(&link_args, "build/libwamble_client.a");
      sv_push(&link_args, "-lm");
      sv_push(&link_args, "-lpthread");
      sv_push(&link_args, "-Wl,--gc-sections");
      sv_push(&link_args, "-lpq");
      sv_push(&link_args, "-o");
      sv_push(&link_args, "build/wamble");
    }
    if (runv(NULL, link_args.data) != 0) {
      fprintf(stderr,
              "[err] failed to build server executable (build/wamble)\n");
      sv_free(&link_args);
      return 1;
    }
    sv_free(&link_args);
  }

  if (build_tests) {

    strvec targs;
    sv_init(&targs);
    int msvc = is_msvc_cc(cc);
#if !defined(WAMBLE_BUILD_WINDOWS)
    (void)msvc;
#endif
    sv_push(&targs, (char *)cc);
#if defined(WAMBLE_BUILD_WINDOWS)
    if (msvc) {
      sv_push(&targs, "/nologo");
      sv_push(&targs, "/O2");
      if (warn)
        sv_push(&targs, "/W4");
      sv_push(&targs, "/Iinclude");
      sv_push(&targs, "/Itests/common");

      sv_push(&targs, "/DWAMBLE_TEST_ONLY");
      if (with_db)
        sv_push(&targs, "/DWAMBLE_ENABLE_DB");
      sv_push(&targs, "tests/common/wamble_test.c");
      sv_push(&targs, "tests/common/wamble_test_helpers.c");
      sv_push(&targs, "src/database.c");
      collect_ctx tcollect = {&targs, "build/obj/", ".obj"};
      iterate_dir("build/obj", collect_with_suffix_cb, &tcollect);
      collect_ctx tcollect_client = {&targs, "build/obj_client/", ".obj"};
      iterate_dir("build/obj_client", collect_with_suffix_cb, &tcollect_client);
      sv_push(&targs, "Ws2_32.lib");
      sv_push(&targs, "Bcrypt.lib");
      if (with_db)
        sv_push(&targs, "libpq.lib");
      char fe[256];
      snprintf(fe, sizeof fe, "/Fe:%s", "build/tests/wamble_tests.exe");
      sv_push(&targs, fe);
    } else
#endif
    {
      sv_push(&targs, "-O2");
      sv_push(&targs, "-std=c99");
      append_warn_flags(&targs, warn);
      sv_push(&targs, "-Iinclude");
      sv_push(&targs, "-Itests/common");

      sv_push(&targs, "-DWAMBLE_TEST_ONLY");
      if (with_db)
        sv_push(&targs, "-DWAMBLE_ENABLE_DB");
      sv_push(&targs, "tests/common/wamble_test.c");
      sv_push(&targs, "tests/common/wamble_test_helpers.c");
      sv_push(&targs, "src/database.c");
      sv_push(&targs, "-Wl,--gc-sections");
    }
    test_src_ctx tctx = {&targs, 1};
    if (iterate_dir("tests", append_tests_cb, &tctx) != 0) {
      perror("iterate_dir tests");
      sv_free(&targs);
      return 1;
    }

    strvec regs;
    sv_init(&regs);
    DIR *d = opendir("tests");
    if (!d) {
      perror("opendir tests");
      sv_free(&targs);
      return 1;
    }
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
      if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
        continue;
      if (strncmp(e->d_name, "common", 6) == 0 ||
          strncmp(e->d_name, "harness", 7) == 0)
        continue;
      if (!has_suffix(e->d_name, ".c"))
        continue;
      char rel[512];
      snprintf(rel, sizeof rel, "tests/%s", e->d_name);

      int included = 0;
      for (int i = 0; i < targs.count; i++) {
        if (targs.data[i] && strcmp(targs.data[i], rel) == 0) {
          included = 1;
          break;
        }
      }
      if (!included)
        continue;
      FILE *f = fopen(rel, "rb");
      if (!f)
        continue;
      fseek(f, 0, SEEK_END);
      long sz = ftell(f);
      fseek(f, 0, SEEK_SET);
      if (sz > 0) {
        char *buf = (char *)malloc((size_t)sz + 1u);
        if (buf) {
          fread(buf, 1u, (size_t)sz, f);
          buf[sz] = '\0';
          const char *needle = "WAMBLE_TESTS_BEGIN_NAMED(";
          char *p = strstr(buf, needle);
          if (p) {
            p += (int)strlen(needle);
            while (*p && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
              p++;
            char name[256];
            int w = 0;
            while (*p && *p != ')' && w < (int)sizeof(name) - 1) {
              if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
                break;
              name[w++] = *p++;
            }
            name[w] = '\0';
            if (w > 0)
              sv_push(&regs, name);
          }
          free(buf);
        }
      }
      fclose(f);
    }
    closedir(d);

    if (regs.count > 0) {
      FILE *rf = fopen("build/tests/_registry.c", "wb");
      if (!rf) {
        perror("fopen build/tests/_registry.c");
        sv_free(&regs);
        sv_free(&targs);
        return 1;
      }
      fprintf(rf, "void wamble_register_tests(void) {\n");
      for (int i = 0; i < regs.count; i++)
        fprintf(rf, "  extern void %s(void); %s();\n", regs.data[i],
                regs.data[i]);
      fprintf(rf, "}\n");
      fclose(rf);
      sv_push(&targs, "build/tests/_registry.c");
      sv_free(&regs);
    }

#if defined(WAMBLE_BUILD_WINDOWS)
    if (msvc) {
    } else {
      sv_push(&targs, "build/libwamble.a");
      sv_push(&targs, "build/libwamble_client.a");
      sv_push(&targs, "-lws2_32");
      sv_push(&targs, "-lbcrypt");
      sv_push(&targs, "-o");
      sv_push(&targs, "build/tests/wamble_tests.exe");
    }
#else
    sv_push(&targs, "build/libwamble.a");
    sv_push(&targs, "build/libwamble_client.a");
    sv_push(&targs, "-lm");
    sv_push(&targs, "-lpthread");
    if (with_db)
      sv_push(&targs, "-lpq");
    sv_push(&targs, "-o");
    sv_push(&targs, "build/tests/wamble_tests");
#endif
    if (runv(NULL, targs.data) != 0) {
      fprintf(stderr, "[err] failed to build unified test binary\n");
      sv_free(&targs);
      return 1;
    }
    sv_free(&targs);

    if (run_tests) {
      strvec runv_args;
      sv_init(&runv_args);
      sv_push(&runv_args, "build/tests/wamble_tests");
      if (list_tests) {
        sv_push(&runv_args, "--list");
      }
      for (int i = 0; i < test_args.count; i++) {
        sv_push(&runv_args, test_args.data[i]);
      }
      if (runv(NULL, runv_args.data) != 0) {
        sv_free(&runv_args);
        return 1;
      }
      sv_free(&runv_args);
    }
  }
  if (build_web) {
    if (ensure_dir("build/web") != 0)
      return 1;

    const char *emcc = "emcc";
    {
      const char *emcc_env = getenv("EMCC");
      if (emcc_env && *emcc_env)
        emcc = emcc_env;
    }
    const char *monocypher_obj = "build/obj_web/monocypher.o";

    if (is_src_newer_than_obj("thirdparty/monocypher.c", monocypher_obj)) {
      strvec monocypher_args;
      sv_init(&monocypher_args);
      sv_push(&monocypher_args, (char *)emcc);
      sv_push(&monocypher_args, "-O2");
      sv_push(&monocypher_args, "-std=gnu99");
      sv_push(&monocypher_args, "-ffunction-sections");
      sv_push(&monocypher_args, "-fdata-sections");
      sv_push(&monocypher_args, "-Iinclude");
      sv_push(&monocypher_args, "-c");
      sv_push(&monocypher_args, "thirdparty/monocypher.c");
      sv_push(&monocypher_args, "-o");
      sv_push(&monocypher_args, (char *)monocypher_obj);
      if (runv(NULL, monocypher_args.data) != 0) {
        fprintf(stderr, "[err] failed to compile thirdparty/monocypher.c\n");
        sv_free(&monocypher_args);
        return 1;
      }
      sv_free(&monocypher_args);
    } else {
      fprintf(stderr, "[skip] up-to-date %s\n", monocypher_obj);
    }

    {
      compile_unit_ctx wctx = {emcc, "web", "build/obj_web", warn, 1, 1,
                               0,    0,     {NULL}};
      if (iterate_dir("web", compile_unit_cb, &wctx) != 0 || wctx.err)
        return 1;
      wctx.src_dir = "client";
      wctx.err = 0;
      if (iterate_dir("client", compile_unit_cb, &wctx) != 0 || wctx.err)
        return 1;
    }

    if (is_src_newer_than_obj("src/move_engine.c",
                              "build/obj_web/move_engine.o")) {
      strvec wc;
      sv_init(&wc);
      sv_push(&wc, (char *)emcc);
      sv_push(&wc, "-O2");
      sv_push(&wc, "-std=gnu99");
      append_warn_flags(&wc, warn);
      sv_push(&wc, "-Iinclude");
      sv_push(&wc, "-c");
      sv_push(&wc, "src/move_engine.c");
      sv_push(&wc, "-o");
      sv_push(&wc, "build/obj_web/move_engine.o");
      if (runv(NULL, wc.data) != 0) {
        fprintf(stderr, "[err] failed compiling src/move_engine.c\n");
        sv_free(&wc);
        return 1;
      }
      sv_free(&wc);
    } else {
      fprintf(stderr, "[skip] up-to-date build/obj_web/move_engine.o\n");
    }

    {
      strvec wargs;
      sv_init(&wargs);
      sv_push(&wargs, (char *)emcc);
      sv_push(&wargs, "-O2");
      {
        collect_ctx wcc = {&wargs, "build/obj_web/", ".o"};
        if (iterate_dir("build/obj_web", collect_with_suffix_cb, &wcc) != 0) {
          perror("iterate_dir build/obj_web");
          sv_free(&wargs);
          return 1;
        }
      }
      sv_push(&wargs, "-lwebsocket.js");
      sv_push(&wargs, "-sALLOW_MEMORY_GROWTH=1");
      sv_push(&wargs, "-sEXPORTED_RUNTIME_METHODS=ccall");
      sv_push(&wargs,
              "-sEXPORTED_FUNCTIONS=_main,_wasm_on_click,_wasm_on_unload");
      sv_push(&wargs, "-o");
      sv_push(&wargs, "build/web/wamble.js");
      if (runv(NULL, wargs.data) != 0) {
        fprintf(stderr, "[err] failed to link WASM web client\n");
        sv_free(&wargs);
        return 1;
      }
      sv_free(&wargs);
    }

    if (copy_dir_contents("web", "build/web") != 0) {
      fprintf(stderr, "[err] failed to copy web directory\n");
      return 1;
    }
    fprintf(stderr, "[done] WASM web client -> build/web/\n");
  }
  if (with_db) {
    strvec dbt;
    sv_init(&dbt);
    sv_push(&dbt, (char *)cc);
    sv_push(&dbt, "-O2");
    sv_push(&dbt, "-std=c99");
    append_warn_flags(&dbt, warn);
    sv_push(&dbt, "tools/wamble_db_tool.c");
    sv_push(&dbt, "-lpq");
    sv_push(&dbt, "-o");
    sv_push(&dbt, "build/wamble_db_tool");
    if (runv(NULL, dbt.data) != 0) {
      fprintf(stderr, "[err] failed to build build/wamble_db_tool\n");
      sv_free(&dbt);
      return 1;
    }
    sv_free(&dbt);
  }
  return 0;
}
