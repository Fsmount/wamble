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

static int clean_obj_cb(const char *name, int is_dir, void *ctx) {
  (void)ctx;
  if (is_dir)
    return 0;
  if (has_suffix(name, ".o") || has_suffix(name, ".obj")) {
    char p[512];
    snprintf(p, sizeof p, "build/obj/%s", name);
    remove(p);
  }
  return 0;
}

typedef struct {
  const char *cc;
  int warn;
  int use_msvc;
  int err;
} compile_ctx;

static int compile_src_cb(const char *name, int is_dir, void *vctx) {
  compile_ctx *c = (compile_ctx *)vctx;
  if (is_dir)
    return 0;
  if (!has_suffix(name, ".c"))
    return 0;
  if (strcmp(name, "main.c") == 0)
    return 0;
  if (strcmp(name, "database.c") == 0)
    return 0;
  char srcpath[512], objpath[512];
  snprintf(srcpath, sizeof(srcpath), "src/%s", name);
  struct stat st;
  if (stat(srcpath, &st) != 0 || !S_ISREG(st.st_mode))
    return 0;
  char base[256];
  snprintf(base, sizeof(base), "%s", name);
  size_t bl = strlen(base);
  if (bl > 2 && base[bl - 2] == '.' && base[bl - 1] == 'c')
    base[bl - 2] = '\0';
  const char *objext = c->use_msvc ? ".obj" : ".o";
  snprintf(objpath, sizeof(objpath), "build/obj/%s%s", base, objext);

  int need = is_src_newer_than_obj(srcpath, objpath);
  if (!need) {
    fprintf(stderr, "[skip] up-to-date %s\n", objpath);
    return 0;
  }

  strvec ccargs;
  sv_init(&ccargs);
  sv_push(&ccargs, (char *)c->cc);
#if defined(WAMBLE_BUILD_WINDOWS)
  if (c->use_msvc) {
    sv_push(&ccargs, "/nologo");
    sv_push(&ccargs, "/O2");
    if (c->warn)
      sv_push(&ccargs, "/W4");
    sv_push(&ccargs, "/Iinclude");
    sv_push(&ccargs, "/c");
    sv_push(&ccargs, srcpath);
    char fo[600];
    snprintf(fo, sizeof fo, "/Fo%s", objpath);
    sv_push(&ccargs, fo);
  } else
#endif
  {
    sv_push(&ccargs, "-O2");
    sv_push(&ccargs, "-std=c99");
    append_warn_flags(&ccargs, c->warn);
    sv_push(&ccargs, "-Iinclude");
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
  char tsrc[512];
  snprintf(tsrc, sizeof tsrc, "tests/%s", name);
  struct stat st;
  if (stat(tsrc, &st) != 0 || !S_ISREG(st.st_mode))
    return 0;
  sv_push(t->args, tsrc);
  return 0;
}

static int compile_objects_to_lib(const char *cc, int with_db, int warn) {
  (void)with_db;
  compile_ctx ctx;
  ctx.cc = cc;
  ctx.warn = warn;
  ctx.use_msvc = is_msvc_cc(cc);
  ctx.err = 0;

  if (iterate_dir("src", compile_src_cb, &ctx) != 0 || ctx.err)
    return -1;

  if (!ctx.use_msvc) {
    strvec ar;
    sv_init(&ar);
    sv_push(&ar, "ar");
    sv_push(&ar, "rcs");
    sv_push(&ar, "build/libwamble.a");
    collect_ctx cc2 = {&ar, "build/obj/", ".o"};
    if (iterate_dir("build/obj", collect_with_suffix_cb, &cc2) != 0) {
      perror("iterate_dir build/obj");
      sv_free(&ar);
      return -1;
    }
    if (runv(NULL, ar.data) != 0) {
      fprintf(stderr, "[err] failed to archive build/libwamble.a\n");
      sv_free(&ar);
      return -1;
    }
    sv_free(&ar);
  }
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

int main(int argc, char **argv) {
  int build_tests = 0;
  int build_server = 0;
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
      with_db = 0;
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
      printf(
          "Usage: %s [--server] [--tests] [--run-tests] [--with-db] [--clean] "
          "[--warn] [--list-tests] [--cc=CC] [-- <test args>]\n",
          argv[0]);
      printf("  --server      Build the server binary (requires libpq "
             "installed)\n");
      printf("  --tests       Build unified test binary\n");
      printf("  --run-tests   Execute tests after building\n");
      printf("  --list-tests  Build tests and list them (no run)\n");
      printf("  --with-no-db  Build tests without a real database backend\n");
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
    remove("build/libwamble.a");
    remove("build/libwamble.lib");
    remove("build/wamble");
    remove("build/wamble.exe");
    remove("build/tests/wamble_tests");
    remove("build/tests/wamble_tests.exe");
    iterate_dir("build/obj", clean_obj_cb, NULL);
  }
  if (ensure_dir("build") || ensure_dir("build/obj") ||
      ensure_dir("build/tests"))
    return 1;

  if (build_server || build_tests) {
    if (compile_objects_to_lib(cc, with_db, warn) != 0)
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
      sv_push(&link_args, "-lm");
      sv_push(&link_args, "-lpthread");
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
      if (with_db) {
        sv_push(&targs, "/DWAMBLE_ENABLE_DB");
      }

      sv_push(&targs, "/DWAMBLE_TEST_ONLY");
      sv_push(&targs, "tests/common/wamble_test.c");
      sv_push(&targs, "tests/common/wamble_test_helpers.c");
      sv_push(&targs, "tests/common/wamble_net_helpers.c");
      if (with_db) {
        sv_push(&targs, "src/database.c");
      } else {
        sv_push(&targs, "src/test/database_stub.c");
      }
      collect_ctx tcollect = {&targs, "build/obj/", ".obj"};
      iterate_dir("build/obj", collect_with_suffix_cb, &tcollect);
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
      if (with_db) {
        sv_push(&targs, "-DWAMBLE_ENABLE_DB");
      }

      sv_push(&targs, "-DWAMBLE_TEST_ONLY");
      sv_push(&targs, "tests/common/wamble_test.c");
      sv_push(&targs, "tests/common/wamble_test_helpers.c");
      sv_push(&targs, "tests/common/wamble_net_helpers.c");
      if (with_db) {
        sv_push(&targs, "src/database.c");
      } else {
        sv_push(&targs, "src/test/database_stub.c");
      }
    }
    test_src_ctx tctx = {&targs};
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
      sv_push(&targs, "-lws2_32");
      sv_push(&targs, "-lbcrypt");
      sv_push(&targs, "-o");
      sv_push(&targs, "build/tests/wamble_tests.exe");
    }
#else
    sv_push(&targs, "build/libwamble.a");
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
