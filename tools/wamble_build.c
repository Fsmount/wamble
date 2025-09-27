#define _XOPEN_SOURCE 700
#include <dirent.h>
#include <errno.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static int runv(const char *cwd, char *const argv[]) {
  pid_t pid;
  int rc;
  fprintf(stderr, "[exec] %s", argv[0]);
  for (int i = 1; argv[i]; i++) {
    fprintf(stderr, " %s", argv[i]);
  }
  fprintf(stderr, "\n");

  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  if (cwd && *cwd) {
  }

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
}

static int ensure_dir(const char *path) {
  struct stat st;
  if (stat(path, &st) == 0) {
    if (S_ISDIR(st.st_mode))
      return 0;
    fprintf(stderr, "[err] %s exists and is not a directory\n", path);
    return -1;
  }
  if (mkdir(path, 0777) != 0 && errno != EEXIST) {
    perror("mkdir");
    return -1;
  }
  return 0;
}

static int has_suffix(const char *s, const char *suf) {
  size_t ls = strlen(s), lf = strlen(suf);
  return ls >= lf && strcmp(s + ls - lf, suf) == 0;
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

static int file_exists(const char *p) {
  struct stat st;
  return stat(p, &st) == 0 && S_ISREG(st.st_mode);
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

static int compile_objects_to_lib(const char *cc, int with_db) {
  DIR *d = opendir("src");
  struct dirent *e;
  if (!d) {
    perror("opendir src");
    return -1;
  }
  while ((e = readdir(d)) != NULL) {
    if (!has_suffix(e->d_name, ".c"))
      continue;
    if (strcmp(e->d_name, "main.c") == 0)
      continue;

    if (strcmp(e->d_name, "database.c") == 0)
      continue;
    char srcpath[512], objpath[512];
    snprintf(srcpath, sizeof(srcpath), "src/%s", e->d_name);
    struct stat st;
    if (stat(srcpath, &st) != 0 || !S_ISREG(st.st_mode))
      continue;
    char base[256];
    snprintf(base, sizeof(base), "%s", e->d_name);
    size_t bl = strlen(base);
    if (bl > 2 && base[bl - 2] == '.' && base[bl - 1] == 'c') {
      base[bl - 2] = '\0';
    }
    snprintf(objpath, sizeof(objpath), "build/obj/%s.o", base);

    int need = is_src_newer_than_obj(srcpath, objpath);
    if (need) {
      strvec ccargs;
      sv_init(&ccargs);
      sv_push(&ccargs, (char *)cc);
      sv_push(&ccargs, "-O2");
      sv_push(&ccargs, "-std=c99");
      sv_push(&ccargs, "-Iinclude");
      sv_push(&ccargs, "-c");
      sv_push(&ccargs, srcpath);
      sv_push(&ccargs, "-o");
      sv_push(&ccargs, objpath);
      if (runv(NULL, ccargs.data) != 0) {
        fprintf(stderr, "[err] failed compiling %s\n", srcpath);
        sv_free(&ccargs);
        closedir(d);
        return -1;
      }
      sv_free(&ccargs);
    } else {
      fprintf(stderr, "[skip] up-to-date %s\n", objpath);
    }
  }
  closedir(d);

  strvec ar;
  sv_init(&ar);
  sv_push(&ar, "ar");
  sv_push(&ar, "rcs");
  sv_push(&ar, "build/libwamble.a");
  DIR *od = opendir("build/obj");
  if (!od) {
    perror("opendir build/obj");
    sv_free(&ar);
    return -1;
  }
  while ((e = readdir(od)) != NULL) {
    if (!has_suffix(e->d_name, ".o"))
      continue;
    char objpath[512];
    snprintf(objpath, sizeof(objpath), "build/obj/%s", e->d_name);
    sv_push(&ar, objpath);
  }
  closedir(od);
  if (runv(NULL, ar.data) != 0) {
    fprintf(stderr, "[err] failed to archive build/libwamble.a\n");
    sv_free(&ar);
    return -1;
  }
  sv_free(&ar);
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
  int with_db = 0;
  const char *cc = "c99";
  int clean = 0;
  int warn = 0;
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
    } else if (strcmp(argv[i], "--with-db") == 0) {
      with_db = 1;
    } else if (strcmp(argv[i], "--clean") == 0) {
      clean = 1;
    } else if (strcmp(argv[i], "--warn") == 0) {
      warn = 1;
    } else if (strncmp(argv[i], "--cc=", 5) == 0) {
      cc = argv[i] + 5;
    } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      printf(
          "Usage: %s [--server] [--tests] [--run-tests] [--with-db] [--clean] "
          "[--warn] [--cc=CC] [-- <test args>]\n",
          argv[0]);
      printf("  --server      Build the server binary (requires libpq "
             "installed)\n");
      printf("  --tests       Build unified test binary\n");
      printf("  --run-tests   Execute tests after building\n");
      printf("  --with-db     Include database.c and link -lpq for tests\n");
      printf("  --warn        Enable extra compiler warnings\n");
      printf("  --cc=CC       Use custom C compiler (default: c99 or $CC)\n");
      printf("  --clean       Remove build artifacts (lib, objs, bins)\n");
      printf("  --            Pass subsequent args to test runner\n");
      return 0;
    }
  }
  {
    const char *cc_env = getenv("CC");
    if (cc_env && *cc_env)
      cc = cc_env;
  }

  if (clean) {
    runv(NULL, (char *[]){"rm", "-f", "build/libwamble.a", NULL});
    runv(NULL, (char *[]){"rm", "-f", "build/wamble", NULL});
    runv(NULL, (char *[]){"rm", "-f", "build/tests/wamble_tests", NULL});
    DIR *od = opendir("build/obj");
    struct dirent *oe;
    if (od) {
      while ((oe = readdir(od)) != NULL) {
        if (has_suffix(oe->d_name, ".o")) {
          char p[512];
          snprintf(p, sizeof(p), "build/obj/%s", oe->d_name);
          runv(NULL, (char *[]){"rm", "-f", p, NULL});
        }
      }
      closedir(od);
    }
  }
  if (ensure_dir("build") || ensure_dir("build/obj") ||
      ensure_dir("build/tests"))
    return 1;

  DIR *d;
  struct dirent *e;

  if (build_server || build_tests) {
    if (compile_objects_to_lib(cc, with_db) != 0)
      return 1;
  }

  if (build_server) {
    strvec link_args;
    sv_init(&link_args);
    sv_push(&link_args, (char *)cc);
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
    sv_push(&targs, (char *)cc);
    sv_push(&targs, "-O2");
    sv_push(&targs, "-std=c99");
    append_warn_flags(&targs, warn);
    sv_push(&targs, "-Iinclude");
    sv_push(&targs, "-Itests/common");
    sv_push(&targs, "tests/common/wamble_test.c");
    sv_push(&targs, "build/libwamble.a");
    if (with_db) {
      sv_push(&targs, "src/database.c");
    }
    d = opendir("tests");
    if (!d) {
      perror("opendir tests");
      sv_free(&targs);
      return 1;
    }
    while ((e = readdir(d)) != NULL) {
      if (e->d_name[0] == '.')
        continue;
      if (!has_suffix(e->d_name, ".c"))
        continue;
      if (strncmp(e->d_name, "harness", 7) == 0 ||
          strncmp(e->d_name, "common", 6) == 0)
        continue;
      char tsrc[512];
      snprintf(tsrc, sizeof(tsrc), "tests/%s", e->d_name);
      struct stat st;
      if (stat(tsrc, &st) != 0 || !S_ISREG(st.st_mode))
        continue;
      sv_push(&targs, tsrc);
    }
    closedir(d);
    sv_push(&targs, "-lm");
    sv_push(&targs, "-lpthread");
    if (with_db)
      sv_push(&targs, "-lpq");
    sv_push(&targs, "-o");
    sv_push(&targs, "build/tests/wamble_tests");
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
      sv_push(&runv_args, "--verbose");
      sv_push(&runv_args, "--timeout-ms");
      sv_push(&runv_args, "5000");
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
  return 0;
}
