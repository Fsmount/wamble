#include "wamble/wamble.h"
#include <string.h>

static WambleConfig g_config;

typedef enum {
  LISP_VALUE_NIL,
  LISP_VALUE_PAIR,
  LISP_VALUE_SYMBOL,
  LISP_VALUE_INTEGER,
  LISP_VALUE_FLOAT,
  LISP_VALUE_STRING,
  LISP_VALUE_BUILTIN,
} LispValueType;

struct LispValue;
struct LispEnv;

typedef struct LispValue *(*LispBuiltin)(struct LispEnv *, struct LispValue *);

typedef struct LispValue {
  LispValueType type;
  union {
    struct {
      struct LispValue *car;
      struct LispValue *cdr;
    } pair;
    char *symbol;
    int64_t integer;
    double real;
    char *string;
    LispBuiltin builtin;
  } as;
} LispValue;

typedef struct LispEnv {
  struct LispEnv *parent;
  LispValue *vars;
} LispEnv;

typedef struct {
  const char *p;
  const char *end;
} Stream;

const WambleConfig *get_config(void) { return &g_config; }

static LispValue *parse_expr(Stream *s);
static LispValue *lisp_env_get(LispEnv *env, LispValue *symbol);
static void free_lisp_value(LispValue *v);
static LispValue *make_value(LispValueType type);
static LispValue *copy_lisp_value(const LispValue *v);
void lisp_env_free(LispEnv *env);

static LispValue *copy_lisp_value(const LispValue *v) {
  if (!v)
    return NULL;
  LispValue *new_v = make_value(v->type);
  switch (v->type) {
  case LISP_VALUE_NIL:
  case LISP_VALUE_INTEGER:
  case LISP_VALUE_FLOAT:
  case LISP_VALUE_BUILTIN:
    new_v->as = v->as;
    break;
  case LISP_VALUE_SYMBOL:
    new_v->as.symbol = strdup(v->as.symbol);
    break;
  case LISP_VALUE_STRING:
    new_v->as.string = strdup(v->as.string);
    break;
  case LISP_VALUE_PAIR:
    new_v->as.pair.car = copy_lisp_value(v->as.pair.car);
    new_v->as.pair.cdr = copy_lisp_value(v->as.pair.cdr);
    break;
  }
  return new_v;
}

static void free_lisp_value(LispValue *v) {
  if (!v)
    return;
  switch (v->type) {
  case LISP_VALUE_PAIR:
    free_lisp_value(v->as.pair.car);
    free_lisp_value(v->as.pair.cdr);
    break;
  case LISP_VALUE_SYMBOL:
    free(v->as.symbol);
    break;
  case LISP_VALUE_STRING:
    free(v->as.string);
    break;
  default:
    break;
  }
  free(v);
}

void lisp_env_free(LispEnv *env) {
  if (!env)
    return;
  free_lisp_value(env->vars);
  free(env);
}

static void skip_whitespace(Stream *s) {
  while (s->p < s->end && isspace(*s->p)) {
    s->p++;
  }
}

static LispValue *make_value(LispValueType type) {
  LispValue *v = calloc(1, sizeof(LispValue));
  v->type = type;
  return v;
}

static LispValue *parse_list(Stream *s) {
  s->p++;
  skip_whitespace(s);
  if (s->p < s->end && *s->p == ')') {
    s->p++;
    return make_value(LISP_VALUE_NIL);
  }

  LispValue *head = make_value(LISP_VALUE_PAIR);
  LispValue *tail = head;
  head->as.pair.car = parse_expr(s);

  while (s->p < s->end && *s->p != ')') {
    skip_whitespace(s);
    if (s->p >= s->end) {
      LOG_ERROR("Unterminated list in config");
      free_lisp_value(head);
      return NULL;
    }
    LispValue *new_tail = make_value(LISP_VALUE_PAIR);
    new_tail->as.pair.car = parse_expr(s);
    tail->as.pair.cdr = new_tail;
    tail = new_tail;
    skip_whitespace(s);
  }
  if (s->p >= s->end) {
    LOG_ERROR("Unterminated list in config");
    free_lisp_value(head);
    return NULL;
  }
  s->p++;
  return head;
}

static LispValue *parse_string(Stream *s) {
  s->p++;
  const char *start = s->p;
  while (s->p < s->end && *s->p != '"') {
    s->p++;
  }
  LispValue *v = make_value(LISP_VALUE_STRING);
  v->as.string = strndup(start, s->p - start);
  s->p++;
  return v;
}

static LispValue *parse_symbol_or_number(Stream *s) {
  const char *start = s->p;
  bool is_float = false;
  bool is_integer = true;

  while (s->p < s->end && !isspace(*s->p) && *s->p != ')' && *s->p != '(') {
    if (*s->p == '.') {
      is_float = true;
      is_integer = false;
    } else if (!isdigit(*s->p) && !(s->p == start && *s->p == '-')) {
      is_integer = false;
      is_float = false;
    }
    s->p++;
  }

  char *str = strndup(start, s->p - start);
  if (is_integer) {
    LispValue *v = make_value(LISP_VALUE_INTEGER);
    v->as.integer = atol(str);
    free(str);
    return v;
  } else if (is_float) {
    LispValue *v = make_value(LISP_VALUE_FLOAT);
    v->as.real = atof(str);
    free(str);
    return v;
  }

  LispValue *v = make_value(LISP_VALUE_SYMBOL);
  v->as.symbol = str;
  return v;
}

static LispValue *parse_expr(Stream *s) {
  skip_whitespace(s);
  if (s->p >= s->end)
    return NULL;

  if (*s->p == '(') {
    return parse_list(s);
  } else if (*s->p == '"') {
    return parse_string(s);
  } else {
    return parse_symbol_or_number(s);
  }
}

static LispValue *eval_expr(LispEnv *env, LispValue *expr);

static LispValue *eval_list(LispEnv *env, LispValue *list) {
  if (!list || list->type == LISP_VALUE_NIL) {
    return make_value(LISP_VALUE_NIL);
  }

  LispValue *op_res = eval_expr(env, list->as.pair.car);
  if (op_res->type != LISP_VALUE_BUILTIN) {
    LOG_ERROR("Not a function");
    free_lisp_value(op_res);
    return make_value(LISP_VALUE_NIL);
  }

  LispBuiltin builtin = op_res->as.builtin;
  free_lisp_value(op_res);
  return builtin(env, list->as.pair.cdr);
}

static LispValue *eval_expr(LispEnv *env, LispValue *expr) {
  if (!expr)
    return make_value(LISP_VALUE_NIL);
  switch (expr->type) {
  case LISP_VALUE_NIL:
  case LISP_VALUE_INTEGER:
  case LISP_VALUE_FLOAT:
  case LISP_VALUE_STRING:
  case LISP_VALUE_BUILTIN:
    return copy_lisp_value(expr);
  case LISP_VALUE_SYMBOL:
    return lisp_env_get(env, expr);
  case LISP_VALUE_PAIR:
    return eval_list(env, expr);
  }
  return make_value(LISP_VALUE_NIL);
}

LispEnv *lisp_env_create(LispEnv *parent) {
  LispEnv *env = calloc(1, sizeof(LispEnv));
  env->parent = parent;
  return env;
}

void lisp_env_put(LispEnv *env, LispValue *symbol, LispValue *value) {
  LispValue *var = make_value(LISP_VALUE_PAIR);
  var->as.pair.car = copy_lisp_value(symbol);
  var->as.pair.cdr = copy_lisp_value(value);

  LispValue *binding = make_value(LISP_VALUE_PAIR);
  binding->as.pair.car = var;
  binding->as.pair.cdr = env->vars;
  env->vars = binding;
}

LispValue *lisp_env_get(LispEnv *env, LispValue *symbol) {
  for (LispValue *v = env->vars; v; v = v->as.pair.cdr) {
    LispValue *var = v->as.pair.car;
    if (strcmp(var->as.pair.car->as.symbol, symbol->as.symbol) == 0) {
      return copy_lisp_value(var->as.pair.cdr);
    }
  }
  if (env->parent) {
    return lisp_env_get(env->parent, symbol);
  }
  return make_value(LISP_VALUE_NIL);
}

static LispValue *builtin_def(LispEnv *env, LispValue *args) {
  LispValue *sym = args->as.pair.car;
  LispValue *val_expr = args->as.pair.cdr->as.pair.car;
  LispValue *val = eval_expr(env, val_expr);
  lisp_env_put(env, sym, val);
  free_lisp_value(val);
  return make_value(LISP_VALUE_NIL);
}

static LispValue *builtin_defprofile(LispEnv *env, LispValue *args) {
  LispValue *profile_name = args->as.pair.car;
  LispValue *profile_vars = args->as.pair.cdr->as.pair.car;

  LispValue *profiles_sym = make_value(LISP_VALUE_SYMBOL);
  profiles_sym->as.symbol = strdup("*profiles*");

  LispValue *profiles = lisp_env_get(env, profiles_sym);
  if (profiles->type == LISP_VALUE_NIL) {
    free_lisp_value(profiles);
    profiles = make_value(LISP_VALUE_NIL);
    lisp_env_put(env, profiles_sym, profiles);
  }

  LispValue *profile = make_value(LISP_VALUE_PAIR);
  profile->as.pair.car = copy_lisp_value(profile_name);
  profile->as.pair.cdr = copy_lisp_value(profile_vars);

  LispValue *new_profiles = make_value(LISP_VALUE_PAIR);
  new_profiles->as.pair.car = profile;
  new_profiles->as.pair.cdr = profiles;
  lisp_env_put(env, profiles_sym, new_profiles);

  free_lisp_value(profiles_sym);
  free_lisp_value(new_profiles);

  return make_value(LISP_VALUE_NIL);
}

typedef enum { CONF_INT, CONF_DOUBLE, CONF_STRING } ConfigType;

typedef struct {
  const char *name;
  ConfigType type;
  size_t offset;
} ConfigVarMap;

#define CONF_ITEM(name, type, field) {name, type, offsetof(WambleConfig, field)}

static const ConfigVarMap config_map[] = {
    CONF_ITEM("port", CONF_INT, port),
    CONF_ITEM("timeout-ms", CONF_INT, timeout_ms),
    CONF_ITEM("max-retries", CONF_INT, max_retries),
    CONF_ITEM("max-message-size", CONF_INT, max_message_size),
    CONF_ITEM("buffer-size", CONF_INT, buffer_size),
    CONF_ITEM("max-client-sessions", CONF_INT, max_client_sessions),
    CONF_ITEM("session-timeout", CONF_INT, session_timeout),
    CONF_ITEM("max-boards", CONF_INT, max_boards),
    CONF_ITEM("min-boards", CONF_INT, min_boards),
    CONF_ITEM("inactivity-timeout", CONF_INT, inactivity_timeout),
    CONF_ITEM("reservation-timeout", CONF_INT, reservation_timeout),
    CONF_ITEM("k-factor", CONF_INT, k_factor),
    CONF_ITEM("default-rating", CONF_INT, default_rating),
    CONF_ITEM("max-players", CONF_INT, max_players),
    CONF_ITEM("token-expiration", CONF_INT, token_expiration),
    CONF_ITEM("max-pot", CONF_DOUBLE, max_pot),
    CONF_ITEM("max-moves-per-board", CONF_INT, max_moves_per_board),
    CONF_ITEM("max-contributors", CONF_INT, max_contributors),
    CONF_ITEM("db-host", CONF_STRING, db_host),
    CONF_ITEM("db-user", CONF_STRING, db_user),
    CONF_ITEM("db-pass", CONF_STRING, db_pass),
    CONF_ITEM("db-name", CONF_STRING, db_name),
    CONF_ITEM("select-timeout-usec", CONF_INT, select_timeout_usec),
    CONF_ITEM("cleanup-interval-sec", CONF_INT, cleanup_interval_sec),
    CONF_ITEM("max-token-attempts", CONF_INT, max_token_attempts),
    CONF_ITEM("max-token-local-attempts", CONF_INT, max_token_local_attempts),
    CONF_ITEM("db-log-frequency", CONF_INT, db_log_frequency),
    CONF_ITEM("new-player-early-phase-mult", CONF_DOUBLE,
              new_player_early_phase_mult),
    CONF_ITEM("new-player-mid-phase-mult", CONF_DOUBLE,
              new_player_mid_phase_mult),
    CONF_ITEM("new-player-end-phase-mult", CONF_DOUBLE,
              new_player_end_phase_mult),
    CONF_ITEM("experienced-player-early-phase-mult", CONF_DOUBLE,
              experienced_player_early_phase_mult),
    CONF_ITEM("experienced-player-mid-phase-mult", CONF_DOUBLE,
              experienced_player_mid_phase_mult),
    CONF_ITEM("experienced-player-end-phase-mult", CONF_DOUBLE,
              experienced_player_end_phase_mult),
};

static void populate_config_from_env(LispEnv *env) {
  for (size_t i = 0; i < sizeof(config_map) / sizeof(config_map[0]); i++) {
    const ConfigVarMap *item = &config_map[i];
    LispValue sym;
    sym.type = LISP_VALUE_SYMBOL;
    sym.as.symbol = (char *)item->name;

    LispValue *val = lisp_env_get(env, &sym);
    if (val->type == LISP_VALUE_NIL) {
      free_lisp_value(val);
      continue;
    }

    void *target = (char *)&g_config + item->offset;
    switch (item->type) {
    case CONF_INT:
      if (val->type == LISP_VALUE_INTEGER) {
        *(int *)target = val->as.integer;
      }
      break;
    case CONF_DOUBLE:
      if (val->type == LISP_VALUE_FLOAT) {
        *(double *)target = val->as.real;
      } else if (val->type == LISP_VALUE_INTEGER) {
        *(double *)target = val->as.integer;
      }
      break;
    case CONF_STRING:
      if (val->type == LISP_VALUE_STRING) {
        free(*(char **)target);
        *(char **)target = strdup(val->as.string);
      }
      break;
    }
    free_lisp_value(val);
  }
}

static void config_set_defaults() {
  g_config.port = 8888;
  g_config.timeout_ms = 100;
  g_config.max_retries = 3;
  g_config.max_message_size = 126;
  g_config.buffer_size = 65536;
  g_config.max_client_sessions = 1024;
  g_config.session_timeout = 300;
  g_config.max_boards = 1024;
  g_config.min_boards = 4;
  g_config.inactivity_timeout = 300;
  g_config.reservation_timeout = 2;
  g_config.k_factor = 32;
  g_config.default_rating = 1200;
  g_config.max_players = 1024;
  g_config.token_expiration = 86400;
  g_config.max_pot = 20.0;
  g_config.max_moves_per_board = 1000;
  g_config.max_contributors = 100;
  g_config.db_host = strdup("localhost");
  g_config.db_user = strdup("wamble");
  g_config.db_pass = strdup("wamble");
  g_config.db_name = strdup("wamble");
  g_config.select_timeout_usec = 100000;
  g_config.cleanup_interval_sec = 60;
  g_config.max_token_attempts = 1000;
  g_config.max_token_local_attempts = 100;
  g_config.db_log_frequency = 1000;
  g_config.new_player_early_phase_mult = 2.0;
  g_config.new_player_mid_phase_mult = 1.0;
  g_config.new_player_end_phase_mult = 0.5;
  g_config.experienced_player_early_phase_mult = 0.5;
  g_config.experienced_player_mid_phase_mult = 1.0;
  g_config.experienced_player_end_phase_mult = 2.0;
}

void config_load(const char *filename, const char *profile) {
  config_set_defaults();

  FILE *f = fopen(filename, "r");
  if (!f) {
    LOG_WARN("Failed to open config file: %s. Using defaults.", filename);
    return;
  }
  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fseek(f, 0, SEEK_SET);

  char *source = malloc(fsize + 1);
  fread(source, 1, fsize, f);
  fclose(f);
  source[fsize] = 0;

  Stream s = {.p = source, .end = source + fsize};
  LispEnv *env = lisp_env_create(NULL);

  LispValue *def_sym = make_value(LISP_VALUE_SYMBOL);
  def_sym->as.symbol = strdup("def");
  LispValue *def_builtin = make_value(LISP_VALUE_BUILTIN);
  def_builtin->as.builtin = builtin_def;
  lisp_env_put(env, def_sym, def_builtin);
  free_lisp_value(def_sym);
  free_lisp_value(def_builtin);

  LispValue *defprofile_sym = make_value(LISP_VALUE_SYMBOL);
  defprofile_sym->as.symbol = strdup("defprofile");
  LispValue *defprofile_builtin = make_value(LISP_VALUE_BUILTIN);
  defprofile_builtin->as.builtin = builtin_defprofile;
  lisp_env_put(env, defprofile_sym, defprofile_builtin);
  free_lisp_value(defprofile_sym);
  free_lisp_value(defprofile_builtin);

  while (s.p < s.end) {
    LispValue *expr = parse_expr(&s);
    if (expr) {
      LispValue *result = eval_expr(env, expr);
      free_lisp_value(result);
      free_lisp_value(expr);
    }
  }

  populate_config_from_env(env);

  if (profile) {
    LispValue *profiles_sym = make_value(LISP_VALUE_SYMBOL);
    profiles_sym->as.symbol = strdup("*profiles*");
    LispValue *profiles = lisp_env_get(env, profiles_sym);
    free_lisp_value(profiles_sym);

    for (LispValue *p = profiles; p && p->type == LISP_VALUE_PAIR;
         p = p->as.pair.cdr) {
      LispValue *prof = p->as.pair.car;
      if (strcmp(prof->as.pair.car->as.symbol, profile) == 0) {
        LispEnv *profile_env = lisp_env_create(env);
        for (LispValue *v = prof->as.pair.cdr; v && v->type == LISP_VALUE_PAIR;
             v = v->as.pair.cdr) {
          LispValue *res = eval_expr(profile_env, v->as.pair.car);
          free_lisp_value(res);
        }
        populate_config_from_env(profile_env);
        lisp_env_free(profile_env);
        break;
      }
    }
    free_lisp_value(profiles);
  }

  lisp_env_free(env);
  free(source);
}
