#include "../include/wamble/wamble.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static WambleConfig g_config;
static WAMBLE_THREAD_LOCAL const WambleConfig *g_thread_config = NULL;
static WambleProfile *g_profiles = NULL;
static int g_profile_count = 0;
typedef struct {
  const WambleConfig **data;
  int count;
  int cap;
} CfgStack;
static WAMBLE_THREAD_LOCAL CfgStack g_cfg_stack = {0};

typedef enum {
  LISP_VALUE_NIL,
  LISP_VALUE_PAIR,
  LISP_VALUE_SYMBOL,
  LISP_VALUE_INTEGER,
  LISP_VALUE_FLOAT,
  LISP_VALUE_STRING,
  LISP_VALUE_BUILTIN,
  LISP_VALUE_FUNCTION,
} LispValueType;

struct LispValue;
struct LispEnv;

typedef struct LispFunc {
  int is_macro;
  struct LispValue *params;
  struct LispValue *body;
  struct LispEnv *env;
  int refcount;
} LispFunc;

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
    LispFunc *func;
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

const WambleConfig *get_config(void) {
  return g_thread_config ? g_thread_config : &g_config;
}

void set_thread_config(const WambleConfig *cfg) { g_thread_config = cfg; }

static void cfg_stack_reserve(CfgStack *s, int need) {
  if (s->cap >= need)
    return;
  int ncap = s->cap ? s->cap * 2 : 8;
  while (ncap < need)
    ncap *= 2;
  const WambleConfig **nd =
      realloc((void *)s->data, (size_t)ncap * sizeof(*nd));
  if (!nd) {
    fprintf(stderr, "[config] OOM\n");
    abort();
  }
  s->data = nd;
  s->cap = ncap;
}

void wamble_config_push(const WambleConfig *cfg) {
  cfg_stack_reserve(&g_cfg_stack, g_cfg_stack.count + 1);
  g_cfg_stack.data[g_cfg_stack.count++] = g_thread_config;
  g_thread_config = cfg;
}

void wamble_config_pop(void) {
  if (g_cfg_stack.count <= 0) {
    g_thread_config = NULL;
    return;
  }
  const WambleConfig *prev = g_cfg_stack.data[--g_cfg_stack.count];
  g_thread_config = prev;
}

static LispValue *parse_expr(Stream *s);
static LispValue *lisp_env_get(LispEnv *env, LispValue *symbol);
static void free_lisp_value(LispValue *v);
static LispValue *make_value(LispValueType type);
static LispValue *copy_lisp_value(const LispValue *v);
void lisp_env_free(LispEnv *env);
LispEnv *lisp_env_create(LispEnv *parent);
void lisp_env_put(LispEnv *env, LispValue *symbol, LispValue *value);
static LispValue *eval_expr(struct LispEnv *env, LispValue *expr);
static LispValue *eval_list(struct LispEnv *env, LispValue *list);
static LispValue *make_function(struct LispEnv *env, LispValue *params,
                                LispValue *body, int is_macro);
static LispValue *builtin_do(struct LispEnv *env, LispValue *args);
static LispValue *builtin_quote(struct LispEnv *env, LispValue *args);
static LispValue *builtin_defn(struct LispEnv *env, LispValue *args);
static LispValue *builtin_defmacro(struct LispEnv *env, LispValue *args);

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
  case LISP_VALUE_FUNCTION:
    new_v->as.func = v->as.func;
    if (new_v->as.func)
      new_v->as.func->refcount++;
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
  case LISP_VALUE_FUNCTION:
    if (v->as.func) {
      v->as.func->refcount--;
      if (v->as.func->refcount <= 0) {

        free_lisp_value(v->as.func->params);
        free_lisp_value(v->as.func->body);
        free(v->as.func);
      }
    }
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
  v->as.string = strndup(start, (size_t)(s->p - start));
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

  char *str = strndup(start, (size_t)(s->p - start));
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
  LispValue *args = list->as.pair.cdr;
  LispValue *result = NULL;
  if (op_res->type == LISP_VALUE_BUILTIN) {
    LispBuiltin builtin = op_res->as.builtin;
    free_lisp_value(op_res);
    return builtin(env, args);
  } else if (op_res->type == LISP_VALUE_FUNCTION && op_res->as.func) {
    LispFunc *fn = op_res->as.func;

    LispEnv *call_env = lisp_env_create(fn->env);

    LispValue *p = fn->params;
    LispValue *a = args;
    while (p && p->type == LISP_VALUE_PAIR) {
      LispValue *param_sym = p->as.pair.car;
      if (!param_sym || param_sym->type != LISP_VALUE_SYMBOL) {
        break;
      }
      LispValue *arg_val = NULL;
      if (a && a->type == LISP_VALUE_PAIR) {
        if (fn->is_macro) {

          arg_val = copy_lisp_value(a->as.pair.car);
        } else {
          arg_val = eval_expr(env, a->as.pair.car);
        }
        a = a->as.pair.cdr;
      } else {
        arg_val = make_value(LISP_VALUE_NIL);
      }
      lisp_env_put(call_env, param_sym, arg_val);
      free_lisp_value(arg_val);
      p = p->as.pair.cdr;
    }

    LispValue *body = fn->body;
    LispValue *last = make_value(LISP_VALUE_NIL);
    free_lisp_value(last);
    last = NULL;
    for (LispValue *b = body; b && b->type == LISP_VALUE_PAIR;
         b = b->as.pair.cdr) {
      if (last)
        free_lisp_value(last);
      last = eval_expr(call_env, b->as.pair.car);
    }
    if (!last)
      last = make_value(LISP_VALUE_NIL);
    if (fn->is_macro) {

      LispValue *expansion = last;
      result = eval_expr(env, expansion);
      free_lisp_value(expansion);
    } else {
      result = last;
    }
    lisp_env_free(call_env);
    free_lisp_value(op_res);
    return result;
  }
  free_lisp_value(op_res);
  return make_value(LISP_VALUE_NIL);
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
  case LISP_VALUE_FUNCTION:
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

static bool as_number(LispEnv *env, LispValue *expr, double *out, bool *is_int,
                      int64_t *out_i) {
  LispValue *v = eval_expr(env, expr);
  bool ok = false;
  if (v->type == LISP_VALUE_INTEGER) {
    *is_int = true;
    *out_i = v->as.integer;
    *out = (double)v->as.integer;
    ok = true;
  } else if (v->type == LISP_VALUE_FLOAT) {
    *is_int = false;
    *out = v->as.real;
    ok = true;
  }
  free_lisp_value(v);
  return ok;
}

static LispValue *builtin_add(LispEnv *env, LispValue *args) {
  double sum = 0.0;
  bool all_int = true;
  while (args && args->type == LISP_VALUE_PAIR) {
    double val;
    bool is_int;
    int64_t ival;
    if (!as_number(env, args->as.pair.car, &val, &is_int, &ival))
      return make_value(LISP_VALUE_NIL);
    if (!is_int)
      all_int = false;
    sum += val;
    args = args->as.pair.cdr;
  }
  if (all_int) {
    LispValue *res = make_value(LISP_VALUE_INTEGER);
    res->as.integer = (int64_t)llround(sum);
    return res;
  }
  LispValue *res = make_value(LISP_VALUE_FLOAT);
  res->as.real = sum;
  return res;
}

static LispValue *builtin_sub(LispEnv *env, LispValue *args) {
  if (!args || args->type != LISP_VALUE_PAIR)
    return make_value(LISP_VALUE_NIL);
  double val;
  bool is_int;
  int64_t ival;
  if (!as_number(env, args->as.pair.car, &val, &is_int, &ival))
    return make_value(LISP_VALUE_NIL);
  double acc = val;
  bool all_int = is_int;
  args = args->as.pair.cdr;
  if (!args) {

    if (all_int) {
      LispValue *res = make_value(LISP_VALUE_INTEGER);
      res->as.integer = (int64_t)(-ival);
      return res;
    }
    LispValue *res = make_value(LISP_VALUE_FLOAT);
    res->as.real = -acc;
    return res;
  }
  while (args && args->type == LISP_VALUE_PAIR) {
    double v;
    bool is_i;
    int64_t iv;
    if (!as_number(env, args->as.pair.car, &v, &is_i, &iv))
      return make_value(LISP_VALUE_NIL);
    if (!is_i)
      all_int = false;
    acc -= v;
    args = args->as.pair.cdr;
  }
  if (all_int) {
    LispValue *res = make_value(LISP_VALUE_INTEGER);
    res->as.integer = (int64_t)llround(acc);
    return res;
  }
  LispValue *res = make_value(LISP_VALUE_FLOAT);
  res->as.real = acc;
  return res;
}

static LispValue *builtin_mul(LispEnv *env, LispValue *args) {
  double acc = 1.0;
  bool all_int = true;
  while (args && args->type == LISP_VALUE_PAIR) {
    double v;
    bool is_i;
    int64_t iv;
    if (!as_number(env, args->as.pair.car, &v, &is_i, &iv))
      return make_value(LISP_VALUE_NIL);
    if (!is_i)
      all_int = false;
    acc *= v;
    args = args->as.pair.cdr;
  }
  if (all_int) {
    LispValue *res = make_value(LISP_VALUE_INTEGER);
    res->as.integer = (int64_t)llround(acc);
    return res;
  }
  LispValue *res = make_value(LISP_VALUE_FLOAT);
  res->as.real = acc;
  return res;
}

static LispValue *builtin_div(LispEnv *env, LispValue *args) {
  if (!args || args->type != LISP_VALUE_PAIR)
    return make_value(LISP_VALUE_NIL);
  double val;
  bool is_int;
  int64_t ival;
  if (!as_number(env, args->as.pair.car, &val, &is_int, &ival))
    return make_value(LISP_VALUE_NIL);
  double acc = val;
  bool all_int = false;
  args = args->as.pair.cdr;
  while (args && args->type == LISP_VALUE_PAIR) {
    double v;
    bool is_i;
    int64_t iv;
    if (!as_number(env, args->as.pair.car, &v, &is_i, &iv) || v == 0.0)
      return make_value(LISP_VALUE_NIL);
    acc /= v;
    args = args->as.pair.cdr;
  }
  if (all_int) {
    LispValue *res = make_value(LISP_VALUE_INTEGER);
    res->as.integer = (int64_t)llround(acc);
    return res;
  }
  LispValue *res = make_value(LISP_VALUE_FLOAT);
  res->as.real = acc;
  return res;
}

static LispValue *builtin_eq(LispEnv *env, LispValue *args) {
  if (!args || args->type != LISP_VALUE_PAIR)
    return make_value(LISP_VALUE_INTEGER);
  LispValue *a = eval_expr(env, args->as.pair.car);
  args = args->as.pair.cdr;
  if (!args) {
    free_lisp_value(a);
    return make_value(LISP_VALUE_INTEGER);
  }
  LispValue *b = eval_expr(env, args->as.pair.car);
  int result = 0;
  if (a->type == LISP_VALUE_INTEGER && b->type == LISP_VALUE_INTEGER) {
    result = (a->as.integer == b->as.integer);
  } else if (a->type == LISP_VALUE_FLOAT && b->type == LISP_VALUE_FLOAT) {
    result = (fabs(a->as.real - b->as.real) < 1e-9);
  } else if (a->type == LISP_VALUE_STRING && b->type == LISP_VALUE_STRING) {
    result = (strcmp(a->as.string, b->as.string) == 0);
  }
  free_lisp_value(a);
  free_lisp_value(b);
  LispValue *res = make_value(LISP_VALUE_INTEGER);
  res->as.integer = result;
  return res;
}

static LispValue *builtin_if(LispEnv *env, LispValue *args) {
  if (!args || args->type != LISP_VALUE_PAIR)
    return make_value(LISP_VALUE_NIL);
  LispValue *cond = eval_expr(env, args->as.pair.car);
  args = args->as.pair.cdr;
  bool truthy = false;
  if (cond->type == LISP_VALUE_INTEGER)
    truthy = (cond->as.integer != 0);
  else if (cond->type == LISP_VALUE_FLOAT)
    truthy = (fabs(cond->as.real) > 1e-12);
  else if (cond->type == LISP_VALUE_STRING)
    truthy = (cond->as.string && cond->as.string[0] != '\0');
  free_lisp_value(cond);
  if (!args)
    return make_value(LISP_VALUE_NIL);
  LispValue *then_expr = args->as.pair.car;
  LispValue *else_expr = NULL;
  if (args->as.pair.cdr && args->as.pair.cdr->type == LISP_VALUE_PAIR)
    else_expr = args->as.pair.cdr->as.pair.car;
  if (truthy)
    return eval_expr(env, then_expr);
  if (else_expr)
    return eval_expr(env, else_expr);
  return make_value(LISP_VALUE_NIL);
}

static LispValue *builtin_getenv(LispEnv *env, LispValue *args) {
  if (!args || args->type != LISP_VALUE_PAIR)
    return make_value(LISP_VALUE_STRING);
  LispValue *name_v = eval_expr(env, args->as.pair.car);
  if (name_v->type != LISP_VALUE_STRING) {
    free_lisp_value(name_v);
    return make_value(LISP_VALUE_STRING);
  }
  const char *val = getenv(name_v->as.string);
  free_lisp_value(name_v);
  LispValue *res = make_value(LISP_VALUE_STRING);
  res->as.string = strdup(val ? val : "");
  return res;
}

static LispValue *builtin_do(LispEnv *env, LispValue *args) {
  LispValue *last = NULL;
  for (LispValue *a = args; a && a->type == LISP_VALUE_PAIR;
       a = a->as.pair.cdr) {
    if (last)
      free_lisp_value(last);
    last = eval_expr(env, a->as.pair.car);
  }
  if (!last)
    return make_value(LISP_VALUE_NIL);
  return last;
}

static LispValue *builtin_quote(LispEnv *env, LispValue *args) {
  (void)env;
  if (!args || args->type != LISP_VALUE_PAIR)
    return make_value(LISP_VALUE_NIL);
  return copy_lisp_value(args->as.pair.car);
}

static LispValue *make_function(LispEnv *env, LispValue *params,
                                LispValue *body, int is_macro) {
  LispValue *v = make_value(LISP_VALUE_FUNCTION);
  LispFunc *fn = calloc(1, sizeof(LispFunc));
  fn->is_macro = is_macro;
  fn->params = copy_lisp_value(params);
  fn->body = copy_lisp_value(body);
  fn->env = env;
  fn->refcount = 1;
  v->as.func = fn;
  return v;
}

static LispValue *builtin_defn(LispEnv *env, LispValue *args) {

  if (!args || args->type != LISP_VALUE_PAIR)
    return make_value(LISP_VALUE_NIL);
  LispValue *name = args->as.pair.car;
  LispValue *rest = args->as.pair.cdr;
  if (!name || name->type != LISP_VALUE_SYMBOL || !rest ||
      rest->type != LISP_VALUE_PAIR)
    return make_value(LISP_VALUE_NIL);
  LispValue *params = rest->as.pair.car;
  LispValue *body =
      rest->as.pair.cdr ? rest->as.pair.cdr : make_value(LISP_VALUE_NIL);
  LispValue *fn = make_function(env, params, body, 0);
  lisp_env_put(env, name, fn);
  free_lisp_value(fn);
  return make_value(LISP_VALUE_NIL);
}

static LispValue *builtin_defmacro(LispEnv *env, LispValue *args) {

  if (!args || args->type != LISP_VALUE_PAIR)
    return make_value(LISP_VALUE_NIL);
  LispValue *name = args->as.pair.car;
  LispValue *rest = args->as.pair.cdr;
  if (!name || name->type != LISP_VALUE_SYMBOL || !rest ||
      rest->type != LISP_VALUE_PAIR)
    return make_value(LISP_VALUE_NIL);
  LispValue *params = rest->as.pair.car;
  LispValue *body =
      rest->as.pair.cdr ? rest->as.pair.cdr : make_value(LISP_VALUE_NIL);
  LispValue *fn = make_function(env, params, body, 1);
  lisp_env_put(env, name, fn);
  free_lisp_value(fn);
  return make_value(LISP_VALUE_NIL);
}

static LispValue *builtin_defprofile(LispEnv *env, LispValue *args) {
  LispValue *profile_name = args->as.pair.car;
  LispValue *rest = args->as.pair.cdr;
  LispValue *profile_vars = NULL;

  if (rest && rest->type == LISP_VALUE_PAIR) {
    LispValue *first = rest->as.pair.car;
    int is_inherits_form = 0;
    LispValue *base_cell = NULL;
    if (first && first->type == LISP_VALUE_SYMBOL &&
        (strcmp(first->as.symbol, ":inherits") == 0 ||
         strcmp(first->as.symbol, "inherits") == 0)) {
      is_inherits_form = 1;
      base_cell = rest->as.pair.cdr;
    } else if (first && first->type == LISP_VALUE_PAIR && first->as.pair.car &&
               first->as.pair.car->type == LISP_VALUE_SYMBOL &&
               (strcmp(first->as.pair.car->as.symbol, ":inherits") == 0 ||
                strcmp(first->as.pair.car->as.symbol, "inherits") == 0)) {
      is_inherits_form = 1;
      base_cell = first->as.pair.cdr;
    }
    if (is_inherits_form) {

      if (base_cell && base_cell->type == LISP_VALUE_PAIR &&
          base_cell->as.pair.car &&
          base_cell->as.pair.car->type == LISP_VALUE_SYMBOL) {
        const char *base_name = base_cell->as.pair.car->as.symbol;

        LispValue *def_sym = make_value(LISP_VALUE_SYMBOL);
        def_sym->as.symbol = strdup("def");
        LispValue *inherits_sym = make_value(LISP_VALUE_SYMBOL);
        inherits_sym->as.symbol = strdup("inherits");
        LispValue *base_str = make_value(LISP_VALUE_STRING);
        base_str->as.string = strdup(base_name);

        LispValue *def_call = make_value(LISP_VALUE_PAIR);
        def_call->as.pair.car = def_sym;
        LispValue *def_args = make_value(LISP_VALUE_PAIR);
        def_args->as.pair.car = inherits_sym;
        LispValue *def_args2 = make_value(LISP_VALUE_PAIR);
        def_args2->as.pair.car = base_str;
        def_args2->as.pair.cdr = make_value(LISP_VALUE_NIL);
        def_args->as.pair.cdr = def_args2;
        def_call->as.pair.cdr = def_args;

        LispValue *vars_cell = base_cell->as.pair.cdr;
        if (vars_cell && vars_cell->type == LISP_VALUE_PAIR)
          profile_vars = copy_lisp_value(vars_cell->as.pair.car);
        else
          profile_vars = make_value(LISP_VALUE_NIL);

        LispValue *new_list = make_value(LISP_VALUE_PAIR);
        new_list->as.pair.car = def_call;
        new_list->as.pair.cdr = profile_vars;
        profile_vars = new_list;
      }
    } else {
      profile_vars = copy_lisp_value(first);
    }
  }
  if (!profile_vars)
    profile_vars = make_value(LISP_VALUE_NIL);

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
  profile->as.pair.cdr = profile_vars;

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
    CONF_ITEM("default-rating", CONF_INT, default_rating),
    CONF_ITEM("max-players", CONF_INT, max_players),
    CONF_ITEM("token-expiration", CONF_INT, token_expiration),
    CONF_ITEM("max-pot", CONF_DOUBLE, max_pot),
    CONF_ITEM("max-moves-per-board", CONF_INT, max_moves_per_board),
    CONF_ITEM("max-contributors", CONF_INT, max_contributors),
    CONF_ITEM("admin-trust-level", CONF_INT, admin_trust_level),
    CONF_ITEM("db-host", CONF_STRING, db_host),
    CONF_ITEM("db-user", CONF_STRING, db_user),
    CONF_ITEM("db-pass", CONF_STRING, db_pass),
    CONF_ITEM("db-name", CONF_STRING, db_name),
    CONF_ITEM("select-timeout-usec", CONF_INT, select_timeout_usec),
    CONF_ITEM("cleanup-interval-sec", CONF_INT, cleanup_interval_sec),
    CONF_ITEM("max-token-attempts", CONF_INT, max_token_attempts),
    CONF_ITEM("max-token-local-attempts", CONF_INT, max_token_local_attempts),
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

    CONF_ITEM("log-level", CONF_INT, log_level),

    CONF_ITEM("max-spectators", CONF_INT, max_spectators),
    CONF_ITEM("spectator-visibility", CONF_INT, spectator_visibility),
    CONF_ITEM("spectator-summary-hz", CONF_INT, spectator_summary_hz),
    CONF_ITEM("spectator-focus-hz", CONF_INT, spectator_focus_hz),
    CONF_ITEM("spectator-max-focus-per-session", CONF_INT,
              spectator_max_focus_per_session),
    CONF_ITEM("spectator-summary-mode", CONF_STRING, spectator_summary_mode),
    CONF_ITEM("state-dir", CONF_STRING, state_dir)};

static void populate_config_from_env(LispEnv *env) {
  for (size_t i = 0; i < sizeof(config_map) / sizeof(config_map[0]); i++) {
    const ConfigVarMap *item = &config_map[i];
    LispValue sym;
    sym.type = LISP_VALUE_SYMBOL;
    sym.as.symbol = strdup(item->name);

    LispValue *val = lisp_env_get(env, &sym);
    free(sym.as.symbol);
    if (val->type == LISP_VALUE_NIL) {
      free_lisp_value(val);
      continue;
    }

    void *target = (char *)&g_config + item->offset;
    switch (item->type) {
    case CONF_INT:
      if (val->type == LISP_VALUE_INTEGER) {
        *(int *)target = (int)val->as.integer;
      }
      break;
    case CONF_DOUBLE:
      if (val->type == LISP_VALUE_FLOAT) {
        *(double *)target = val->as.real;
      } else if (val->type == LISP_VALUE_INTEGER) {
        *(double *)target = (double)val->as.integer;
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

static void config_set_defaults(void) {
  g_config.port = 8888;
  g_config.timeout_ms = 100;
  g_config.max_retries = 3;
  g_config.max_message_size = 126;
  g_config.buffer_size = 32768;
  g_config.max_client_sessions = 1024;
  g_config.session_timeout = 300;
  g_config.max_boards = 1024;
  g_config.min_boards = 4;
  g_config.inactivity_timeout = 300;
  g_config.reservation_timeout = 14 * 24 * 60 * 60;
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
  g_config.admin_trust_level = -1;

  g_config.new_player_early_phase_mult = 2.0;
  g_config.new_player_mid_phase_mult = 1.0;
  g_config.new_player_end_phase_mult = 0.5;
  g_config.experienced_player_early_phase_mult = 0.5;
  g_config.experienced_player_mid_phase_mult = 1.0;
  g_config.experienced_player_end_phase_mult = 2.0;
  g_config.log_level = LOG_LEVEL_INFO;

  g_config.max_spectators = 1024;
  g_config.spectator_visibility = 0;
  g_config.spectator_summary_hz = 2;
  g_config.spectator_focus_hz = 20;
  g_config.spectator_max_focus_per_session = 1;
  g_config.spectator_summary_mode = strdup("changes");
  g_config.state_dir = NULL;
}

static void free_profiles(void) {
  if (!g_profiles)
    return;
  for (int i = 0; i < g_profile_count; i++) {
    free(g_profiles[i].name);

    free(g_profiles[i].config.db_host);
    free(g_profiles[i].config.db_user);
    free(g_profiles[i].config.db_pass);
    free(g_profiles[i].config.db_name);
    free(g_profiles[i].config.spectator_summary_mode);
    free(g_profiles[i].config.state_dir);
  }
  free(g_profiles);
  g_profiles = NULL;
  g_profile_count = 0;
}

ConfigLoadStatus config_load(const char *filename, const char *profile,
                             char *status_msg, size_t status_msg_size) {
  if (status_msg && status_msg_size)
    status_msg[0] = '\0';
  free(g_config.db_host);
  free(g_config.db_user);
  free(g_config.db_pass);
  free(g_config.db_name);
  free(g_config.spectator_summary_mode);
  free(g_config.state_dir);
  config_set_defaults();
  free_profiles();

  if (!filename) {
    if (status_msg && status_msg_size)
      snprintf(status_msg, status_msg_size, "defaults: no file provided");
    return CONFIG_LOAD_DEFAULTS;
  }

  FILE *f = fopen(filename, "r");
  if (!f) {
    if (status_msg && status_msg_size)
      snprintf(status_msg, status_msg_size, "defaults: cannot open %s",
               filename);
    return CONFIG_LOAD_DEFAULTS;
  }
  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fseek(f, 0, SEEK_SET);

  char *source = malloc((size_t)fsize + 1u);
  fread(source, 1u, (size_t)fsize, f);
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

  struct {
    const char *name;
    LispBuiltin fn;
  } builtins[] = {
      {"+", builtin_add},
      {"-", builtin_sub},
      {"*", builtin_mul},
      {"/", builtin_div},
      {"=", builtin_eq},
      {"if", builtin_if},
      {"getenv", builtin_getenv},
      {"do", builtin_do},
      {"quote", builtin_quote},
      {"defn", builtin_defn},
      {"defmacro", builtin_defmacro},
  };
  for (size_t i = 0; i < sizeof(builtins) / sizeof(builtins[0]); i++) {
    LispValue *sym = make_value(LISP_VALUE_SYMBOL);
    sym->as.symbol = strdup(builtins[i].name);
    LispValue *fn = make_value(LISP_VALUE_BUILTIN);
    fn->as.builtin = builtins[i].fn;
    lisp_env_put(env, sym, fn);
    free_lisp_value(sym);
    free_lisp_value(fn);
  }

  while (s.p < s.end) {
    LispValue *expr = parse_expr(&s);
    if (expr) {
      LispValue *result = eval_expr(env, expr);
      free_lisp_value(result);
      free_lisp_value(expr);
    }
  }

  populate_config_from_env(env);

  {
    LispValue *profiles_sym = make_value(LISP_VALUE_SYMBOL);
    profiles_sym->as.symbol = strdup("*profiles*");
    LispValue *profiles = lisp_env_get(env, profiles_sym);
    free_lisp_value(profiles_sym);

    int count = 0;
    for (LispValue *p = profiles; p && p->type == LISP_VALUE_PAIR;
         p = p->as.pair.cdr) {
      count++;
    }
    if (count > 0) {
      g_profiles = calloc((size_t)count, sizeof(WambleProfile));
      bool *processed = calloc((size_t)count, sizeof(bool));

      LispValue **plist = calloc((size_t)count, sizeof(LispValue *));
      int idx = 0;
      for (LispValue *p = profiles; p && p->type == LISP_VALUE_PAIR;
           p = p->as.pair.cdr) {
        plist[idx++] = p->as.pair.car;
      }

      int built = 0;
      for (int pass = 0; pass < count * 2 && built < count; pass++) {
        bool progress = false;
        for (int i = 0; i < count; i++) {
          if (processed[i])
            continue;
          LispValue *prof = plist[i];
          const char *pname = prof->as.pair.car->as.symbol;

          LispEnv *profile_env = lisp_env_create(env);
          for (LispValue *v = prof->as.pair.cdr;
               v && v->type == LISP_VALUE_PAIR; v = v->as.pair.cdr) {
            LispValue *res = eval_expr(profile_env, v->as.pair.car);
            free_lisp_value(res);
          }

          char *base_name = NULL;
          {
            LispValue sym;
            sym.type = LISP_VALUE_SYMBOL;
            sym.as.symbol = (char *)"inherits";
            LispValue *val = lisp_env_get(profile_env, &sym);
            if (val->type == LISP_VALUE_STRING && val->as.string &&
                val->as.string[0] != '\0') {
              base_name = strdup(val->as.string);
            }
            free_lisp_value(val);
          }

          WambleConfig base_cfg = g_config;
          int base_advertise = 0;
          int base_visibility = 0;
          int base_db_isolated = 0;
          if (base_name) {
            int found = 0;
            for (int j = 0; j < count; j++) {
              if (processed[j] && g_profiles[j].name &&
                  strcmp(g_profiles[j].name, base_name) == 0) {
                base_cfg = g_profiles[j].config;
                base_advertise = g_profiles[j].advertise;
                base_visibility = g_profiles[j].visibility;
                base_db_isolated = g_profiles[j].db_isolated;
                found = 1;
                break;
              }
            }
            if (!found) {

              free(base_name);
              lisp_env_free(profile_env);
              continue;
            }
            free(base_name);
          }

          WambleConfig cfg = base_cfg;
          cfg.db_host = strdup(base_cfg.db_host);
          cfg.db_user = strdup(base_cfg.db_user);
          cfg.db_pass = strdup(base_cfg.db_pass);
          cfg.db_name = strdup(base_cfg.db_name);
          if (base_cfg.spectator_summary_mode)
            cfg.spectator_summary_mode =
                strdup(base_cfg.spectator_summary_mode);
          if (base_cfg.state_dir)
            cfg.state_dir = strdup(base_cfg.state_dir);

          WambleConfig saved = g_config;
          g_config = cfg;
          populate_config_from_env(profile_env);
          WambleConfig overlaid = g_config;
          g_config = saved;

          int advertise = base_advertise;
          int visibility = base_visibility;
          int db_isolated = base_db_isolated;
          {
            LispValue sym;
            sym.type = LISP_VALUE_SYMBOL;
            sym.as.symbol = (char *)"advertise";
            LispValue *val = lisp_env_get(profile_env, &sym);
            if (val->type == LISP_VALUE_INTEGER)
              advertise = (int)val->as.integer;
            free_lisp_value(val);
            sym.as.symbol = (char *)"visibility";
            val = lisp_env_get(profile_env, &sym);
            if (val->type == LISP_VALUE_INTEGER)
              visibility = (int)val->as.integer;
            free_lisp_value(val);
            sym.as.symbol = (char *)"db-isolated";
            val = lisp_env_get(profile_env, &sym);
            if (val->type == LISP_VALUE_INTEGER)
              db_isolated = (int)val->as.integer;
            free_lisp_value(val);
          }

          g_profiles[i].name = strdup(pname);
          g_profiles[i].config = overlaid;
          g_profiles[i].advertise = advertise;
          g_profiles[i].visibility = visibility;
          g_profiles[i].db_isolated = db_isolated;

          processed[i] = true;
          built++;
          progress = true;

          lisp_env_free(profile_env);
        }
        if (!progress)
          break;
      }

      if (built > 0) {
        WambleProfile *compact = calloc((size_t)built, sizeof(WambleProfile));
        int w = 0;
        for (int i = 0; i < count; i++) {
          if (processed[i] && g_profiles[i].name) {
            compact[w++] = g_profiles[i];
          } else {

            free(g_profiles[i].name);
            free(g_profiles[i].config.db_host);
            free(g_profiles[i].config.db_user);
            free(g_profiles[i].config.db_pass);
            free(g_profiles[i].config.db_name);
            free(g_profiles[i].config.spectator_summary_mode);
            free(g_profiles[i].config.state_dir);
          }
        }
        free(g_profiles);
        g_profiles = compact;
        g_profile_count = built;
      }

      int applied_profile = 0;
      if (profile) {
        for (int i = 0; i < g_profile_count; i++) {
          if (g_profiles[i].name && strcmp(g_profiles[i].name, profile) == 0) {
            g_config = g_profiles[i].config;
            applied_profile = 1;
            break;
          }
        }
        if (!applied_profile && status_msg && status_msg_size) {

          snprintf(status_msg, status_msg_size,
                   "loaded %s, profile '%s' not found", filename, profile);
        }
      }

      free(processed);
      free(plist);
    }
    free_lisp_value(profiles);
  }

  lisp_env_free(env);
  free(source);
  if (profile) {
    int found = 0;
    for (int i = 0; i < g_profile_count; i++) {
      if (g_profiles[i].name && strcmp(g_profiles[i].name, profile) == 0) {
        found = 1;
        break;
      }
    }
    if (!found) {
      if (status_msg && status_msg_size)
        snprintf(status_msg, status_msg_size,
                 "loaded %s, profile '%s' not found", filename, profile);
      return CONFIG_LOAD_PROFILE_NOT_FOUND;
    }
  }

  if (status_msg && status_msg_size)
    snprintf(status_msg, status_msg_size, "loaded %s", filename);
  return CONFIG_LOAD_OK;
}

int config_profile_count(void) { return g_profile_count; }

const WambleProfile *config_get_profile(int index) {
  if (index < 0 || index >= g_profile_count)
    return NULL;
  return &g_profiles[index];
}

const WambleProfile *config_find_profile(const char *name) {
  if (!name)
    return NULL;
  for (int i = 0; i < g_profile_count; i++) {
    if (g_profiles[i].name && strcmp(g_profiles[i].name, name) == 0)
      return &g_profiles[i];
  }
  return NULL;
}
