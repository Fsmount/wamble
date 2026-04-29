#include "../include/wamble/wamble.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

struct LispEnv;
typedef struct LispEnv LispEnv;

static WambleConfig g_config;
static WAMBLE_THREAD_LOCAL const WambleConfig *g_thread_config = NULL;
static WambleProfile *g_profiles = NULL;
static int g_profile_count = 0;
static WamblePolicyRuleSpec *g_policy_rules = NULL;
static int g_policy_rule_count = 0;
static WambleTreatmentGroupSpec *g_treatment_groups = NULL;
static int g_treatment_group_count = 0;
static WambleTreatmentRuleSpec *g_treatment_rules = NULL;
static int g_treatment_rule_count = 0;
static WambleTreatmentEdgeSpec *g_treatment_edges = NULL;
static int g_treatment_edge_count = 0;
static WambleTreatmentOutputSpec *g_treatment_outputs = NULL;
static int g_treatment_output_count = 0;
static LispEnv *g_policy_env = NULL;
static char *g_last_loaded_source = NULL;
static wamble_mutex_t g_policy_eval_mutex;
static int g_policy_eval_mutex_ready = 0;
static int g_profile_local_unsupported_seen = 0;
typedef struct {
  const WambleConfig **data;
  int count;
  int cap;
} CfgStack;
static WAMBLE_THREAD_LOCAL CfgStack g_cfg_stack = {0};

typedef struct ConfigSnapshot {
  WambleConfig config;
  WambleProfile *profiles;
  int profile_count;
  WamblePolicyRuleSpec *policy_rules;
  int policy_rule_count;
  WambleTreatmentGroupSpec *treatment_groups;
  int treatment_group_count;
  WambleTreatmentRuleSpec *treatment_rules;
  int treatment_rule_count;
  WambleTreatmentEdgeSpec *treatment_edges;
  int treatment_edge_count;
  WambleTreatmentOutputSpec *treatment_outputs;
  int treatment_output_count;
  char *source_text;
} ConfigSnapshot;

static LispEnv *policy_env_swap(LispEnv *new_env) {
  LispEnv *old = NULL;
  if (g_policy_eval_mutex_ready)
    wamble_mutex_lock(&g_policy_eval_mutex);
  old = g_policy_env;
  g_policy_env = new_env;
  if (g_policy_eval_mutex_ready)
    wamble_mutex_unlock(&g_policy_eval_mutex);
  return old;
}

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

struct LispEnv {
  struct LispEnv *parent;
  LispValue *vars;
};

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
static void lisp_env_free(LispEnv *env);
static LispEnv *lisp_env_create(LispEnv *parent);
static void lisp_env_put(LispEnv *env, LispValue *symbol, LispValue *value);
static LispValue *eval_expr(struct LispEnv *env, LispValue *expr);
static LispValue *eval_list(struct LispEnv *env, LispValue *list);
static LispValue *make_function(struct LispEnv *env, LispValue *params,
                                LispValue *body, int is_macro);
static LispValue *builtin_do(struct LispEnv *env, LispValue *args);
static LispValue *builtin_quote(struct LispEnv *env, LispValue *args);
static LispValue *builtin_defn(struct LispEnv *env, LispValue *args);
static LispValue *builtin_defmacro(struct LispEnv *env, LispValue *args);
static LispValue *builtin_policy_allow(struct LispEnv *env, LispValue *args);
static LispValue *builtin_policy_deny(struct LispEnv *env, LispValue *args);
static LispValue *builtin_treatment_group(struct LispEnv *env, LispValue *args);
static LispValue *builtin_treatment_default(struct LispEnv *env,
                                            LispValue *args);
static LispValue *builtin_treatment_assign(struct LispEnv *env,
                                           LispValue *args);
static LispValue *builtin_treatment_edge(struct LispEnv *env, LispValue *args);
static LispValue *builtin_treatment_tag(struct LispEnv *env, LispValue *args);
static LispValue *builtin_treatment_feature(struct LispEnv *env,
                                            LispValue *args);
static LispValue *builtin_treatment_context(struct LispEnv *env,
                                            LispValue *args);
static LispValue *builtin_treatment_behavior(struct LispEnv *env,
                                             LispValue *args);
static LispValue *builtin_treatment_meta(struct LispEnv *env, LispValue *args);
static LispValue *builtin_treatment_payload(struct LispEnv *env,
                                            LispValue *args);
static LispValue *builtin_treatment_visible_fen(struct LispEnv *env,
                                                LispValue *args);
static LispValue *builtin_treatment_predictions_from_moves(struct LispEnv *env,
                                                           LispValue *args);
static LispValue *builtin_profile_local_unsupported(LispEnv *env,
                                                    LispValue *args);

static void policy_rules_free(WamblePolicyRuleSpec *rules, int count);
static int policy_rule_dup(WamblePolicyRuleSpec *dst,
                           const WamblePolicyRuleSpec *src);
static int policy_rules_append(const WamblePolicyRuleSpec *rule);
static void treatment_value_clear(WambleTreatmentValueSpec *v);
static int treatment_value_dup(WambleTreatmentValueSpec *dst,
                               const WambleTreatmentValueSpec *src);
static void treatment_group_clear(WambleTreatmentGroupSpec *g);
static void treatment_groups_free(WambleTreatmentGroupSpec *groups, int count);
static int treatment_group_dup(WambleTreatmentGroupSpec *dst,
                               const WambleTreatmentGroupSpec *src);
static int treatment_groups_append(const WambleTreatmentGroupSpec *group);
static void treatment_rule_clear(WambleTreatmentRuleSpec *r);
static void treatment_rules_free(WambleTreatmentRuleSpec *rules, int count);
static int treatment_rule_dup(WambleTreatmentRuleSpec *dst,
                              const WambleTreatmentRuleSpec *src);
static int treatment_rules_append(const WambleTreatmentRuleSpec *rule);
static void treatment_edge_clear(WambleTreatmentEdgeSpec *e);
static void treatment_edges_free(WambleTreatmentEdgeSpec *edges, int count);
static int treatment_edge_dup(WambleTreatmentEdgeSpec *dst,
                              const WambleTreatmentEdgeSpec *src);
static int treatment_edges_append(const WambleTreatmentEdgeSpec *edge);
static void treatment_output_clear(WambleTreatmentOutputSpec *o);
static void treatment_outputs_free(WambleTreatmentOutputSpec *out, int count);
static int treatment_output_dup(WambleTreatmentOutputSpec *dst,
                                const WambleTreatmentOutputSpec *src);
static int treatment_outputs_append(const WambleTreatmentOutputSpec *out);
static LispValue *cons(LispValue *car, LispValue *cdr);
static LispValue *make_string_value(const char *s);
static int parse_policy_eval_result(LispValue *res, WamblePolicyDecision *out);
static LispEnv *build_policy_env_from_source(const char *source);

static int cfg_dup_owned(WambleConfig *dst, const WambleConfig *src) {
  if (!dst || !src)
    return -1;
  memset(dst, 0, sizeof(*dst));
  *dst = *src;
  dst->db_host = src->db_host ? wamble_strdup(src->db_host) : NULL;
  dst->db_user = src->db_user ? wamble_strdup(src->db_user) : NULL;
  dst->db_pass = src->db_pass ? wamble_strdup(src->db_pass) : NULL;
  dst->db_name = src->db_name ? wamble_strdup(src->db_name) : NULL;
  dst->global_db_host =
      src->global_db_host ? wamble_strdup(src->global_db_host) : NULL;
  dst->global_db_user =
      src->global_db_user ? wamble_strdup(src->global_db_user) : NULL;
  dst->global_db_pass =
      src->global_db_pass ? wamble_strdup(src->global_db_pass) : NULL;
  dst->global_db_name =
      src->global_db_name ? wamble_strdup(src->global_db_name) : NULL;
  dst->spectator_summary_mode = src->spectator_summary_mode
                                    ? wamble_strdup(src->spectator_summary_mode)
                                    : NULL;
  dst->prediction_match_policy =
      src->prediction_match_policy ? wamble_strdup(src->prediction_match_policy)
                                   : NULL;
  dst->state_dir = src->state_dir ? wamble_strdup(src->state_dir) : NULL;
  dst->websocket_path =
      src->websocket_path ? wamble_strdup(src->websocket_path) : NULL;
  if (!dst->db_host || !dst->db_user || !dst->db_pass || !dst->db_name ||
      !dst->global_db_host || !dst->global_db_user || !dst->global_db_pass ||
      !dst->global_db_name || !dst->spectator_summary_mode ||
      !dst->prediction_match_policy || !dst->websocket_path) {
    free(dst->db_host);
    free(dst->db_user);
    free(dst->db_pass);
    free(dst->db_name);
    free(dst->global_db_host);
    free(dst->global_db_user);
    free(dst->global_db_pass);
    free(dst->global_db_name);
    free(dst->spectator_summary_mode);
    free(dst->prediction_match_policy);
    free(dst->state_dir);
    free(dst->websocket_path);
    memset(dst, 0, sizeof(*dst));
    return -1;
  }
  return 0;
}

static void cfg_free_owned(WambleConfig *cfg) {
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
  free(cfg->spectator_summary_mode);
  free(cfg->prediction_match_policy);
  free(cfg->state_dir);
  free(cfg->websocket_path);
  memset(cfg, 0, sizeof(*cfg));
}

static void policy_rule_clear(WamblePolicyRuleSpec *r) {
  if (!r)
    return;
  free(r->identity_selector);
  free(r->action);
  free(r->resource);
  free(r->effect);
  free(r->reason);
  free(r->policy_version);
  free(r->context_key);
  free(r->context_value);
  memset(r, 0, sizeof(*r));
}

static void policy_rules_free(WamblePolicyRuleSpec *rules, int count) {
  if (!rules)
    return;
  for (int i = 0; i < count; i++) {
    policy_rule_clear(&rules[i]);
  }
  free(rules);
}

static int policy_rule_dup(WamblePolicyRuleSpec *dst,
                           const WamblePolicyRuleSpec *src) {
  if (!dst || !src)
    return -1;
  memset(dst, 0, sizeof(*dst));
  dst->permission_level = src->permission_level;
  dst->not_before_at = src->not_before_at;
  dst->not_after_at = src->not_after_at;
  dst->identity_selector = src->identity_selector
                               ? wamble_strdup(src->identity_selector)
                               : wamble_strdup("*");
  dst->action = src->action ? wamble_strdup(src->action) : NULL;
  dst->resource = src->resource ? wamble_strdup(src->resource) : NULL;
  dst->effect = src->effect ? wamble_strdup(src->effect) : NULL;
  dst->reason = src->reason ? wamble_strdup(src->reason) : wamble_strdup("");
  dst->policy_version = src->policy_version ? wamble_strdup(src->policy_version)
                                            : wamble_strdup("v1");
  dst->context_key = src->context_key ? wamble_strdup(src->context_key) : NULL;
  dst->context_value =
      src->context_value ? wamble_strdup(src->context_value) : NULL;
  if (!dst->identity_selector || !dst->action || !dst->resource ||
      !dst->effect || !dst->reason || !dst->policy_version ||
      (src->context_key && !dst->context_key) ||
      (src->context_value && !dst->context_value)) {
    policy_rule_clear(dst);
    return -1;
  }
  return 0;
}

static int policy_rules_append(const WamblePolicyRuleSpec *rule) {
  if (!rule || !rule->action || !rule->resource || !rule->effect)
    return -1;
  WamblePolicyRuleSpec *nr =
      realloc(g_policy_rules,
              (size_t)(g_policy_rule_count + 1) * sizeof(*g_policy_rules));
  if (!nr)
    return -1;
  g_policy_rules = nr;
  memset(&g_policy_rules[g_policy_rule_count], 0, sizeof(g_policy_rules[0]));
  if (policy_rule_dup(&g_policy_rules[g_policy_rule_count], rule) != 0)
    return -1;
  g_policy_rule_count++;
  return 0;
}

static void treatment_value_clear(WambleTreatmentValueSpec *v) {
  if (!v)
    return;
  free(v->string_value);
  free(v->fact_key);
  memset(v, 0, sizeof(*v));
}

static int treatment_value_dup(WambleTreatmentValueSpec *dst,
                               const WambleTreatmentValueSpec *src) {
  if (!dst || !src)
    return -1;
  memset(dst, 0, sizeof(*dst));
  *dst = *src;
  dst->string_value =
      src->string_value ? wamble_strdup(src->string_value) : NULL;
  dst->fact_key = src->fact_key ? wamble_strdup(src->fact_key) : NULL;
  if ((src->string_value && !dst->string_value) ||
      (src->fact_key && !dst->fact_key)) {
    treatment_value_clear(dst);
    return -1;
  }
  return 0;
}

static void treatment_group_clear(WambleTreatmentGroupSpec *g) {
  if (!g)
    return;
  free(g->group_key);
  memset(g, 0, sizeof(*g));
}

static void treatment_groups_free(WambleTreatmentGroupSpec *groups, int count) {
  if (!groups)
    return;
  for (int i = 0; i < count; i++)
    treatment_group_clear(&groups[i]);
  free(groups);
}

static int treatment_group_dup(WambleTreatmentGroupSpec *dst,
                               const WambleTreatmentGroupSpec *src) {
  if (!dst || !src)
    return -1;
  memset(dst, 0, sizeof(*dst));
  dst->group_key = src->group_key ? wamble_strdup(src->group_key) : NULL;
  dst->priority = src->priority;
  dst->is_default = src->is_default;
  if (!dst->group_key) {
    treatment_group_clear(dst);
    return -1;
  }
  return 0;
}

static int treatment_groups_append(const WambleTreatmentGroupSpec *group) {
  if (!group || !group->group_key)
    return -1;
  WambleTreatmentGroupSpec *nr =
      realloc(g_treatment_groups, (size_t)(g_treatment_group_count + 1) *
                                      sizeof(*g_treatment_groups));
  if (!nr)
    return -1;
  g_treatment_groups = nr;
  memset(&g_treatment_groups[g_treatment_group_count], 0,
         sizeof(g_treatment_groups[0]));
  if (treatment_group_dup(&g_treatment_groups[g_treatment_group_count],
                          group) != 0)
    return -1;
  g_treatment_group_count++;
  return 0;
}

static void treatment_rule_clear(WambleTreatmentRuleSpec *r) {
  if (!r)
    return;
  free(r->identity_selector);
  free(r->profile_scope);
  free(r->group_key);
  if (r->predicates) {
    for (int i = 0; i < r->predicate_count; i++) {
      free(r->predicates[i].fact_key);
      free(r->predicates[i].op);
      treatment_value_clear(&r->predicates[i].value);
    }
  }
  free(r->predicates);
  memset(r, 0, sizeof(*r));
}

static void treatment_rules_free(WambleTreatmentRuleSpec *rules, int count) {
  if (!rules)
    return;
  for (int i = 0; i < count; i++)
    treatment_rule_clear(&rules[i]);
  free(rules);
}

static int treatment_rule_dup(WambleTreatmentRuleSpec *dst,
                              const WambleTreatmentRuleSpec *src) {
  if (!dst || !src)
    return -1;
  memset(dst, 0, sizeof(*dst));
  dst->identity_selector = src->identity_selector
                               ? wamble_strdup(src->identity_selector)
                               : wamble_strdup("*");
  dst->profile_scope = src->profile_scope ? wamble_strdup(src->profile_scope)
                                          : wamble_strdup("*");
  dst->group_key = src->group_key ? wamble_strdup(src->group_key) : NULL;
  dst->priority = src->priority;
  dst->predicate_count = src->predicate_count;
  if (!dst->identity_selector || !dst->profile_scope || !dst->group_key) {
    treatment_rule_clear(dst);
    return -1;
  }
  if (src->predicate_count > 0) {
    dst->predicates = (WambleTreatmentRulePredicateSpec *)calloc(
        (size_t)src->predicate_count, sizeof(*dst->predicates));
    if (!dst->predicates) {
      treatment_rule_clear(dst);
      return -1;
    }
    for (int i = 0; i < src->predicate_count; i++) {
      dst->predicates[i].fact_key =
          src->predicates[i].fact_key
              ? wamble_strdup(src->predicates[i].fact_key)
              : NULL;
      dst->predicates[i].op =
          src->predicates[i].op ? wamble_strdup(src->predicates[i].op) : NULL;
      if (!dst->predicates[i].fact_key || !dst->predicates[i].op ||
          treatment_value_dup(&dst->predicates[i].value,
                              &src->predicates[i].value) != 0) {
        treatment_rule_clear(dst);
        return -1;
      }
    }
  }
  return 0;
}

static int treatment_rules_append(const WambleTreatmentRuleSpec *rule) {
  if (!rule || !rule->group_key)
    return -1;
  WambleTreatmentRuleSpec *nr =
      realloc(g_treatment_rules, (size_t)(g_treatment_rule_count + 1) *
                                     sizeof(*g_treatment_rules));
  if (!nr)
    return -1;
  g_treatment_rules = nr;
  memset(&g_treatment_rules[g_treatment_rule_count], 0,
         sizeof(g_treatment_rules[0]));
  if (treatment_rule_dup(&g_treatment_rules[g_treatment_rule_count], rule) != 0)
    return -1;
  g_treatment_rule_count++;
  return 0;
}

static void treatment_edge_clear(WambleTreatmentEdgeSpec *e) {
  if (!e)
    return;
  free(e->source_group_key);
  free(e->target_group_key);
  memset(e, 0, sizeof(*e));
}

static void treatment_edges_free(WambleTreatmentEdgeSpec *edges, int count) {
  if (!edges)
    return;
  for (int i = 0; i < count; i++)
    treatment_edge_clear(&edges[i]);
  free(edges);
}

static int treatment_edge_dup(WambleTreatmentEdgeSpec *dst,
                              const WambleTreatmentEdgeSpec *src) {
  if (!dst || !src)
    return -1;
  memset(dst, 0, sizeof(*dst));
  dst->source_group_key =
      src->source_group_key ? wamble_strdup(src->source_group_key) : NULL;
  dst->target_group_key =
      src->target_group_key ? wamble_strdup(src->target_group_key) : NULL;
  if (!dst->source_group_key || !dst->target_group_key) {
    treatment_edge_clear(dst);
    return -1;
  }
  return 0;
}

static int treatment_edges_append(const WambleTreatmentEdgeSpec *edge) {
  if (!edge || !edge->source_group_key || !edge->target_group_key)
    return -1;
  WambleTreatmentEdgeSpec *nr =
      realloc(g_treatment_edges, (size_t)(g_treatment_edge_count + 1) *
                                     sizeof(*g_treatment_edges));
  if (!nr)
    return -1;
  g_treatment_edges = nr;
  memset(&g_treatment_edges[g_treatment_edge_count], 0,
         sizeof(g_treatment_edges[0]));
  if (treatment_edge_dup(&g_treatment_edges[g_treatment_edge_count], edge) != 0)
    return -1;
  g_treatment_edge_count++;
  return 0;
}

static void treatment_output_clear(WambleTreatmentOutputSpec *o) {
  if (!o)
    return;
  free(o->group_key);
  free(o->hook_name);
  free(o->output_kind);
  free(o->output_key);
  treatment_value_clear(&o->value);
  memset(o, 0, sizeof(*o));
}

static void treatment_outputs_free(WambleTreatmentOutputSpec *out, int count) {
  if (!out)
    return;
  for (int i = 0; i < count; i++)
    treatment_output_clear(&out[i]);
  free(out);
}

static int treatment_output_dup(WambleTreatmentOutputSpec *dst,
                                const WambleTreatmentOutputSpec *src) {
  if (!dst || !src)
    return -1;
  memset(dst, 0, sizeof(*dst));
  dst->group_key = src->group_key ? wamble_strdup(src->group_key) : NULL;
  dst->hook_name =
      src->hook_name ? wamble_strdup(src->hook_name) : wamble_strdup("*");
  dst->output_kind = src->output_kind ? wamble_strdup(src->output_kind) : NULL;
  dst->output_key = src->output_key ? wamble_strdup(src->output_key) : NULL;
  if (!dst->group_key || !dst->hook_name || !dst->output_kind ||
      !dst->output_key || treatment_value_dup(&dst->value, &src->value) != 0) {
    treatment_output_clear(dst);
    return -1;
  }
  return 0;
}

static int treatment_outputs_append(const WambleTreatmentOutputSpec *out) {
  if (!out || !out->group_key || !out->output_kind || !out->output_key)
    return -1;
  WambleTreatmentOutputSpec *nr =
      realloc(g_treatment_outputs, (size_t)(g_treatment_output_count + 1) *
                                       sizeof(*g_treatment_outputs));
  if (!nr)
    return -1;
  g_treatment_outputs = nr;
  memset(&g_treatment_outputs[g_treatment_output_count], 0,
         sizeof(g_treatment_outputs[0]));
  if (treatment_output_dup(&g_treatment_outputs[g_treatment_output_count],
                           out) != 0)
    return -1;
  g_treatment_output_count++;
  return 0;
}

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
    new_v->as.symbol = wamble_strdup(v->as.symbol);
    break;
  case LISP_VALUE_STRING:
    new_v->as.string = wamble_strdup(v->as.string);
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

static void lisp_env_free(LispEnv *env) {
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

static LispValue *cons(LispValue *car, LispValue *cdr) {
  LispValue *p = make_value(LISP_VALUE_PAIR);
  p->as.pair.car = car;
  p->as.pair.cdr = cdr ? cdr : make_value(LISP_VALUE_NIL);
  return p;
}

static LispValue *make_string_value(const char *s) {
  LispValue *v = make_value(LISP_VALUE_STRING);
  v->as.string = wamble_strdup(s ? s : "");
  if (!v->as.string) {
    free(v);
    return NULL;
  }
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

static LispEnv *lisp_env_create(LispEnv *parent) {
  LispEnv *env = calloc(1, sizeof(LispEnv));
  env->parent = parent;
  return env;
}

static void lisp_env_put(LispEnv *env, LispValue *symbol, LispValue *value) {
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
  res->as.string = wamble_strdup(val ? val : "");
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

static int eval_string_arg(LispEnv *env, LispValue *expr, char **out) {
  if (!out)
    return -1;
  *out = NULL;
  LispValue *v = eval_expr(env, expr);
  if (!v)
    return -1;
  if (v->type != LISP_VALUE_STRING || !v->as.string) {
    free_lisp_value(v);
    return -1;
  }
  *out = wamble_strdup(v->as.string);
  free_lisp_value(v);
  return *out ? 0 : -1;
}

static int eval_int_arg(LispEnv *env, LispValue *expr, int *out) {
  if (!out)
    return -1;
  LispValue *v = eval_expr(env, expr);
  if (!v)
    return -1;
  if (v->type != LISP_VALUE_INTEGER) {
    free_lisp_value(v);
    return -1;
  }
  *out = (int)v->as.integer;
  free_lisp_value(v);
  return 0;
}

static int eval_i64_arg(LispEnv *env, LispValue *expr, int64_t *out) {
  if (!out)
    return -1;
  LispValue *v = eval_expr(env, expr);
  if (!v)
    return -1;
  if (v->type != LISP_VALUE_INTEGER) {
    free_lisp_value(v);
    return -1;
  }
  *out = v->as.integer;
  free_lisp_value(v);
  return 0;
}

static int eval_treatment_value_arg(LispEnv *env, LispValue *expr,
                                    WambleTreatmentValueSpec *out) {
  if (!out)
    return -1;
  memset(out, 0, sizeof(*out));
  if (!expr)
    return -1;
  if (expr->type == LISP_VALUE_PAIR) {
    LispValue *head = expr->as.pair.car;
    LispValue *tail = expr->as.pair.cdr;
    if (head && head->type == LISP_VALUE_SYMBOL &&
        strcmp(head->as.symbol, "fact") == 0 && tail &&
        tail->type == LISP_VALUE_PAIR) {
      char *fact_key = NULL;
      if (eval_string_arg(env, tail->as.pair.car, &fact_key) != 0)
        return -1;
      out->type = WAMBLE_TREATMENT_VALUE_FACT_REF;
      out->fact_key = fact_key;
      return 0;
    }
  }
  LispValue *v = eval_expr(env, expr);
  if (!v)
    return -1;
  if (v->type == LISP_VALUE_STRING && v->as.string) {
    out->type = WAMBLE_TREATMENT_VALUE_STRING;
    out->string_value = wamble_strdup(v->as.string);
  } else if (v->type == LISP_VALUE_INTEGER) {
    out->type = WAMBLE_TREATMENT_VALUE_INT;
    out->int_value = v->as.integer;
  } else if (v->type == LISP_VALUE_FLOAT) {
    out->type = WAMBLE_TREATMENT_VALUE_DOUBLE;
    out->double_value = v->as.real;
  } else if (v->type == LISP_VALUE_SYMBOL &&
             (strcmp(v->as.symbol, "true") == 0 ||
              strcmp(v->as.symbol, "false") == 0)) {
    out->type = WAMBLE_TREATMENT_VALUE_BOOL;
    out->bool_value = (strcmp(v->as.symbol, "true") == 0) ? 1 : 0;
  } else {
    free_lisp_value(v);
    return -1;
  }
  free_lisp_value(v);
  if (out->type == WAMBLE_TREATMENT_VALUE_STRING && !out->string_value)
    return -1;
  return 0;
}

static LispValue *builtin_policy_record(LispEnv *env, LispValue *args,
                                        const char *effect) {
  if (!args || args->type != LISP_VALUE_PAIR)
    return make_value(LISP_VALUE_NIL);

  WamblePolicyRuleSpec rule;
  memset(&rule, 0, sizeof(rule));
  rule.identity_selector = wamble_strdup("*");
  rule.reason = wamble_strdup("");
  rule.policy_version = wamble_strdup("v1");
  rule.permission_level = 0;
  rule.not_before_at = 0;
  rule.not_after_at = 0;
  rule.effect = wamble_strdup(effect ? effect : "deny");
  if (!rule.identity_selector || !rule.reason || !rule.policy_version ||
      !rule.effect) {
    policy_rule_clear(&rule);
    return make_value(LISP_VALUE_NIL);
  }

  int idx = 0;
  for (LispValue *a = args; a && a->type == LISP_VALUE_PAIR;
       a = a->as.pair.cdr) {
    if (idx == 0) {
      free(rule.identity_selector);
      rule.identity_selector = NULL;
      if (eval_string_arg(env, a->as.pair.car, &rule.identity_selector) != 0)
        break;
    } else if (idx == 1) {
      if (eval_string_arg(env, a->as.pair.car, &rule.action) != 0)
        break;
    } else if (idx == 2) {
      if (eval_string_arg(env, a->as.pair.car, &rule.resource) != 0)
        break;
    } else if (idx == 3 && strcmp(effect, "allow") == 0) {
      if (eval_int_arg(env, a->as.pair.car, &rule.permission_level) != 0)
        break;
    } else if ((idx == 3 && strcmp(effect, "deny") == 0) ||
               (idx == 4 && strcmp(effect, "allow") == 0)) {
      free(rule.reason);
      rule.reason = NULL;
      if (eval_string_arg(env, a->as.pair.car, &rule.reason) != 0)
        break;
    } else if ((idx == 4 && strcmp(effect, "deny") == 0) ||
               (idx == 5 && strcmp(effect, "allow") == 0)) {
      free(rule.policy_version);
      rule.policy_version = NULL;
      if (eval_string_arg(env, a->as.pair.car, &rule.policy_version) != 0)
        break;
    } else if ((idx == 5 && strcmp(effect, "deny") == 0) ||
               (idx == 6 && strcmp(effect, "allow") == 0)) {
      if (eval_i64_arg(env, a->as.pair.car, &rule.not_before_at) != 0)
        break;
    } else if ((idx == 6 && strcmp(effect, "deny") == 0) ||
               (idx == 7 && strcmp(effect, "allow") == 0)) {
      if (eval_i64_arg(env, a->as.pair.car, &rule.not_after_at) != 0)
        break;
    } else if ((idx == 7 && strcmp(effect, "deny") == 0) ||
               (idx == 8 && strcmp(effect, "allow") == 0)) {
      if (eval_string_arg(env, a->as.pair.car, &rule.context_key) != 0)
        break;
    } else if ((idx == 8 && strcmp(effect, "deny") == 0) ||
               (idx == 9 && strcmp(effect, "allow") == 0)) {
      if (eval_string_arg(env, a->as.pair.car, &rule.context_value) != 0)
        break;
    }
    idx++;
  }

  int ok = (rule.action && rule.resource && rule.effect) ? 1 : 0;
  if (ok && policy_rules_append(&rule) != 0)
    ok = 0;
  policy_rule_clear(&rule);
  if (!ok)
    return make_value(LISP_VALUE_NIL);
  LispValue *one = make_value(LISP_VALUE_INTEGER);
  one->as.integer = 1;
  return one;
}

static LispValue *builtin_policy_allow(LispEnv *env, LispValue *args) {
  return builtin_policy_record(env, args, "allow");
}

static LispValue *builtin_policy_deny(LispEnv *env, LispValue *args) {
  return builtin_policy_record(env, args, "deny");
}

static LispValue *builtin_treatment_group(LispEnv *env, LispValue *args) {
  (void)env;
  if (!args || args->type != LISP_VALUE_PAIR)
    return make_value(LISP_VALUE_NIL);
  WambleTreatmentGroupSpec group = {0};
  if (eval_string_arg(env, args->as.pair.car, &group.group_key) != 0)
    return make_value(LISP_VALUE_NIL);
  if (!args->as.pair.cdr || args->as.pair.cdr->type != LISP_VALUE_PAIR ||
      eval_int_arg(env, args->as.pair.cdr->as.pair.car, &group.priority) != 0) {
    treatment_group_clear(&group);
    return make_value(LISP_VALUE_NIL);
  }
  int ok = (treatment_groups_append(&group) == 0);
  treatment_group_clear(&group);
  if (!ok)
    return make_value(LISP_VALUE_NIL);
  LispValue *one = make_value(LISP_VALUE_INTEGER);
  one->as.integer = 1;
  return one;
}

static LispValue *builtin_treatment_default(LispEnv *env, LispValue *args) {
  if (!args || args->type != LISP_VALUE_PAIR)
    return make_value(LISP_VALUE_NIL);
  char *key = NULL;
  if (eval_string_arg(env, args->as.pair.car, &key) != 0)
    return make_value(LISP_VALUE_NIL);
  int ok = 0;
  for (int i = 0; i < g_treatment_group_count; i++) {
    g_treatment_groups[i].is_default =
        (strcmp(g_treatment_groups[i].group_key, key) == 0) ? 1 : 0;
    if (g_treatment_groups[i].is_default)
      ok = 1;
  }
  free(key);
  if (!ok)
    return make_value(LISP_VALUE_NIL);
  LispValue *one = make_value(LISP_VALUE_INTEGER);
  one->as.integer = 1;
  return one;
}

static int treatment_parse_predicates(LispEnv *env, LispValue *list,
                                      WambleTreatmentRuleSpec *rule) {
  int count = 0;
  for (LispValue *a = list; a && a->type == LISP_VALUE_PAIR;
       a = a->as.pair.cdr) {
    count++;
  }
  if (count == 0)
    return 0;
  rule->predicates = (WambleTreatmentRulePredicateSpec *)calloc(
      (size_t)count, sizeof(*rule->predicates));
  if (!rule->predicates)
    return -1;
  int idx = 0;
  for (LispValue *a = list; a && a->type == LISP_VALUE_PAIR;
       a = a->as.pair.cdr, idx++) {
    LispValue *expr = a->as.pair.car;
    if (!expr || expr->type != LISP_VALUE_PAIR)
      return -1;
    LispValue *head = expr->as.pair.car;
    if (!head || head->type != LISP_VALUE_SYMBOL ||
        strcmp(head->as.symbol, "match") != 0)
      return -1;
    LispValue *parts = expr->as.pair.cdr;
    if (!parts || parts->type != LISP_VALUE_PAIR)
      return -1;
    if (eval_string_arg(env, parts->as.pair.car,
                        &rule->predicates[idx].fact_key) != 0)
      return -1;
    parts = parts->as.pair.cdr;
    if (!parts || parts->type != LISP_VALUE_PAIR)
      return -1;
    if (eval_string_arg(env, parts->as.pair.car, &rule->predicates[idx].op) !=
        0)
      return -1;
    parts = parts->as.pair.cdr;
    if (!parts || parts->type != LISP_VALUE_PAIR)
      return -1;
    if (eval_treatment_value_arg(env, parts->as.pair.car,
                                 &rule->predicates[idx].value) != 0)
      return -1;
  }
  rule->predicate_count = count;
  return 0;
}

static LispValue *builtin_treatment_assign(LispEnv *env, LispValue *args) {
  if (!args || args->type != LISP_VALUE_PAIR)
    return make_value(LISP_VALUE_NIL);
  WambleTreatmentRuleSpec rule = {0};
  rule.identity_selector = wamble_strdup("*");
  rule.profile_scope = wamble_strdup("*");
  if (!rule.identity_selector || !rule.profile_scope) {
    treatment_rule_clear(&rule);
    return make_value(LISP_VALUE_NIL);
  }
  int idx = 0;
  LispValue *pred_start = NULL;
  for (LispValue *a = args; a && a->type == LISP_VALUE_PAIR;
       a = a->as.pair.cdr, idx++) {
    if (idx == 0) {
      free(rule.identity_selector);
      rule.identity_selector = NULL;
      if (eval_string_arg(env, a->as.pair.car, &rule.identity_selector) != 0)
        break;
    } else if (idx == 1) {
      free(rule.profile_scope);
      rule.profile_scope = NULL;
      if (eval_string_arg(env, a->as.pair.car, &rule.profile_scope) != 0)
        break;
    } else if (idx == 2) {
      if (eval_string_arg(env, a->as.pair.car, &rule.group_key) != 0)
        break;
    } else if (idx == 3) {
      if (eval_int_arg(env, a->as.pair.car, &rule.priority) != 0)
        break;
    } else {
      pred_start = a;
      break;
    }
  }
  int ok =
      (rule.identity_selector && rule.profile_scope && rule.group_key) ? 1 : 0;
  if (ok && pred_start &&
      treatment_parse_predicates(env, pred_start, &rule) != 0)
    ok = 0;
  if (ok && treatment_rules_append(&rule) != 0)
    ok = 0;
  treatment_rule_clear(&rule);
  if (!ok)
    return make_value(LISP_VALUE_NIL);
  LispValue *one = make_value(LISP_VALUE_INTEGER);
  one->as.integer = 1;
  return one;
}

static LispValue *builtin_treatment_edge(LispEnv *env, LispValue *args) {
  if (!args || args->type != LISP_VALUE_PAIR)
    return make_value(LISP_VALUE_NIL);
  WambleTreatmentEdgeSpec edge = {0};
  if (eval_string_arg(env, args->as.pair.car, &edge.source_group_key) != 0) {
    treatment_edge_clear(&edge);
    return make_value(LISP_VALUE_NIL);
  }
  if (!args->as.pair.cdr || args->as.pair.cdr->type != LISP_VALUE_PAIR ||
      eval_string_arg(env, args->as.pair.cdr->as.pair.car,
                      &edge.target_group_key) != 0) {
    treatment_edge_clear(&edge);
    return make_value(LISP_VALUE_NIL);
  }
  int ok = (treatment_edges_append(&edge) == 0);
  treatment_edge_clear(&edge);
  if (!ok)
    return make_value(LISP_VALUE_NIL);
  LispValue *one = make_value(LISP_VALUE_INTEGER);
  one->as.integer = 1;
  return one;
}

static LispValue *builtin_treatment_output_record(LispEnv *env, LispValue *args,
                                                  const char *kind) {
  if (!args || args->type != LISP_VALUE_PAIR)
    return make_value(LISP_VALUE_NIL);
  WambleTreatmentOutputSpec out = {0};
  out.output_kind = wamble_strdup(kind);
  out.hook_name = wamble_strdup("*");
  if (!out.output_kind || !out.hook_name) {
    treatment_output_clear(&out);
    return make_value(LISP_VALUE_NIL);
  }
  int arg_count = 0;
  for (LispValue *a = args; a && a->type == LISP_VALUE_PAIR; a = a->as.pair.cdr)
    arg_count++;
  int idx = 0;
  int uses_wildcard_hook = (strcmp(kind, "tag") != 0 && arg_count == 3);
  for (LispValue *a = args; a && a->type == LISP_VALUE_PAIR;
       a = a->as.pair.cdr, idx++) {
    if (idx == 0) {
      if (eval_string_arg(env, a->as.pair.car, &out.group_key) != 0)
        break;
    } else if (idx == 1 && strcmp(kind, "tag") == 0) {
      if (eval_string_arg(env, a->as.pair.car, &out.output_key) != 0)
        break;
    } else if (idx == 1 && uses_wildcard_hook) {
      if (eval_string_arg(env, a->as.pair.car, &out.output_key) != 0)
        break;
    } else if (idx == 1) {
      free(out.hook_name);
      out.hook_name = NULL;
      if (eval_string_arg(env, a->as.pair.car, &out.hook_name) != 0)
        break;
    } else if (idx == 2 && strcmp(kind, "tag") != 0 && !uses_wildcard_hook) {
      if (eval_string_arg(env, a->as.pair.car, &out.output_key) != 0)
        break;
    } else {
      if (strcmp(kind, "tag") == 0) {
        out.value.type = WAMBLE_TREATMENT_VALUE_STRING;
        out.value.string_value =
            wamble_strdup(out.output_key ? out.output_key : "");
      } else if (eval_treatment_value_arg(env, a->as.pair.car, &out.value) !=
                 0) {
        break;
      }
      idx = 1000;
      break;
    }
  }
  if (strcmp(kind, "tag") == 0 && out.output_key && out.value.type == 0) {
    out.value.type = WAMBLE_TREATMENT_VALUE_STRING;
    out.value.string_value = wamble_strdup(out.output_key);
  }
  int ok = (out.group_key && out.output_kind && out.output_key) ? 1 : 0;
  if (ok && treatment_outputs_append(&out) != 0)
    ok = 0;
  treatment_output_clear(&out);
  if (!ok)
    return make_value(LISP_VALUE_NIL);
  LispValue *one = make_value(LISP_VALUE_INTEGER);
  one->as.integer = 1;
  return one;
}

static LispValue *builtin_treatment_view_record(LispEnv *env, LispValue *args,
                                                const char *output_key) {
  if (!args || args->type != LISP_VALUE_PAIR || !output_key)
    return make_value(LISP_VALUE_NIL);
  WambleTreatmentOutputSpec out = {0};
  out.output_kind = wamble_strdup("view");
  out.output_key = wamble_strdup(output_key);
  if (!out.output_kind || !out.output_key) {
    treatment_output_clear(&out);
    return make_value(LISP_VALUE_NIL);
  }
  int idx = 0;
  for (LispValue *a = args; a && a->type == LISP_VALUE_PAIR;
       a = a->as.pair.cdr, idx++) {
    if (idx == 0) {
      if (eval_string_arg(env, a->as.pair.car, &out.group_key) != 0)
        break;
    } else if (idx == 1) {
      if (eval_string_arg(env, a->as.pair.car, &out.hook_name) != 0)
        break;
    } else {
      if (eval_treatment_value_arg(env, a->as.pair.car, &out.value) != 0)
        break;
      idx = 1000;
      break;
    }
  }
  int ok = (out.group_key && out.hook_name && out.output_kind &&
            out.output_key && out.value.type != WAMBLE_TREATMENT_VALUE_NONE)
               ? 1
               : 0;
  if (ok && treatment_outputs_append(&out) != 0)
    ok = 0;
  treatment_output_clear(&out);
  if (!ok)
    return make_value(LISP_VALUE_NIL);
  LispValue *one = make_value(LISP_VALUE_INTEGER);
  one->as.integer = 1;
  return one;
}

static LispValue *builtin_treatment_tag(LispEnv *env, LispValue *args) {
  return builtin_treatment_output_record(env, args, "tag");
}

static LispValue *builtin_treatment_feature(LispEnv *env, LispValue *args) {
  return builtin_treatment_output_record(env, args, "feature");
}

static LispValue *builtin_treatment_context(LispEnv *env, LispValue *args) {
  return builtin_treatment_output_record(env, args, "context");
}

static LispValue *builtin_treatment_behavior(LispEnv *env, LispValue *args) {
  return builtin_treatment_output_record(env, args, "behavior");
}

static LispValue *builtin_treatment_meta(LispEnv *env, LispValue *args) {
  return builtin_treatment_output_record(env, args, "meta");
}

static LispValue *builtin_treatment_payload(LispEnv *env, LispValue *args) {
  int before = g_treatment_output_count;
  LispValue *res = builtin_treatment_output_record(env, args, "payload");
  if (!args || args->type != LISP_VALUE_PAIR ||
      g_treatment_output_count <= before)
    return res;

  WambleTreatmentOutputSpec *out = NULL;
  if (g_treatment_output_count > 0)
    out = &g_treatment_outputs[g_treatment_output_count - 1];
  if (!out || !out->hook_name || strcmp(out->output_kind, "payload") != 0)
    return res;

  for (char *p = out->hook_name; *p; ++p) {
    if (*p >= 'A' && *p <= 'Z')
      *p = (char)(*p - 'A' + 'a');
    else if (*p == '-')
      *p = '_';
  }
  if (strcmp(out->hook_name, "") == 0) {
    char *grown = (char *)realloc(out->hook_name, 2);
    if (grown) {
      out->hook_name = grown;
      out->hook_name[0] = '*';
      out->hook_name[1] = '\0';
    }
  }
  return res;
}

static LispValue *builtin_treatment_visible_fen(LispEnv *env, LispValue *args) {
  return builtin_treatment_view_record(env, args, "board.fen");
}

static LispValue *builtin_treatment_last_move(LispEnv *env, LispValue *args) {
  if (!args || args->type != LISP_VALUE_PAIR)
    return make_value(LISP_VALUE_NIL);
  WambleTreatmentOutputSpec type_out = {0};
  type_out.output_kind = wamble_strdup("view");
  type_out.output_key = wamble_strdup("last_move.type");
  if (!type_out.output_kind || !type_out.output_key) {
    treatment_output_clear(&type_out);
    return make_value(LISP_VALUE_NIL);
  }

  int have_age = 0;
  int max_age = 0;
  char group_key[128] = {0};
  char hook_name[64] = {0};
  int idx = 0;
  for (LispValue *a = args; a && a->type == LISP_VALUE_PAIR;
       a = a->as.pair.cdr, idx++) {
    if (idx == 0) {
      if (eval_string_arg(env, a->as.pair.car, &type_out.group_key) != 0)
        break;
    } else if (idx == 1) {
      if (eval_string_arg(env, a->as.pair.car, &type_out.hook_name) != 0)
        break;
    } else if (idx == 2) {
      if (eval_treatment_value_arg(env, a->as.pair.car, &type_out.value) != 0)
        break;
    } else if (idx == 3) {
      if (eval_int_arg(env, a->as.pair.car, &max_age) != 0)
        break;
      have_age = 1;
    } else {
      break;
    }
  }

  int ok = (idx >= 3 && idx <= 4 && type_out.group_key && type_out.hook_name &&
            type_out.output_kind && type_out.output_key &&
            type_out.value.type != WAMBLE_TREATMENT_VALUE_NONE)
               ? 1
               : 0;
  if (ok) {
    snprintf(group_key, sizeof(group_key), "%s", type_out.group_key);
    snprintf(hook_name, sizeof(hook_name), "%s", type_out.hook_name);
  }
  if (ok && treatment_outputs_append(&type_out) != 0)
    ok = 0;
  treatment_output_clear(&type_out);
  if (!ok)
    return make_value(LISP_VALUE_NIL);

  if (have_age) {
    WambleTreatmentOutputSpec age_out = {0};
    age_out.group_key = wamble_strdup(group_key);
    age_out.hook_name = wamble_strdup(hook_name);
    age_out.output_kind = wamble_strdup("view");
    age_out.output_key = wamble_strdup("last_move.max_age_ms");
    age_out.value.type = WAMBLE_TREATMENT_VALUE_INT;
    age_out.value.int_value = (int64_t)max_age;
    int age_ok = (age_out.group_key && age_out.hook_name &&
                  age_out.output_kind && age_out.output_key)
                     ? 1
                     : 0;
    if (age_ok && treatment_outputs_append(&age_out) != 0)
      age_ok = 0;
    treatment_output_clear(&age_out);
    if (!age_ok)
      return make_value(LISP_VALUE_NIL);
  }

  LispValue *one = make_value(LISP_VALUE_INTEGER);
  one->as.integer = 1;
  return one;
}

static LispValue *builtin_treatment_last_move_data(LispEnv *env,
                                                   LispValue *args) {
  if (!args || args->type != LISP_VALUE_PAIR)
    return make_value(LISP_VALUE_NIL);
  WambleTreatmentOutputSpec out = {0};
  out.output_kind = wamble_strdup("view");
  if (!out.output_kind) {
    treatment_output_clear(&out);
    return make_value(LISP_VALUE_NIL);
  }

  char *data_key = NULL;
  int idx = 0;
  for (LispValue *a = args; a && a->type == LISP_VALUE_PAIR;
       a = a->as.pair.cdr, idx++) {
    if (idx == 0) {
      if (eval_string_arg(env, a->as.pair.car, &out.group_key) != 0)
        break;
    } else if (idx == 1) {
      if (eval_string_arg(env, a->as.pair.car, &out.hook_name) != 0)
        break;
    } else if (idx == 2) {
      if (eval_string_arg(env, a->as.pair.car, &data_key) != 0)
        break;
    } else if (idx == 3) {
      if (eval_treatment_value_arg(env, a->as.pair.car, &out.value) != 0)
        break;
    } else {
      break;
    }
  }
  int ok = (idx == 4 && out.group_key && out.hook_name && out.output_kind &&
            data_key && out.value.type != WAMBLE_TREATMENT_VALUE_NONE)
               ? 1
               : 0;
  if (ok) {
    char full_key[192];
    snprintf(full_key, sizeof(full_key), "%s%s", "last_move.data.", data_key);
    out.output_key = wamble_strdup(full_key);
    ok = (out.output_key != NULL) ? 1 : 0;
  }
  if (ok && treatment_outputs_append(&out) != 0)
    ok = 0;
  free(data_key);
  treatment_output_clear(&out);
  if (!ok)
    return make_value(LISP_VALUE_NIL);
  LispValue *one = make_value(LISP_VALUE_INTEGER);
  one->as.integer = 1;
  return one;
}

static LispValue *builtin_treatment_predictions_from_moves(LispEnv *env,
                                                           LispValue *args) {
  if (!args || args->type != LISP_VALUE_PAIR)
    return make_value(LISP_VALUE_NIL);
  WambleTreatmentOutputSpec out = {0};
  out.group_key = NULL;
  out.hook_name = NULL;
  out.output_kind = wamble_strdup("view");
  out.output_key = wamble_strdup("prediction.source");
  if (!out.output_kind || !out.output_key) {
    treatment_output_clear(&out);
    return make_value(LISP_VALUE_NIL);
  }
  int idx = 0;
  for (LispValue *a = args; a && a->type == LISP_VALUE_PAIR;
       a = a->as.pair.cdr, idx++) {
    if (idx == 0) {
      if (eval_string_arg(env, a->as.pair.car, &out.group_key) != 0)
        break;
    } else if (idx == 1) {
      if (eval_string_arg(env, a->as.pair.car, &out.hook_name) != 0)
        break;
    } else {
      break;
    }
  }
  out.value.type = WAMBLE_TREATMENT_VALUE_STRING;
  out.value.string_value = wamble_strdup("moves");
  int ok = (out.group_key && out.hook_name && out.output_kind &&
            out.output_key && out.value.string_value)
               ? 1
               : 0;
  if (ok && treatment_outputs_append(&out) != 0)
    ok = 0;
  treatment_output_clear(&out);
  if (!ok)
    return make_value(LISP_VALUE_NIL);
  LispValue *one = make_value(LISP_VALUE_INTEGER);
  one->as.integer = 1;
  return one;
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
        def_sym->as.symbol = wamble_strdup("def");
        LispValue *inherits_sym = make_value(LISP_VALUE_SYMBOL);
        inherits_sym->as.symbol = wamble_strdup("inherits");
        LispValue *base_str = make_value(LISP_VALUE_STRING);
        base_str->as.string = wamble_strdup(base_name);

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
  profiles_sym->as.symbol = wamble_strdup("*profiles*");

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

static LispValue *builtin_profile_local_unsupported(LispEnv *env,
                                                    LispValue *args) {
  (void)env;
  (void)args;
  g_profile_local_unsupported_seen = 1;
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
    CONF_ITEM("websocket-enabled", CONF_INT, websocket_enabled),
    CONF_ITEM("websocket-port", CONF_INT, websocket_port),
    CONF_ITEM("experiment-enabled", CONF_INT, experiment_enabled),
    CONF_ITEM("experiment-seed", CONF_INT, experiment_seed),
    CONF_ITEM("timeout-ms", CONF_INT, timeout_ms),
    CONF_ITEM("max-retries", CONF_INT, max_retries),
    CONF_ITEM("max-message-size", CONF_INT, max_message_size),
    CONF_ITEM("buffer-size", CONF_INT, buffer_size),
    CONF_ITEM("terminal-cache-ttl-ms", CONF_INT, terminal_cache_ttl_ms),
    CONF_ITEM("rate-limit-requests-per-sec", CONF_INT,
              rate_limit_requests_per_sec),
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
    CONF_ITEM("db-host", CONF_STRING, db_host),
    CONF_ITEM("db-port", CONF_INT, db_port),
    CONF_ITEM("db-user", CONF_STRING, db_user),
    CONF_ITEM("db-pass", CONF_STRING, db_pass),
    CONF_ITEM("db-name", CONF_STRING, db_name),
    CONF_ITEM("global-db-host", CONF_STRING, global_db_host),
    CONF_ITEM("global-db-port", CONF_INT, global_db_port),
    CONF_ITEM("global-db-user", CONF_STRING, global_db_user),
    CONF_ITEM("global-db-pass", CONF_STRING, global_db_pass),
    CONF_ITEM("global-db-name", CONF_STRING, global_db_name),
    CONF_ITEM("select-timeout-usec", CONF_INT, select_timeout_usec),
    CONF_ITEM("cleanup-interval-sec", CONF_INT, cleanup_interval_sec),
    CONF_ITEM("max-token-attempts", CONF_INT, max_token_attempts),
    CONF_ITEM("max-token-local-attempts", CONF_INT, max_token_local_attempts),
    CONF_ITEM("persistence-max-intents", CONF_INT, persistence_max_intents),
    CONF_ITEM("persistence-max-payload-bytes", CONF_INT,
              persistence_max_payload_bytes),
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
    CONF_ITEM("prediction-mode", CONF_INT, prediction_mode),
    CONF_ITEM("prediction-base-points", CONF_DOUBLE, prediction_base_points),
    CONF_ITEM("prediction-streak-multiplier", CONF_DOUBLE,
              prediction_streak_multiplier),
    CONF_ITEM("prediction-streak-cap", CONF_INT, prediction_streak_cap),
    CONF_ITEM("prediction-gated-percent", CONF_INT, prediction_gated_percent),
    CONF_ITEM("prediction-view-depth-limit", CONF_INT,
              prediction_view_depth_limit),
    CONF_ITEM("prediction-penalty-incorrect", CONF_DOUBLE,
              prediction_penalty_incorrect),
    CONF_ITEM("prediction-match-policy", CONF_STRING, prediction_match_policy),
    CONF_ITEM("prediction-max-pending", CONF_INT, prediction_max_pending),
    CONF_ITEM("prediction-max-per-parent", CONF_INT, prediction_max_per_parent),
    CONF_ITEM("prediction-enforce-move-duplicate", CONF_INT,
              prediction_enforce_move_duplicate),
    CONF_ITEM("spectator-summary-mode", CONF_STRING, spectator_summary_mode),
    CONF_ITEM("state-dir", CONF_STRING, state_dir),
    CONF_ITEM("websocket-path", CONF_STRING, websocket_path),
    CONF_ITEM("chess960-interval", CONF_INT, chess960_interval)};

static void populate_config_from_env(LispEnv *env) {
  for (size_t i = 0; i < sizeof(config_map) / sizeof(config_map[0]); i++) {
    const ConfigVarMap *item = &config_map[i];
    LispValue sym;
    sym.type = LISP_VALUE_SYMBOL;
    sym.as.symbol = wamble_strdup(item->name);

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
        *(char **)target = wamble_strdup(val->as.string);
      }
      break;
    }
    free_lisp_value(val);
  }
}

static void config_set_defaults(void) {
  g_config.port = 8888;
  g_config.websocket_enabled = 0;
  g_config.websocket_port = 0;
  g_config.experiment_enabled = 0;
  g_config.experiment_seed = 0;
  g_config.timeout_ms = 100;
  g_config.max_retries = 3;
  g_config.max_message_size = 126;
  g_config.buffer_size = 32768;
  g_config.terminal_cache_ttl_ms = 2000;
  g_config.rate_limit_requests_per_sec = 120;
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
  g_config.db_host = wamble_strdup("localhost");
  g_config.db_port = 5432;
  g_config.db_user = wamble_strdup("wamble");
  g_config.db_pass = wamble_strdup("wamble");
  g_config.db_name = wamble_strdup("wamble");
  g_config.global_db_host = wamble_strdup("localhost");
  g_config.global_db_port = 5432;
  g_config.global_db_user = wamble_strdup("wamble");
  g_config.global_db_pass = wamble_strdup("wamble");
  g_config.global_db_name = wamble_strdup("wamble_global");
  g_config.select_timeout_usec = 100000;
  g_config.cleanup_interval_sec = 60;
  g_config.max_token_attempts = 1000;
  g_config.max_token_local_attempts = 100;
  g_config.persistence_max_intents = 128;
  g_config.persistence_max_payload_bytes = 64 * 1024;
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
  g_config.prediction_mode = 0;
  g_config.prediction_gated_percent = 10;
  g_config.prediction_streak_cap = 10;
  g_config.prediction_max_pending = 64;
  g_config.prediction_max_per_parent = 1;
  g_config.prediction_enforce_move_duplicate = 1;
  g_config.prediction_view_depth_limit = 2;
  g_config.prediction_base_points = 1.0;
  g_config.prediction_streak_multiplier = 2.0;
  g_config.prediction_penalty_incorrect = 0.0;
  g_config.prediction_match_policy = wamble_strdup("exact-uci");
  g_config.spectator_summary_mode = wamble_strdup("changes");
  g_config.state_dir = NULL;
  g_config.websocket_path = wamble_strdup("/ws");
  g_config.chess960_interval = -1;
}

static void free_profiles(void) {
  if (!g_profiles)
    return;
  for (int i = 0; i < g_profile_count; i++) {
    free(g_profiles[i].name);
    free(g_profiles[i].group);
    free(g_profiles[i].tos_text);

    free(g_profiles[i].config.db_host);
    free(g_profiles[i].config.db_user);
    free(g_profiles[i].config.db_pass);
    free(g_profiles[i].config.db_name);
    free(g_profiles[i].config.global_db_host);
    free(g_profiles[i].config.global_db_user);
    free(g_profiles[i].config.global_db_pass);
    free(g_profiles[i].config.global_db_name);
    free(g_profiles[i].config.spectator_summary_mode);
    free(g_profiles[i].config.prediction_match_policy);
    free(g_profiles[i].config.state_dir);
    free(g_profiles[i].config.websocket_path);
  }
  free(g_profiles);
  g_profiles = NULL;
  g_profile_count = 0;
}

static LispEnv *build_policy_env_from_source(const char *source) {
  if (!source)
    return NULL;
  Stream s = {.p = source, .end = source + strlen(source)};
  LispEnv *env = lisp_env_create(NULL);
  if (!env)
    return NULL;

  LispValue *def_sym = make_value(LISP_VALUE_SYMBOL);
  LispValue *def_builtin = make_value(LISP_VALUE_BUILTIN);
  LispValue *defprofile_sym = make_value(LISP_VALUE_SYMBOL);
  LispValue *defprofile_builtin = make_value(LISP_VALUE_BUILTIN);
  if (!def_sym || !def_builtin || !defprofile_sym || !defprofile_builtin) {
    free_lisp_value(def_sym);
    free_lisp_value(def_builtin);
    free_lisp_value(defprofile_sym);
    free_lisp_value(defprofile_builtin);
    lisp_env_free(env);
    return NULL;
  }
  def_sym->as.symbol = wamble_strdup("def");
  def_builtin->as.builtin = builtin_def;
  defprofile_sym->as.symbol = wamble_strdup("defprofile");
  defprofile_builtin->as.builtin = builtin_defprofile;
  if (!def_sym->as.symbol || !defprofile_sym->as.symbol) {
    free_lisp_value(def_sym);
    free_lisp_value(def_builtin);
    free_lisp_value(defprofile_sym);
    free_lisp_value(defprofile_builtin);
    lisp_env_free(env);
    return NULL;
  }
  lisp_env_put(env, def_sym, def_builtin);
  lisp_env_put(env, defprofile_sym, defprofile_builtin);
  free_lisp_value(def_sym);
  free_lisp_value(def_builtin);
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
      {"policy-allow", builtin_policy_allow},
      {"policy-deny", builtin_policy_deny},
      {"treatment-group", builtin_treatment_group},
      {"treatment-default", builtin_treatment_default},
      {"treatment-assign", builtin_treatment_assign},
      {"treatment-edge", builtin_treatment_edge},
      {"treatment-tag", builtin_treatment_tag},
      {"treatment-feature", builtin_treatment_feature},
      {"treatment-context", builtin_treatment_context},
      {"treatment-behavior", builtin_treatment_behavior},
      {"treatment-meta", builtin_treatment_meta},
      {"treatment-payload", builtin_treatment_payload},
      {"treatment-visible-fen", builtin_treatment_visible_fen},
      {"treatment-last-move", builtin_treatment_last_move},
      {"treatment-last-move-data", builtin_treatment_last_move_data},
      {"treatment-predictions-from-moves",
       builtin_treatment_predictions_from_moves},
  };
  for (size_t i = 0; i < sizeof(builtins) / sizeof(builtins[0]); i++) {
    LispValue *sym = make_value(LISP_VALUE_SYMBOL);
    LispValue *fn = make_value(LISP_VALUE_BUILTIN);
    if (!sym || !fn) {
      free_lisp_value(sym);
      free_lisp_value(fn);
      lisp_env_free(env);
      return NULL;
    }
    sym->as.symbol = wamble_strdup(builtins[i].name);
    fn->as.builtin = builtins[i].fn;
    if (!sym->as.symbol) {
      free_lisp_value(sym);
      free_lisp_value(fn);
      lisp_env_free(env);
      return NULL;
    }
    lisp_env_put(env, sym, fn);
    free_lisp_value(sym);
    free_lisp_value(fn);
  }

  WamblePolicyRuleSpec *saved_rules = g_policy_rules;
  int saved_rule_count = g_policy_rule_count;
  WambleTreatmentGroupSpec *saved_treatment_groups = g_treatment_groups;
  int saved_treatment_group_count = g_treatment_group_count;
  WambleTreatmentRuleSpec *saved_treatment_rules = g_treatment_rules;
  int saved_treatment_rule_count = g_treatment_rule_count;
  WambleTreatmentEdgeSpec *saved_treatment_edges = g_treatment_edges;
  int saved_treatment_edge_count = g_treatment_edge_count;
  WambleTreatmentOutputSpec *saved_treatment_outputs = g_treatment_outputs;
  int saved_treatment_output_count = g_treatment_output_count;
  g_policy_rules = NULL;
  g_policy_rule_count = 0;
  g_treatment_groups = NULL;
  g_treatment_group_count = 0;
  g_treatment_rules = NULL;
  g_treatment_rule_count = 0;
  g_treatment_edges = NULL;
  g_treatment_edge_count = 0;
  g_treatment_outputs = NULL;
  g_treatment_output_count = 0;

  while (s.p < s.end) {
    LispValue *expr = parse_expr(&s);
    if (expr) {
      LispValue *result = eval_expr(env, expr);
      free_lisp_value(result);
      free_lisp_value(expr);
    }
  }

  policy_rules_free(g_policy_rules, g_policy_rule_count);
  g_policy_rules = saved_rules;
  g_policy_rule_count = saved_rule_count;
  treatment_groups_free(g_treatment_groups, g_treatment_group_count);
  g_treatment_groups = saved_treatment_groups;
  g_treatment_group_count = saved_treatment_group_count;
  treatment_rules_free(g_treatment_rules, g_treatment_rule_count);
  g_treatment_rules = saved_treatment_rules;
  g_treatment_rule_count = saved_treatment_rule_count;
  treatment_edges_free(g_treatment_edges, g_treatment_edge_count);
  g_treatment_edges = saved_treatment_edges;
  g_treatment_edge_count = saved_treatment_edge_count;
  treatment_outputs_free(g_treatment_outputs, g_treatment_output_count);
  g_treatment_outputs = saved_treatment_outputs;
  g_treatment_output_count = saved_treatment_output_count;
  return env;
}

ConfigLoadStatus config_load(const char *filename, const char *profile,
                             char *status_msg, size_t status_msg_size) {
  void *rollback_snapshot = NULL;
  if (!g_policy_eval_mutex_ready) {
    if (wamble_mutex_init(&g_policy_eval_mutex) == 0) {
      g_policy_eval_mutex_ready = 1;
    }
  }
  if (status_msg && status_msg_size)
    status_msg[0] = '\0';
  if (g_config.db_host && g_config.db_user && g_config.db_pass &&
      g_config.db_name && g_config.global_db_host && g_config.global_db_user &&
      g_config.global_db_pass && g_config.global_db_name &&
      g_config.spectator_summary_mode && g_config.prediction_match_policy &&
      g_config.websocket_path) {
    rollback_snapshot = config_create_snapshot();
  }
  g_profile_local_unsupported_seen = 0;
  LispEnv *prev_policy_env = policy_env_swap(NULL);
  policy_rules_free(g_policy_rules, g_policy_rule_count);
  g_policy_rules = NULL;
  g_policy_rule_count = 0;
  treatment_groups_free(g_treatment_groups, g_treatment_group_count);
  g_treatment_groups = NULL;
  g_treatment_group_count = 0;
  treatment_rules_free(g_treatment_rules, g_treatment_rule_count);
  g_treatment_rules = NULL;
  g_treatment_rule_count = 0;
  treatment_edges_free(g_treatment_edges, g_treatment_edge_count);
  g_treatment_edges = NULL;
  g_treatment_edge_count = 0;
  treatment_outputs_free(g_treatment_outputs, g_treatment_output_count);
  g_treatment_outputs = NULL;
  g_treatment_output_count = 0;
  if (g_profiles) {
    free_profiles();
    g_config.db_host = NULL;
    g_config.db_user = NULL;
    g_config.db_pass = NULL;
    g_config.db_name = NULL;
    g_config.global_db_host = NULL;
    g_config.global_db_user = NULL;
    g_config.global_db_pass = NULL;
    g_config.global_db_name = NULL;
    g_config.spectator_summary_mode = NULL;
    g_config.prediction_match_policy = NULL;
    g_config.state_dir = NULL;
    g_config.websocket_path = NULL;
  } else {
    free(g_config.db_host);
    free(g_config.db_user);
    free(g_config.db_pass);
    free(g_config.db_name);
    free(g_config.global_db_host);
    free(g_config.global_db_user);
    free(g_config.global_db_pass);
    free(g_config.global_db_name);
    free(g_config.spectator_summary_mode);
    free(g_config.prediction_match_policy);
    free(g_config.state_dir);
    free(g_config.websocket_path);
  }
  config_set_defaults();

  if (!filename) {
    if (prev_policy_env)
      lisp_env_free(prev_policy_env);
    config_free_snapshot(rollback_snapshot);
    if (status_msg && status_msg_size)
      snprintf(status_msg, status_msg_size, "defaults: no file provided");
    return CONFIG_LOAD_DEFAULTS;
  }

  FILE *f = fopen(filename, "r");
  if (!f) {
    if (prev_policy_env)
      lisp_env_free(prev_policy_env);
    config_free_snapshot(rollback_snapshot);
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
  def_sym->as.symbol = wamble_strdup("def");
  LispValue *def_builtin = make_value(LISP_VALUE_BUILTIN);
  def_builtin->as.builtin = builtin_def;
  lisp_env_put(env, def_sym, def_builtin);
  free_lisp_value(def_sym);
  free_lisp_value(def_builtin);

  LispValue *defprofile_sym = make_value(LISP_VALUE_SYMBOL);
  defprofile_sym->as.symbol = wamble_strdup("defprofile");
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
      {"policy-allow", builtin_policy_allow},
      {"policy-deny", builtin_policy_deny},
      {"treatment-group", builtin_treatment_group},
      {"treatment-default", builtin_treatment_default},
      {"treatment-assign", builtin_treatment_assign},
      {"treatment-edge", builtin_treatment_edge},
      {"treatment-tag", builtin_treatment_tag},
      {"treatment-feature", builtin_treatment_feature},
      {"treatment-context", builtin_treatment_context},
      {"treatment-behavior", builtin_treatment_behavior},
      {"treatment-meta", builtin_treatment_meta},
      {"treatment-payload", builtin_treatment_payload},
      {"treatment-visible-fen", builtin_treatment_visible_fen},
      {"treatment-last-move", builtin_treatment_last_move},
      {"treatment-last-move-data", builtin_treatment_last_move_data},
      {"treatment-predictions-from-moves",
       builtin_treatment_predictions_from_moves},
  };
  for (size_t i = 0; i < sizeof(builtins) / sizeof(builtins[0]); i++) {
    LispValue *sym = make_value(LISP_VALUE_SYMBOL);
    sym->as.symbol = wamble_strdup(builtins[i].name);
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
    profiles_sym->as.symbol = wamble_strdup("*profiles*");
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
          {
            const char *unsupported[] = {
                "policy-allow",
                "policy-deny",
                "treatment-group",
                "treatment-default",
                "treatment-assign",
                "treatment-edge",
                "treatment-tag",
                "treatment-feature",
                "treatment-context",
                "treatment-behavior",
                "treatment-meta",
                "treatment-payload",
                "treatment-visible-fen",
                "treatment-last-move",
                "treatment-last-move-data",
                "treatment-predictions-from-moves",
            };
            for (size_t u = 0; u < sizeof(unsupported) / sizeof(unsupported[0]);
                 u++) {
              LispValue *sym = make_value(LISP_VALUE_SYMBOL);
              LispValue *fn = make_value(LISP_VALUE_BUILTIN);
              sym->as.symbol = wamble_strdup(unsupported[u]);
              fn->as.builtin = builtin_profile_local_unsupported;
              lisp_env_put(profile_env, sym, fn);
              free_lisp_value(sym);
              free_lisp_value(fn);
            }
          }
          for (LispValue *v = prof->as.pair.cdr;
               v && v->type == LISP_VALUE_PAIR; v = v->as.pair.cdr) {
            LispValue *res = eval_expr(profile_env, v->as.pair.car);
            free_lisp_value(res);
          }
          if (g_profile_local_unsupported_seen) {
            if (status_msg && status_msg_size) {
              snprintf(
                  status_msg, status_msg_size,
                  "unsupported policy/treatment declaration inside defprofile");
            }
            lisp_env_free(profile_env);
            free(processed);
            free(plist);
            g_profile_count = built;
            free_profiles();
            free_lisp_value(profiles);
            (void)policy_env_swap(prev_policy_env);
            prev_policy_env = NULL;
            if (env)
              lisp_env_free(env);
            free(source);
            if (rollback_snapshot)
              (void)config_restore_snapshot(rollback_snapshot);
            config_free_snapshot(rollback_snapshot);
            return CONFIG_LOAD_IO_ERROR;
          }

          char *base_name = NULL;
          {
            LispValue sym;
            sym.type = LISP_VALUE_SYMBOL;
            sym.as.symbol = (char *)"inherits";
            LispValue *val = lisp_env_get(profile_env, &sym);
            if (val->type == LISP_VALUE_STRING && val->as.string &&
                val->as.string[0] != '\0') {
              base_name = wamble_strdup(val->as.string);
            }
            free_lisp_value(val);
          }

          WambleConfig base_cfg = g_config;
          int base_advertise = 0;
          int base_visibility = 0;
          int base_db_isolated = 0;
          const char *base_group = NULL;
          const char *base_tos_text = NULL;
          if (base_name) {
            int found = 0;
            for (int j = 0; j < count; j++) {
              if (processed[j] && g_profiles[j].name &&
                  strcmp(g_profiles[j].name, base_name) == 0) {
                base_cfg = g_profiles[j].config;
                base_advertise = g_profiles[j].advertise;
                base_visibility = g_profiles[j].visibility;
                base_db_isolated = g_profiles[j].db_isolated;
                base_group = g_profiles[j].group;
                base_tos_text = g_profiles[j].tos_text;
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
          cfg.db_host = wamble_strdup(base_cfg.db_host);
          cfg.db_user = wamble_strdup(base_cfg.db_user);
          cfg.db_pass = wamble_strdup(base_cfg.db_pass);
          cfg.db_name = wamble_strdup(base_cfg.db_name);
          cfg.global_db_host = wamble_strdup(base_cfg.global_db_host);
          cfg.global_db_user = wamble_strdup(base_cfg.global_db_user);
          cfg.global_db_pass = wamble_strdup(base_cfg.global_db_pass);
          cfg.global_db_name = wamble_strdup(base_cfg.global_db_name);
          if (base_cfg.spectator_summary_mode)
            cfg.spectator_summary_mode =
                wamble_strdup(base_cfg.spectator_summary_mode);
          if (base_cfg.prediction_match_policy)
            cfg.prediction_match_policy =
                wamble_strdup(base_cfg.prediction_match_policy);
          if (base_cfg.state_dir)
            cfg.state_dir = wamble_strdup(base_cfg.state_dir);
          if (base_cfg.websocket_path)
            cfg.websocket_path = wamble_strdup(base_cfg.websocket_path);

          WambleConfig saved = g_config;
          g_config = cfg;
          populate_config_from_env(profile_env);
          WambleConfig overlaid = g_config;
          g_config = saved;

          int abstract = 0;
          int advertise = base_advertise;
          int visibility = base_visibility;
          int db_isolated = base_db_isolated;
          char *profile_group = NULL;
          if (base_group)
            profile_group = wamble_strdup(base_group);
          char *profile_tos = NULL;
          if (base_tos_text)
            profile_tos = wamble_strdup(base_tos_text);
          {
            LispValue sym;
            sym.type = LISP_VALUE_SYMBOL;
            sym.as.symbol = (char *)"abstract";
            LispValue *val = lisp_env_get(profile_env, &sym);
            if (val->type == LISP_VALUE_INTEGER)
              abstract = (int)val->as.integer;
            free_lisp_value(val);
            sym.as.symbol = (char *)"advertise";
            val = lisp_env_get(profile_env, &sym);
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
            sym.as.symbol = (char *)"profile-group";
            val = lisp_env_get(profile_env, &sym);
            if (val->type == LISP_VALUE_STRING) {
              free(profile_group);
              profile_group = wamble_strdup(val->as.string);
            }
            free_lisp_value(val);
            sym.as.symbol = (char *)"tos-text";
            val = lisp_env_get(profile_env, &sym);
            if (val->type == LISP_VALUE_STRING) {
              free(profile_tos);
              profile_tos = wamble_strdup(val->as.string);
            }
            free_lisp_value(val);
          }

          if (strcmp(pname, WAMBLE_DEFAULT_RUNTIME_EXPORT_NAME) == 0) {
            if (status_msg && status_msg_size) {
              snprintf(status_msg, status_msg_size,
                       "profile name '%s' is reserved",
                       WAMBLE_DEFAULT_RUNTIME_EXPORT_NAME);
            }
            free(profile_group);
            free(profile_tos);
            free(overlaid.db_host);
            free(overlaid.db_user);
            free(overlaid.db_pass);
            free(overlaid.db_name);
            free(overlaid.global_db_host);
            free(overlaid.global_db_user);
            free(overlaid.global_db_pass);
            free(overlaid.global_db_name);
            free(overlaid.spectator_summary_mode);
            free(overlaid.prediction_match_policy);
            free(overlaid.state_dir);
            free(overlaid.websocket_path);
            lisp_env_free(profile_env);
            free(processed);
            free(plist);
            g_profile_count = built;
            free_profiles();
            free_lisp_value(profiles);
            (void)policy_env_swap(prev_policy_env);
            prev_policy_env = NULL;
            if (env)
              lisp_env_free(env);
            free(source);
            if (rollback_snapshot)
              (void)config_restore_snapshot(rollback_snapshot);
            config_free_snapshot(rollback_snapshot);
            return CONFIG_LOAD_IO_ERROR;
          }

          g_profiles[i].name = wamble_strdup(pname);
          g_profiles[i].group = profile_group;
          g_profiles[i].tos_text = profile_tos;
          g_profiles[i].config = overlaid;
          g_profiles[i].abstract = abstract;
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
            free(g_profiles[i].group);
            free(g_profiles[i].tos_text);
            free(g_profiles[i].config.db_host);
            free(g_profiles[i].config.db_user);
            free(g_profiles[i].config.db_pass);
            free(g_profiles[i].config.db_name);
            free(g_profiles[i].config.global_db_host);
            free(g_profiles[i].config.global_db_user);
            free(g_profiles[i].config.global_db_pass);
            free(g_profiles[i].config.global_db_name);
            free(g_profiles[i].config.spectator_summary_mode);
            free(g_profiles[i].config.prediction_match_policy);
            free(g_profiles[i].config.state_dir);
            free(g_profiles[i].config.websocket_path);
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
      (void)policy_env_swap(prev_policy_env);
      prev_policy_env = NULL;
      if (env)
        lisp_env_free(env);
      free(source);
      config_free_snapshot(rollback_snapshot);
      return CONFIG_LOAD_PROFILE_NOT_FOUND;
    }
  }

  (void)policy_env_swap(env);
  env = NULL;
  if (prev_policy_env)
    lisp_env_free(prev_policy_env);
  env = NULL;
  {
    char *loaded_copy = wamble_strdup(source);
    if (!loaded_copy) {
      if (status_msg && status_msg_size)
        snprintf(status_msg, status_msg_size, "loaded %s (source copy failed)",
                 filename);
      free(source);
      config_free_snapshot(rollback_snapshot);
      return CONFIG_LOAD_IO_ERROR;
    }
    free(g_last_loaded_source);
    g_last_loaded_source = loaded_copy;
  }
  if (status_msg && status_msg_size)
    snprintf(status_msg, status_msg_size, "loaded %s", filename);
  free(source);
  config_free_snapshot(rollback_snapshot);
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

static void snapshot_free_profiles(WambleProfile *profiles, int count) {
  if (!profiles)
    return;
  for (int i = 0; i < count; i++) {
    free(profiles[i].name);
    free(profiles[i].group);
    cfg_free_owned(&profiles[i].config);
  }
  free(profiles);
}

void *config_create_snapshot(void) {
  ConfigSnapshot *snap = (ConfigSnapshot *)calloc(1, sizeof(*snap));
  if (!snap)
    return NULL;
  if (cfg_dup_owned(&snap->config, &g_config) != 0) {
    free(snap);
    return NULL;
  }
  snap->profile_count = g_profile_count;
  if (g_profile_count > 0) {
    snap->profiles =
        (WambleProfile *)calloc((size_t)g_profile_count, sizeof(WambleProfile));
    if (!snap->profiles) {
      cfg_free_owned(&snap->config);
      free(snap);
      return NULL;
    }
    for (int i = 0; i < g_profile_count; i++) {
      snap->profiles[i] = g_profiles[i];
      snap->profiles[i].name =
          g_profiles[i].name ? wamble_strdup(g_profiles[i].name) : NULL;
      snap->profiles[i].group =
          g_profiles[i].group ? wamble_strdup(g_profiles[i].group) : NULL;
      if (cfg_dup_owned(&snap->profiles[i].config, &g_profiles[i].config) !=
              0 ||
          !snap->profiles[i].name) {
        snapshot_free_profiles(snap->profiles, snap->profile_count);
        cfg_free_owned(&snap->config);
        free(snap);
        return NULL;
      }
    }
  }
  snap->policy_rule_count = g_policy_rule_count;
  if (g_policy_rule_count > 0) {
    snap->policy_rules = (WamblePolicyRuleSpec *)calloc(
        (size_t)g_policy_rule_count, sizeof(WamblePolicyRuleSpec));
    if (!snap->policy_rules) {
      snapshot_free_profiles(snap->profiles, snap->profile_count);
      cfg_free_owned(&snap->config);
      free(snap);
      return NULL;
    }
    for (int i = 0; i < g_policy_rule_count; i++) {
      if (policy_rule_dup(&snap->policy_rules[i], &g_policy_rules[i]) != 0) {
        policy_rules_free(snap->policy_rules, g_policy_rule_count);
        snapshot_free_profiles(snap->profiles, snap->profile_count);
        cfg_free_owned(&snap->config);
        free(snap);
        return NULL;
      }
    }
  }
  snap->treatment_group_count = g_treatment_group_count;
  if (g_treatment_group_count > 0) {
    snap->treatment_groups = (WambleTreatmentGroupSpec *)calloc(
        (size_t)g_treatment_group_count, sizeof(WambleTreatmentGroupSpec));
    if (!snap->treatment_groups) {
      policy_rules_free(snap->policy_rules, snap->policy_rule_count);
      snapshot_free_profiles(snap->profiles, snap->profile_count);
      cfg_free_owned(&snap->config);
      free(snap);
      return NULL;
    }
    for (int i = 0; i < g_treatment_group_count; i++) {
      if (treatment_group_dup(&snap->treatment_groups[i],
                              &g_treatment_groups[i]) != 0) {
        treatment_groups_free(snap->treatment_groups,
                              snap->treatment_group_count);
        policy_rules_free(snap->policy_rules, snap->policy_rule_count);
        snapshot_free_profiles(snap->profiles, snap->profile_count);
        cfg_free_owned(&snap->config);
        free(snap);
        return NULL;
      }
    }
  }
  snap->treatment_rule_count = g_treatment_rule_count;
  if (g_treatment_rule_count > 0) {
    snap->treatment_rules = (WambleTreatmentRuleSpec *)calloc(
        (size_t)g_treatment_rule_count, sizeof(WambleTreatmentRuleSpec));
    if (!snap->treatment_rules) {
      treatment_groups_free(snap->treatment_groups,
                            snap->treatment_group_count);
      policy_rules_free(snap->policy_rules, snap->policy_rule_count);
      snapshot_free_profiles(snap->profiles, snap->profile_count);
      cfg_free_owned(&snap->config);
      free(snap);
      return NULL;
    }
    for (int i = 0; i < g_treatment_rule_count; i++) {
      if (treatment_rule_dup(&snap->treatment_rules[i],
                             &g_treatment_rules[i]) != 0) {
        treatment_rules_free(snap->treatment_rules, snap->treatment_rule_count);
        treatment_groups_free(snap->treatment_groups,
                              snap->treatment_group_count);
        policy_rules_free(snap->policy_rules, snap->policy_rule_count);
        snapshot_free_profiles(snap->profiles, snap->profile_count);
        cfg_free_owned(&snap->config);
        free(snap);
        return NULL;
      }
    }
  }
  snap->treatment_edge_count = g_treatment_edge_count;
  if (g_treatment_edge_count > 0) {
    snap->treatment_edges = (WambleTreatmentEdgeSpec *)calloc(
        (size_t)g_treatment_edge_count, sizeof(WambleTreatmentEdgeSpec));
    if (!snap->treatment_edges) {
      treatment_rules_free(snap->treatment_rules, snap->treatment_rule_count);
      treatment_groups_free(snap->treatment_groups,
                            snap->treatment_group_count);
      policy_rules_free(snap->policy_rules, snap->policy_rule_count);
      snapshot_free_profiles(snap->profiles, snap->profile_count);
      cfg_free_owned(&snap->config);
      free(snap);
      return NULL;
    }
    for (int i = 0; i < g_treatment_edge_count; i++) {
      if (treatment_edge_dup(&snap->treatment_edges[i],
                             &g_treatment_edges[i]) != 0) {
        treatment_edges_free(snap->treatment_edges, snap->treatment_edge_count);
        treatment_rules_free(snap->treatment_rules, snap->treatment_rule_count);
        treatment_groups_free(snap->treatment_groups,
                              snap->treatment_group_count);
        policy_rules_free(snap->policy_rules, snap->policy_rule_count);
        snapshot_free_profiles(snap->profiles, snap->profile_count);
        cfg_free_owned(&snap->config);
        free(snap);
        return NULL;
      }
    }
  }
  snap->treatment_output_count = g_treatment_output_count;
  if (g_treatment_output_count > 0) {
    snap->treatment_outputs = (WambleTreatmentOutputSpec *)calloc(
        (size_t)g_treatment_output_count, sizeof(WambleTreatmentOutputSpec));
    if (!snap->treatment_outputs) {
      treatment_edges_free(snap->treatment_edges, snap->treatment_edge_count);
      treatment_rules_free(snap->treatment_rules, snap->treatment_rule_count);
      treatment_groups_free(snap->treatment_groups,
                            snap->treatment_group_count);
      policy_rules_free(snap->policy_rules, snap->policy_rule_count);
      snapshot_free_profiles(snap->profiles, snap->profile_count);
      cfg_free_owned(&snap->config);
      free(snap);
      return NULL;
    }
    for (int i = 0; i < g_treatment_output_count; i++) {
      if (treatment_output_dup(&snap->treatment_outputs[i],
                               &g_treatment_outputs[i]) != 0) {
        treatment_outputs_free(snap->treatment_outputs,
                               snap->treatment_output_count);
        treatment_edges_free(snap->treatment_edges, snap->treatment_edge_count);
        treatment_rules_free(snap->treatment_rules, snap->treatment_rule_count);
        treatment_groups_free(snap->treatment_groups,
                              snap->treatment_group_count);
        policy_rules_free(snap->policy_rules, snap->policy_rule_count);
        snapshot_free_profiles(snap->profiles, snap->profile_count);
        cfg_free_owned(&snap->config);
        free(snap);
        return NULL;
      }
    }
  }
  if (g_last_loaded_source) {
    snap->source_text = wamble_strdup(g_last_loaded_source);
    if (!snap->source_text) {
      treatment_outputs_free(snap->treatment_outputs,
                             snap->treatment_output_count);
      treatment_edges_free(snap->treatment_edges, snap->treatment_edge_count);
      treatment_rules_free(snap->treatment_rules, snap->treatment_rule_count);
      treatment_groups_free(snap->treatment_groups,
                            snap->treatment_group_count);
      policy_rules_free(snap->policy_rules, snap->policy_rule_count);
      snapshot_free_profiles(snap->profiles, snap->profile_count);
      cfg_free_owned(&snap->config);
      free(snap);
      return NULL;
    }
  }
  return snap;
}

static int
config_restore_snapshot_policy_and_treatments(const ConfigSnapshot *snap);

int config_restore_snapshot(const void *snapshot) {
  const ConfigSnapshot *snap = (const ConfigSnapshot *)snapshot;
  if (!snap)
    return -1;

  if (g_profiles) {
    free_profiles();
    g_config.db_host = NULL;
    g_config.db_user = NULL;
    g_config.db_pass = NULL;
    g_config.db_name = NULL;
    g_config.global_db_host = NULL;
    g_config.global_db_user = NULL;
    g_config.global_db_pass = NULL;
    g_config.global_db_name = NULL;
    g_config.spectator_summary_mode = NULL;
    g_config.prediction_match_policy = NULL;
    g_config.state_dir = NULL;
    g_config.websocket_path = NULL;
  } else {
    cfg_free_owned(&g_config);
  }
  policy_rules_free(g_policy_rules, g_policy_rule_count);
  g_policy_rules = NULL;
  g_policy_rule_count = 0;
  treatment_groups_free(g_treatment_groups, g_treatment_group_count);
  g_treatment_groups = NULL;
  g_treatment_group_count = 0;
  treatment_rules_free(g_treatment_rules, g_treatment_rule_count);
  g_treatment_rules = NULL;
  g_treatment_rule_count = 0;
  treatment_edges_free(g_treatment_edges, g_treatment_edge_count);
  g_treatment_edges = NULL;
  g_treatment_edge_count = 0;
  treatment_outputs_free(g_treatment_outputs, g_treatment_output_count);
  g_treatment_outputs = NULL;
  g_treatment_output_count = 0;

  if (cfg_dup_owned(&g_config, &snap->config) != 0)
    return -1;

  if (snap->profile_count <= 0 || !snap->profiles) {
    g_profiles = NULL;
    g_profile_count = 0;
    if (config_restore_snapshot_policy_and_treatments(snap) != 0)
      return -1;
    free(g_last_loaded_source);
    g_last_loaded_source =
        snap->source_text ? wamble_strdup(snap->source_text) : NULL;
    LispEnv *rebuilt = NULL;
    if (snap->source_text && snap->source_text[0]) {
      rebuilt = build_policy_env_from_source(snap->source_text);
      if (!rebuilt)
        return -1;
    }
    LispEnv *old_env = policy_env_swap(rebuilt);
    if (old_env)
      lisp_env_free(old_env);
    return 0;
  }
  g_profiles = (WambleProfile *)calloc((size_t)snap->profile_count,
                                       sizeof(WambleProfile));
  if (!g_profiles)
    return -1;
  g_profile_count = snap->profile_count;
  for (int i = 0; i < snap->profile_count; i++) {
    g_profiles[i] = snap->profiles[i];
    g_profiles[i].name =
        snap->profiles[i].name ? wamble_strdup(snap->profiles[i].name) : NULL;
    g_profiles[i].group =
        snap->profiles[i].group ? wamble_strdup(snap->profiles[i].group) : NULL;
    if (cfg_dup_owned(&g_profiles[i].config, &snap->profiles[i].config) != 0 ||
        !g_profiles[i].name) {
      free_profiles();
      return -1;
    }
  }
  if (config_restore_snapshot_policy_and_treatments(snap) != 0) {
    free_profiles();
    return -1;
  }
  free(g_last_loaded_source);
  g_last_loaded_source =
      snap->source_text ? wamble_strdup(snap->source_text) : NULL;

  LispEnv *rebuilt = NULL;
  if (snap->source_text && snap->source_text[0]) {
    rebuilt = build_policy_env_from_source(snap->source_text);
    if (!rebuilt)
      return -1;
  }
  LispEnv *old_env = policy_env_swap(rebuilt);
  if (old_env)
    lisp_env_free(old_env);
  return 0;
}

static int
config_restore_snapshot_policy_and_treatments(const ConfigSnapshot *snap) {
  if (!snap)
    return -1;
  if (snap->policy_rule_count > 0 && snap->policy_rules) {
    g_policy_rules = (WamblePolicyRuleSpec *)calloc(
        (size_t)snap->policy_rule_count, sizeof(WamblePolicyRuleSpec));
    if (!g_policy_rules)
      return -1;
    g_policy_rule_count = snap->policy_rule_count;
    for (int i = 0; i < snap->policy_rule_count; i++) {
      if (policy_rule_dup(&g_policy_rules[i], &snap->policy_rules[i]) != 0) {
        policy_rules_free(g_policy_rules, g_policy_rule_count);
        g_policy_rules = NULL;
        g_policy_rule_count = 0;
        return -1;
      }
    }
  }
  if (snap->treatment_group_count > 0 && snap->treatment_groups) {
    g_treatment_groups = (WambleTreatmentGroupSpec *)calloc(
        (size_t)snap->treatment_group_count, sizeof(WambleTreatmentGroupSpec));
    if (!g_treatment_groups)
      return -1;
    g_treatment_group_count = snap->treatment_group_count;
    for (int i = 0; i < snap->treatment_group_count; i++) {
      if (treatment_group_dup(&g_treatment_groups[i],
                              &snap->treatment_groups[i]) != 0) {
        treatment_groups_free(g_treatment_groups, g_treatment_group_count);
        g_treatment_groups = NULL;
        g_treatment_group_count = 0;
        return -1;
      }
    }
  }
  if (snap->treatment_rule_count > 0 && snap->treatment_rules) {
    g_treatment_rules = (WambleTreatmentRuleSpec *)calloc(
        (size_t)snap->treatment_rule_count, sizeof(WambleTreatmentRuleSpec));
    if (!g_treatment_rules)
      return -1;
    g_treatment_rule_count = snap->treatment_rule_count;
    for (int i = 0; i < snap->treatment_rule_count; i++) {
      if (treatment_rule_dup(&g_treatment_rules[i],
                             &snap->treatment_rules[i]) != 0) {
        treatment_rules_free(g_treatment_rules, g_treatment_rule_count);
        g_treatment_rules = NULL;
        g_treatment_rule_count = 0;
        return -1;
      }
    }
  }
  if (snap->treatment_edge_count > 0 && snap->treatment_edges) {
    g_treatment_edges = (WambleTreatmentEdgeSpec *)calloc(
        (size_t)snap->treatment_edge_count, sizeof(WambleTreatmentEdgeSpec));
    if (!g_treatment_edges)
      return -1;
    g_treatment_edge_count = snap->treatment_edge_count;
    for (int i = 0; i < snap->treatment_edge_count; i++) {
      if (treatment_edge_dup(&g_treatment_edges[i],
                             &snap->treatment_edges[i]) != 0) {
        treatment_edges_free(g_treatment_edges, g_treatment_edge_count);
        g_treatment_edges = NULL;
        g_treatment_edge_count = 0;
        return -1;
      }
    }
  }
  if (snap->treatment_output_count > 0 && snap->treatment_outputs) {
    g_treatment_outputs = (WambleTreatmentOutputSpec *)calloc(
        (size_t)snap->treatment_output_count,
        sizeof(WambleTreatmentOutputSpec));
    if (!g_treatment_outputs)
      return -1;
    g_treatment_output_count = snap->treatment_output_count;
    for (int i = 0; i < snap->treatment_output_count; i++) {
      if (treatment_output_dup(&g_treatment_outputs[i],
                               &snap->treatment_outputs[i]) != 0) {
        treatment_outputs_free(g_treatment_outputs, g_treatment_output_count);
        g_treatment_outputs = NULL;
        g_treatment_output_count = 0;
        return -1;
      }
    }
  }
  return 0;
}

void config_free_snapshot(void *snapshot) {
  ConfigSnapshot *snap = (ConfigSnapshot *)snapshot;
  if (!snap)
    return;
  cfg_free_owned(&snap->config);
  snapshot_free_profiles(snap->profiles, snap->profile_count);
  policy_rules_free(snap->policy_rules, snap->policy_rule_count);
  treatment_groups_free(snap->treatment_groups, snap->treatment_group_count);
  treatment_rules_free(snap->treatment_rules, snap->treatment_rule_count);
  treatment_edges_free(snap->treatment_edges, snap->treatment_edge_count);
  treatment_outputs_free(snap->treatment_outputs, snap->treatment_output_count);
  free(snap->source_text);
  free(snap);
}

const char *config_profile_group(const char *name) {
  const WambleProfile *p = config_find_profile(name);
  if (!p)
    return NULL;
  return p->group;
}

int config_policy_rule_count(void) { return g_policy_rule_count; }

const WamblePolicyRuleSpec *config_policy_rule_get(int index) {
  if (index < 0 || index >= g_policy_rule_count || !g_policy_rules)
    return NULL;
  return &g_policy_rules[index];
}

int config_treatment_group_count(void) { return g_treatment_group_count; }

const WambleTreatmentGroupSpec *config_treatment_group_get(int index) {
  if (index < 0 || index >= g_treatment_group_count || !g_treatment_groups)
    return NULL;
  return &g_treatment_groups[index];
}

int config_treatment_rule_count(void) { return g_treatment_rule_count; }

const WambleTreatmentRuleSpec *config_treatment_rule_get(int index) {
  if (index < 0 || index >= g_treatment_rule_count || !g_treatment_rules)
    return NULL;
  return &g_treatment_rules[index];
}

int config_treatment_edge_count(void) { return g_treatment_edge_count; }

const WambleTreatmentEdgeSpec *config_treatment_edge_get(int index) {
  if (index < 0 || index >= g_treatment_edge_count || !g_treatment_edges)
    return NULL;
  return &g_treatment_edges[index];
}

int config_treatment_output_count(void) { return g_treatment_output_count; }

const WambleTreatmentOutputSpec *config_treatment_output_get(int index) {
  if (index < 0 || index >= g_treatment_output_count || !g_treatment_outputs)
    return NULL;
  return &g_treatment_outputs[index];
}

int config_has_policy_eval(void) {
  if (!g_policy_env)
    return 0;
  LispValue sym = {.type = LISP_VALUE_SYMBOL,
                   .as.symbol = (char *)"policy-eval"};
  LispValue *v = lisp_env_get(g_policy_env, &sym);
  int has = (v && v->type == LISP_VALUE_FUNCTION) ? 1 : 0;
  free_lisp_value(v);
  return has;
}

static int parse_policy_eval_result(LispValue *res, WamblePolicyDecision *out) {
  if (!res || !out)
    return -1;
  out->allowed = 0;
  out->permission_level = 0;
  snprintf(out->reason, sizeof(out->reason), "%s", "dsl_default_deny");
  snprintf(out->policy_version, sizeof(out->policy_version), "%s", "dsl");
  snprintf(out->effect, sizeof(out->effect), "%s", "deny");

  if (res->type == LISP_VALUE_INTEGER) {
    if (res->as.integer >= 0) {
      out->allowed = 1;
      out->permission_level = (int)res->as.integer;
      snprintf(out->effect, sizeof(out->effect), "%s", "allow");
    }
    return 0;
  }
  if (res->type == LISP_VALUE_STRING) {
    if (strcmp(res->as.string ? res->as.string : "", "allow") == 0) {
      out->allowed = 1;
      out->permission_level = 1;
      snprintf(out->effect, sizeof(out->effect), "%s", "allow");
      return 0;
    }
    if (strcmp(res->as.string ? res->as.string : "", "deny") == 0) {
      return 0;
    }
    return -1;
  }
  if (res->type != LISP_VALUE_PAIR)
    return -1;

  LispValue *head = res->as.pair.car;
  const char *decision = NULL;
  if (head && head->type == LISP_VALUE_STRING)
    decision = head->as.string;
  else if (head && head->type == LISP_VALUE_SYMBOL)
    decision = head->as.symbol;
  if (!decision)
    return -1;

  LispValue *tail = res->as.pair.cdr;
  if (strcmp(decision, "allow") == 0) {
    out->allowed = 1;
    out->permission_level = 1;
    snprintf(out->effect, sizeof(out->effect), "%s", "allow");
    if (tail && tail->type == LISP_VALUE_PAIR && tail->as.pair.car &&
        tail->as.pair.car->type == LISP_VALUE_INTEGER) {
      out->permission_level = (int)tail->as.pair.car->as.integer;
      tail = tail->as.pair.cdr;
    }
  } else if (strcmp(decision, "deny") == 0) {
    out->allowed = 0;
    out->permission_level = 0;
    tail = (tail && tail->type == LISP_VALUE_PAIR) ? tail : NULL;
  } else {
    return -1;
  }

  if (tail && tail->type == LISP_VALUE_PAIR && tail->as.pair.car &&
      tail->as.pair.car->type == LISP_VALUE_STRING) {
    snprintf(out->reason, sizeof(out->reason), "%s",
             tail->as.pair.car->as.string);
    tail = tail->as.pair.cdr;
  }
  if (tail && tail->type == LISP_VALUE_PAIR && tail->as.pair.car &&
      tail->as.pair.car->type == LISP_VALUE_STRING) {
    snprintf(out->policy_version, sizeof(out->policy_version), "%s",
             tail->as.pair.car->as.string);
  }
  return 0;
}

int config_policy_eval(const char *identity_selector, const char *action,
                       const char *resource, const char *profile_name,
                       const char *profile_group, const char *context_key,
                       const char *context_value, int64_t now_epoch_seconds,
                       WamblePolicyDecision *out) {
  if (!out || !g_policy_env || !action || !resource)
    return 0;
  if (g_policy_eval_mutex_ready)
    wamble_mutex_lock(&g_policy_eval_mutex);

  LispValue sym = {.type = LISP_VALUE_SYMBOL,
                   .as.symbol = (char *)"policy-eval"};
  LispValue *fn = lisp_env_get(g_policy_env, &sym);
  if (!fn || fn->type != LISP_VALUE_FUNCTION) {
    free_lisp_value(fn);
    if (g_policy_eval_mutex_ready)
      wamble_mutex_unlock(&g_policy_eval_mutex);
    return 0;
  }
  free_lisp_value(fn);

  LispValue *expr = make_value(LISP_VALUE_PAIR);
  if (!expr) {
    if (g_policy_eval_mutex_ready)
      wamble_mutex_unlock(&g_policy_eval_mutex);
    return -1;
  }
  LispValue *callee = make_value(LISP_VALUE_SYMBOL);
  if (!callee) {
    free_lisp_value(expr);
    if (g_policy_eval_mutex_ready)
      wamble_mutex_unlock(&g_policy_eval_mutex);
    return -1;
  }
  callee->as.symbol = wamble_strdup("policy-eval");
  expr->as.pair.car = callee;

  LispValue *args = make_value(LISP_VALUE_NIL);
  LispValue *nowv = make_value(LISP_VALUE_INTEGER);
  nowv->as.integer = now_epoch_seconds;
  args = cons(nowv, args);
  const char *argv[] = {identity_selector ? identity_selector : "",
                        action,
                        resource,
                        profile_name ? profile_name : "",
                        profile_group ? profile_group : "",
                        context_key ? context_key : "",
                        context_value ? context_value : ""};
  for (int i = 6; i >= 0; i--) {
    LispValue *sv = make_string_value(argv[i]);
    if (!sv) {
      free_lisp_value(args);
      free_lisp_value(expr);
      if (g_policy_eval_mutex_ready)
        wamble_mutex_unlock(&g_policy_eval_mutex);
      return -1;
    }
    args = cons(sv, args);
  }
  expr->as.pair.cdr = args;

  LispValue *result = eval_expr(g_policy_env, expr);
  free_lisp_value(expr);
  int rc = parse_policy_eval_result(result, out);
  free_lisp_value(result);
  if (g_policy_eval_mutex_ready)
    wamble_mutex_unlock(&g_policy_eval_mutex);
  return (rc == 0) ? 1 : -1;
}
