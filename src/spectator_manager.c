#include "../include/wamble/wamble.h"
#include <inttypes.h>
#include <string.h>

typedef struct SpectatorEntry {
  struct sockaddr_in addr;
  uint8_t token[TOKEN_LENGTH];
  int trust;
  SpectatorState state;
  uint64_t focus_board_id;
  double last_summary_sent;
  double last_focus_sent;
  double last_activity;
  int has_pending_notice;
  uint8_t pending_notice_flags;
  uint8_t pending_notice_type;
  uint64_t pending_notice_board_id;
  char pending_notice[FEN_MAX_LENGTH];
  int capacity_bypass;
  int game_mode_visible;
  int owner_port;
  unsigned int game_mode_filter;
} SpectatorEntry;

static SpectatorEntry *spectators;
static int spectators_count;
static int spectators_capacity;
static wamble_mutex_t spectators_mutex;
static int rr_index = 0;
static uint64_t summary_generation_counter = 0;

static WambleBoard **summary_cache = NULL;
static int summary_cache_count = 0;
static int summary_cache_capacity = 0;
static time_t summary_cache_built_wall = 0;

static int is_board_eligible(const WambleBoard *b);
static int cmp_boards(const void *a, const void *b);
static int spectator_current_port(void);
static int spectator_count_for_port_locked(int owner_port);
static int spectator_active_count_for_port_locked(int owner_port);
static int fill_focus_now(SpectatorEntry *e, SpectatorUpdate *out, int out_cap,
                          int *out_count);
static int fill_summary_now(SpectatorEntry *e, SpectatorUpdate *out,
                            int out_cap, int *out_count);

static int token_has_any_byte(const uint8_t *token) {
  if (!token)
    return 0;
  for (int i = 0; i < TOKEN_LENGTH; i++) {
    if (token[i] != 0)
      return 1;
  }
  return 0;
}

static void rebuild_summary_cache_locked(int max_to_scan) {
  if (max_to_scan <= 0) {
    summary_cache_count = 0;
    summary_cache_built_wall = wamble_now_wall();
    return;
  }
  if (summary_cache_capacity < max_to_scan) {
    WambleBoard **newbuf = (WambleBoard **)realloc(
        summary_cache, sizeof(WambleBoard *) * (size_t)max_to_scan);
    if (newbuf) {
      summary_cache = newbuf;
      summary_cache_capacity = max_to_scan;
    }
  }
  if (!summary_cache || summary_cache_capacity <= 0) {
    summary_cache_count = 0;
    summary_cache_built_wall = wamble_now_wall();
    return;
  }

  WambleBoard *exported =
      (WambleBoard *)calloc((size_t)max_to_scan, sizeof(*exported));
  if (!exported) {
    summary_cache_count = 0;
    summary_cache_built_wall = wamble_now_wall();
    return;
  }

  int exported_count = 0;
  if (board_manager_export(exported, max_to_scan, &exported_count, NULL) != 0) {
    free(exported);
    summary_cache_count = 0;
    summary_cache_built_wall = wamble_now_wall();
    return;
  }

  int count = 0;
  for (int i = 0; i < exported_count && count < summary_cache_capacity; i++) {
    WambleBoard *b = get_board_by_id(exported[i].id);
    if (!b || !is_board_eligible(b))
      continue;
    summary_cache[count++] = b;
  }
  free(exported);

  if (count > 1) {
    qsort(summary_cache, (size_t)count, sizeof(summary_cache[0]), cmp_boards);
  }
  summary_cache_count = count;
  summary_cache_built_wall = wamble_now_wall();
}

static double monotonic_seconds(void) {
  uint64_t ms = wamble_now_mono_millis();
  return (double)ms / 1000.0;
}

static int is_board_eligible(const WambleBoard *b) {
  if (!b)
    return 0;
  return (b->state == BOARD_STATE_ACTIVE || b->state == BOARD_STATE_RESERVED);
}

static void spectator_write_visible_fen(const uint8_t *token,
                                        const WambleBoard *board, char *out_fen,
                                        size_t out_fen_size) {
  if (!out_fen || out_fen_size == 0)
    return;
  out_fen[0] = '\0';
  if (!board)
    return;
  wamble_strip_fen_history(board->fen, out_fen, out_fen_size);
  if (!token)
    return;
  WambleFact facts[24];
  memset(facts, 0, sizeof(facts));
  int fact_count = wamble_collect_board_treatment_facts(board, facts, 24);
  if (token_has_any_byte(board->last_mover_token) && fact_count + 2 <= 24) {
    WamblePlayer prev;
    if (get_player_snapshot_by_token(board->last_mover_token, &prev) == 0) {
      snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
               "previous_player.rating");
      facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_DOUBLE;
      facts[fact_count].double_value = prev.rating;
      fact_count++;

      snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
               "previous_player.score");
      facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_DOUBLE;
      facts[fact_count].double_value = prev.score;
      fact_count++;
    }
  }
  WambleTreatmentAction actions[8];
  int action_count = 0;
  DbStatus treatment_status = wamble_query_resolve_treatment_actions(
      token, wamble_runtime_profile_key(), "board.read",
      board->last_mover_treatment_group, facts, fact_count, actions, 8,
      &action_count);
  if (treatment_status != DB_OK) {
    WambleRuntimeStatus runtime_status = {WAMBLE_RUNTIME_STATUS_TREATMENT_AUDIT,
                                          TREATMENT_AUDIT_STATUS_QUERY_FAILED};
    wamble_runtime_event_publish(runtime_status, wamble_runtime_profile_key(),
                                 NULL);
    return;
  }
  WambleRuntimeStatus runtime_status = {WAMBLE_RUNTIME_STATUS_TREATMENT_AUDIT,
                                        action_count > 0
                                            ? TREATMENT_AUDIT_STATUS_TREATED
                                            : TREATMENT_AUDIT_STATUS_UNTREATED};
  wamble_runtime_event_publish(runtime_status, wamble_runtime_profile_key(),
                               NULL);
  for (int i = 0; i < action_count; i++) {
    if (strcmp(actions[i].output_kind, "view") != 0 ||
        strcmp(actions[i].output_key, "board.fen") != 0 ||
        actions[i].value_type != WAMBLE_TREATMENT_VALUE_STRING ||
        !actions[i].string_value[0]) {
      continue;
    }
    snprintf(out_fen, out_fen_size, "%s", actions[i].string_value);
  }
}

static double board_attractiveness(const WambleBoard *b) {
  if (!b)
    return 0.0;
  double score = 1.0;

  GamePhase phase;
  int fullmove_number = b->board.fullmove_number;
  if (fullmove_number < GAME_PHASE_EARLY_THRESHOLD) {
    phase = GAME_PHASE_EARLY;
  } else if (fullmove_number < GAME_PHASE_MID_THRESHOLD) {
    phase = GAME_PHASE_MID;
  } else {
    phase = GAME_PHASE_END;
  }

  if (phase == GAME_PHASE_EARLY) {
    score *= get_config()->new_player_early_phase_mult;
  } else if (phase == GAME_PHASE_MID) {
    score *= get_config()->new_player_mid_phase_mult;
  } else {
    score *= get_config()->new_player_end_phase_mult;
  }

  time_t now = wamble_now_wall();
  double since_assign = (double)(now - b->last_assignment_time);
  if (since_assign < 0)
    since_assign = 0;
  score *= 1.0 / (since_assign + 1.0);
  return score;
}

static int cmp_boards(const void *a, const void *b) {
  const WambleBoard *ba = *(const WambleBoard *const *)a;
  const WambleBoard *bb = *(const WambleBoard *const *)b;
  if (!ba && !bb)
    return 0;
  if (!ba)
    return 1;
  if (!bb)
    return -1;

  if (ba->last_move_time != bb->last_move_time) {
    return (bb->last_move_time > ba->last_move_time) -
           (bb->last_move_time < ba->last_move_time);
  }

  double sa = board_attractiveness(ba);
  double sb = board_attractiveness(bb);
  if (sa == sb)
    return 0;
  return (sb > sa) - (sb < sa);
}

static int spectator_current_port(void) {
  return get_config() ? get_config()->port : 0;
}

static int spectator_count_for_port_locked(int owner_port) {
  int count = 0;
  for (int i = 0; i < spectators_count; i++) {
    if (spectators[i].owner_port == owner_port)
      count++;
  }
  return count;
}

static int spectator_active_count_for_port_locked(int owner_port) {
  int count = 0;
  for (int i = 0; i < spectators_count; i++) {
    if (spectators[i].owner_port != owner_port)
      continue;
    if (spectators[i].state != SPECTATOR_STATE_IDLE &&
        !spectators[i].capacity_bypass) {
      count++;
    }
  }
  return count;
}

static SpectatorEntry *ensure_spectator(const struct sockaddr_in *addr,
                                        const uint8_t *token, int trust) {
  int owner_port = spectator_current_port();
  SpectatorEntry *e = NULL;
  for (int i = 0; i < spectators_count; i++) {
    if (memcmp(spectators[i].token, token, TOKEN_LENGTH) == 0 &&
        spectators[i].addr.sin_addr.s_addr == addr->sin_addr.s_addr &&
        spectators[i].addr.sin_port == addr->sin_port &&
        spectators[i].owner_port == owner_port) {
      return &spectators[i];
    }
  }
  if (token_has_any_byte(token)) {
    for (int i = 0; i < spectators_count; i++) {
      if (memcmp(spectators[i].token, token, TOKEN_LENGTH) != 0 ||
          spectators[i].owner_port != owner_port) {
        continue;
      }
      spectators[i].addr = *addr;
      spectators[i].trust = trust;
      return &spectators[i];
    }
  }
  if (spectators_count >= spectators_capacity) {
    int new_cap = spectators_capacity > 0 ? spectators_capacity * 2 : 1;
    SpectatorEntry *new_entries = (SpectatorEntry *)realloc(
        spectators, (size_t)new_cap * sizeof(*spectators));
    if (!new_entries)
      return NULL;
    memset(new_entries + spectators_capacity, 0,
           (size_t)(new_cap - spectators_capacity) * sizeof(*new_entries));
    spectators = new_entries;
    spectators_capacity = new_cap;
  }
  e = &spectators[spectators_count++];
  memset(e, 0, sizeof(*e));
  e->addr = *addr;
  memcpy(e->token, token, TOKEN_LENGTH);
  e->trust = trust;
  e->state = SPECTATOR_STATE_IDLE;
  e->last_summary_sent = 0.0;
  e->last_focus_sent = 0.0;
  e->last_activity = monotonic_seconds();
  e->has_pending_notice = 0;
  e->pending_notice_flags = 0;
  e->pending_notice_type = WAMBLE_NOTIFICATION_TYPE_GENERIC;
  e->pending_notice_board_id = 0;
  e->pending_notice[0] = '\0';
  e->capacity_bypass = 0;
  e->owner_port = owner_port;
  return e;
}

SpectatorInitStatus spectator_manager_init(void) {
  wamble_mutex_init(&spectators_mutex);
  wamble_mutex_lock(&spectators_mutex);
  if (spectators) {
    free(spectators);
    spectators = NULL;
  }
  spectators_count = 0;

  spectators_capacity = 0;

  if (summary_cache) {
    free(summary_cache);
    summary_cache = NULL;
  }
  summary_cache_capacity = 0;
  summary_cache_count = 0;
  summary_cache_built_wall = 0;
  int cap = get_config()->max_boards;
  if (cap < 0)
    cap = 0;
  if (cap > 0) {
    summary_cache = (WambleBoard **)calloc((size_t)cap, sizeof(WambleBoard *));
    if (summary_cache) {
      summary_cache_capacity = cap;
    }
  }
  wamble_mutex_unlock(&spectators_mutex);
  return SPECTATOR_INIT_OK;
}

void spectator_manager_shutdown(void) {
  wamble_mutex_lock(&spectators_mutex);
  if (spectators) {
    free(spectators);
    spectators = NULL;
  }
  if (summary_cache) {
    free(summary_cache);
    summary_cache = NULL;
  }
  spectators_count = 0;
  spectators_capacity = 0;
  wamble_mutex_unlock(&spectators_mutex);
  wamble_mutex_destroy(&spectators_mutex);
}

void spectator_manager_tick(void) {
  const WambleConfig *cfg = get_config();
  if (!cfg || !spectators || spectators_count <= 0)
    return;

  wamble_mutex_lock(&spectators_mutex);

  int max_to_scan = cfg->max_boards;
  if (max_to_scan <= 0)
    max_to_scan = 0;
  rebuild_summary_cache_locked(max_to_scan);
  double now = monotonic_seconds();
  int max_focus = cfg->max_spectators;
  double inactivity =
      (cfg->session_timeout > 0) ? (double)cfg->session_timeout : 300.0;
  int port = spectator_current_port();

  int write_idx = 0;
  for (int read_idx = 0; read_idx < spectators_count; read_idx++) {
    SpectatorEntry *e = &spectators[read_idx];

    if (e->owner_port != port) {
      if (write_idx != read_idx)
        spectators[write_idx] = *e;
      write_idx++;
      continue;
    }

    if (e->trust < cfg->spectator_visibility) {
      continue;
    }

    double last = e->last_activity;
    if (last <= 0.0)
      last = (e->last_focus_sent > e->last_summary_sent) ? e->last_focus_sent
                                                         : e->last_summary_sent;
    if (last > 0.0 && (now - last) > inactivity) {
      continue;
    }

    if (e->state == SPECTATOR_STATE_FOCUS) {
      if (cfg->spectator_max_focus_per_session <= 0) {
        if (!e->has_pending_notice && e->focus_board_id) {
          e->has_pending_notice = 1;
          e->pending_notice_flags =
              WAMBLE_FLAG_SPECTATE_NOTICE_SUMMARY_FALLBACK;
          e->pending_notice_type = WAMBLE_NOTIFICATION_TYPE_SPECTATE_ENDED;
          e->pending_notice_board_id = e->focus_board_id;
          snprintf(e->pending_notice, sizeof(e->pending_notice),
                   "focus ended; switched to summary mode (board %" PRIu64 ")",
                   e->focus_board_id);
          WambleRuntimeStatus runtime_status = {
              WAMBLE_RUNTIME_STATUS_PROFILE_ADMIN,
              PROFILE_ADMIN_STATUS_SPECTATOR_FOCUS_DISABLED_FALLBACK};
          wamble_runtime_event_publish(runtime_status,
                                       wamble_runtime_profile_key(), NULL);
        }
        e->state = SPECTATOR_STATE_SUMMARY;
        e->focus_board_id = 0;
        e->last_focus_sent = 0.0;
        e->capacity_bypass = 0;
      } else {
        WambleBoard *b = get_board_by_id(e->focus_board_id);
        if (!b || !is_board_eligible(b)) {
          if (!e->has_pending_notice && e->focus_board_id) {
            e->has_pending_notice = 1;
            e->pending_notice_flags =
                WAMBLE_FLAG_SPECTATE_NOTICE_SUMMARY_FALLBACK;
            e->pending_notice_type = WAMBLE_NOTIFICATION_TYPE_SPECTATE_ENDED;
            e->pending_notice_board_id = e->focus_board_id;
            snprintf(e->pending_notice, sizeof(e->pending_notice),
                     "focused game finished; switched to summary mode "
                     "(board %" PRIu64 ")",
                     e->focus_board_id);
            WambleRuntimeStatus runtime_status = {
                WAMBLE_RUNTIME_STATUS_PROFILE_ADMIN,
                PROFILE_ADMIN_STATUS_SPECTATOR_BOARD_FINISHED_FALLBACK};
            wamble_runtime_event_publish(runtime_status,
                                         wamble_runtime_profile_key(), NULL);
          }
          e->state = SPECTATOR_STATE_SUMMARY;
          e->focus_board_id = 0;
          e->last_focus_sent = 0.0;
          e->capacity_bypass = 0;
        }
      }
    }

    if (e->state == SPECTATOR_STATE_SUMMARY && cfg->spectator_summary_hz <= 0) {
      if (e->last_summary_sent == 0.0)
        e->last_summary_sent = now;
    }
    if (e->state == SPECTATOR_STATE_FOCUS && cfg->spectator_focus_hz <= 0) {

      if (e->last_focus_sent == 0.0)
        e->last_focus_sent = now;
    }

    if (max_focus == 0 && e->state != SPECTATOR_STATE_IDLE &&
        !e->capacity_bypass) {
      e->has_pending_notice = 1;
      e->pending_notice_flags = WAMBLE_FLAG_SPECTATE_NOTICE_STOPPED;
      e->pending_notice_type = WAMBLE_NOTIFICATION_TYPE_SPECTATE_ENDED;
      e->pending_notice_board_id = e->focus_board_id;
      snprintf(e->pending_notice, sizeof(e->pending_notice),
               "spectating stopped; max-spectators is 0");
      WambleRuntimeStatus runtime_status = {
          WAMBLE_RUNTIME_STATUS_PROFILE_ADMIN,
          PROFILE_ADMIN_STATUS_SPECTATOR_STOPPED_BY_ZERO_CAP};
      wamble_runtime_event_publish(runtime_status, wamble_runtime_profile_key(),
                                   NULL);
      e->state = SPECTATOR_STATE_IDLE;
      e->focus_board_id = 0;
      e->last_focus_sent = 0.0;
      e->capacity_bypass = 0;
    }

    if (write_idx != read_idx) {
      spectators[write_idx] = *e;
    }
    write_idx++;
  }

  if (write_idx != spectators_count) {
    spectators_count = write_idx;
  }
  wamble_mutex_unlock(&spectators_mutex);
}

int spectator_manager_active_count_for_port(int owner_port) {
  if (!spectators)
    return 0;
  wamble_mutex_lock(&spectators_mutex);
  int n = spectator_active_count_for_port_locked(owner_port);
  wamble_mutex_unlock(&spectators_mutex);
  return n;
}

int spectator_collect_notifications(struct SpectatorUpdate *out, int max) {
  if (!out || max <= 0 || !spectators || spectators_count <= 0)
    return 0;
  wamble_mutex_lock(&spectators_mutex);
  int out_count = 0;
  int port = get_config() ? get_config()->port : 0;
  for (int i = 0; i < spectators_count && out_count < max; i++) {
    SpectatorEntry *e = &spectators[i];
    if (!e->has_pending_notice || e->owner_port != port)
      continue;
    SpectatorUpdate *u = &out[out_count++];
    memcpy(u->token, e->token, TOKEN_LENGTH);
    u->board_id = e->pending_notice_board_id;
    strncpy(u->fen, e->pending_notice, FEN_MAX_LENGTH);
    u->fen[FEN_MAX_LENGTH - 1] = '\0';
    u->addr = e->addr;
    u->flags = e->pending_notice_flags;
    u->notification_type = e->pending_notice_type;
    u->summary_generation = 0;
    e->has_pending_notice = 0;
    e->pending_notice_flags = 0;
    e->pending_notice_type = WAMBLE_NOTIFICATION_TYPE_GENERIC;
    e->pending_notice[0] = '\0';
    e->pending_notice_board_id = 0;
  }
  wamble_mutex_unlock(&spectators_mutex);
  return out_count;
}

SpectatorRequestStatus spectator_handle_request(
    const struct WambleMsg *msg, const struct sockaddr_in *cliaddr,
    int trust_tier, int capacity_bypass, int game_mode_visible,
    SpectatorState *out_state, uint64_t *out_focus_board_id) {
  wamble_mutex_lock(&spectators_mutex);
  if (msg->ctrl == WAMBLE_CTRL_SPECTATE_STOP) {
    int owner_port = spectator_current_port();
    for (int i = 0; i < spectators_count; i++) {
      SpectatorEntry *e = &spectators[i];
      if (memcmp(e->token, msg->token, TOKEN_LENGTH) != 0 ||
          e->owner_port != owner_port) {
        continue;
      }
      if (!token_has_any_byte(msg->token) &&
          (e->addr.sin_addr.s_addr != cliaddr->sin_addr.s_addr ||
           e->addr.sin_port != cliaddr->sin_port)) {
        continue;
      }
      e->addr = *cliaddr;
      e->trust = trust_tier;
      e->state = SPECTATOR_STATE_IDLE;
      e->focus_board_id = 0;
      e->last_focus_sent = 0.0;
      e->last_summary_sent = 0.0;
      e->last_activity = monotonic_seconds();
      e->has_pending_notice = 0;
      e->pending_notice_flags = 0;
      e->pending_notice_type = WAMBLE_NOTIFICATION_TYPE_GENERIC;
      e->pending_notice_board_id = 0;
      e->pending_notice[0] = '\0';
      e->capacity_bypass = 0;
      e->game_mode_visible = 0;
      break;
    }
    if (out_state)
      *out_state = SPECTATOR_STATE_IDLE;
    if (out_focus_board_id)
      *out_focus_board_id = 0;
    wamble_mutex_unlock(&spectators_mutex);
    return SPECTATOR_OK_STOP;
  }

  if (trust_tier < get_config()->spectator_visibility) {
    wamble_mutex_unlock(&spectators_mutex);
    return SPECTATOR_ERR_VISIBILITY;
  }

  SpectatorEntry *e = ensure_spectator(cliaddr, msg->token, trust_tier);
  if (!e) {
    wamble_mutex_unlock(&spectators_mutex);
    return SPECTATOR_ERR_BUSY;
  }
  e->last_activity = monotonic_seconds();

  if (msg->ctrl == WAMBLE_CTRL_SPECTATE_GAME) {
    e->game_mode_visible = game_mode_visible ? 1 : 0;
    int cap = get_config()->max_spectators;
    int active_non_bypass =
        (cap >= 0) ? spectator_active_count_for_port_locked(e->owner_port) : 0;
    int current_contrib =
        (e->state != SPECTATOR_STATE_IDLE && !e->capacity_bypass) ? 1 : 0;
    int desired_contrib = (msg->board_id == 0 || !capacity_bypass) ? 1 : 0;
    int projected_non_bypass =
        active_non_bypass - current_contrib + desired_contrib;
    if (cap >= 0 && projected_non_bypass > cap) {
      wamble_mutex_unlock(&spectators_mutex);
      return SPECTATOR_ERR_FULL;
    }

    if (msg->board_id == 0) {
      e->state = SPECTATOR_STATE_SUMMARY;
      e->focus_board_id = 0;
      e->last_summary_sent = 0.0;
      e->capacity_bypass = 0;
      e->game_mode_filter = 0;
      if (e->game_mode_visible) {
        if (msg->flags & WAMBLE_FLAG_MODE_FILTER_CHESS960)
          e->game_mode_filter |= (1u << GAME_MODE_CHESS960);
        if (msg->flags & WAMBLE_FLAG_MODE_FILTER_STANDARD)
          e->game_mode_filter |= (1u << GAME_MODE_STANDARD);
      }
      if (out_state)
        *out_state = e->state;
      if (out_focus_board_id)
        *out_focus_board_id = 0;
      wamble_mutex_unlock(&spectators_mutex);
      return SPECTATOR_OK_SUMMARY;
    } else {
      if (get_config()->spectator_max_focus_per_session <= 0) {
        wamble_mutex_unlock(&spectators_mutex);
        return SPECTATOR_ERR_FOCUS_DISABLED;
      }

      WambleBoard *target = get_board_by_id(msg->board_id);
      if (!target || !is_board_eligible(target)) {
        wamble_mutex_unlock(&spectators_mutex);
        return SPECTATOR_ERR_NOT_AVAILABLE;
      }
      e->state = SPECTATOR_STATE_FOCUS;
      e->focus_board_id = msg->board_id;
      e->last_focus_sent = 0.0;
      e->capacity_bypass = capacity_bypass ? 1 : 0;
      if (out_state)
        *out_state = e->state;
      if (out_focus_board_id)
        *out_focus_board_id = e->focus_board_id;
      wamble_mutex_unlock(&spectators_mutex);
      return SPECTATOR_OK_FOCUS;
    }
  }

  if (out_state)
    *out_state = e->state;
  if (out_focus_board_id)
    *out_focus_board_id = e->focus_board_id;
  SpectatorRequestStatus rc =
      (e->state == SPECTATOR_STATE_FOCUS)
          ? SPECTATOR_OK_FOCUS
          : (e->state == SPECTATOR_STATE_SUMMARY ? SPECTATOR_OK_SUMMARY
                                                 : SPECTATOR_OK_STOP);
  wamble_mutex_unlock(&spectators_mutex);
  return rc;
}

int spectator_get_state_by_token(const uint8_t *token,
                                 SpectatorState *out_state,
                                 uint64_t *out_focus_board_id) {
  int owner_port = 0;
  if (!token || !out_state || !out_focus_board_id)
    return -1;
  owner_port = spectator_current_port();
  wamble_mutex_lock(&spectators_mutex);
  for (int i = 0; i < spectators_count; i++) {
    SpectatorEntry *e = &spectators[i];
    if (memcmp(e->token, token, TOKEN_LENGTH) != 0 ||
        e->owner_port != owner_port) {
      continue;
    }
    *out_state = e->state;
    *out_focus_board_id = e->focus_board_id;
    wamble_mutex_unlock(&spectators_mutex);
    return 0;
  }
  wamble_mutex_unlock(&spectators_mutex);
  return -1;
}

int spectator_collect_state_snapshot(const uint8_t *token, SpectatorUpdate *out,
                                     int max) {
  if (!token || !out || max <= 0)
    return 0;
  const WambleConfig *cfg = get_config();
  if (!cfg)
    return 0;

  wamble_mutex_lock(&spectators_mutex);
  if (summary_cache_built_wall == 0) {
    rebuild_summary_cache_locked(cfg->max_boards);
  }

  int port = spectator_current_port();
  double now = monotonic_seconds();
  int out_count = 0;
  for (int i = 0; i < spectators_count; i++) {
    SpectatorEntry *e = &spectators[i];
    if (e->owner_port != port || memcmp(e->token, token, TOKEN_LENGTH) != 0) {
      continue;
    }
    if (e->state == SPECTATOR_STATE_SUMMARY) {
      if (fill_summary_now(e, out, max, &out_count) >= 0)
        e->last_summary_sent = now;
    } else if (e->state == SPECTATOR_STATE_FOCUS) {
      if (fill_focus_now(e, out, max, &out_count) >= 0)
        e->last_focus_sent = now;
    }
    break;
  }
  wamble_mutex_unlock(&spectators_mutex);
  return out_count;
}

static int fill_focus_now(SpectatorEntry *e, SpectatorUpdate *out, int out_cap,
                          int *out_count) {
  if (!e || !out || !out_count)
    return 0;
  if (*out_count >= out_cap)
    return -1;
  WambleBoard *b = get_board_by_id(e->focus_board_id);
  if (!b || !is_board_eligible(b))
    return 0;

  SpectatorUpdate *u = &out[*out_count];
  memset(u, 0, sizeof(*u));
  memcpy(u->token, e->token, TOKEN_LENGTH);
  u->board_id = b->id;
  spectator_write_visible_fen(e->token, b, u->fen, sizeof(u->fen));
  u->addr = e->addr;
  u->flags = WAMBLE_FLAG_UNRELIABLE;
  if (e->game_mode_visible && b->board.game_mode == GAME_MODE_CHESS960)
    u->flags |= WAMBLE_FLAG_BOARD_IS_960;
  (*out_count)++;
  return 1;
}

void spectator_discard_by_token(const uint8_t *token) {
  if (!token || !spectators)
    return;
  int owner_port = spectator_current_port();
  wamble_mutex_lock(&spectators_mutex);
  int write_idx = 0;
  for (int read_idx = 0; read_idx < spectators_count; read_idx++) {
    if (memcmp(spectators[read_idx].token, token, TOKEN_LENGTH) == 0 &&
        spectators[read_idx].owner_port == owner_port)
      continue;
    if (write_idx != read_idx)
      spectators[write_idx] = spectators[read_idx];
    write_idx++;
  }
  spectators_count = write_idx;
  wamble_mutex_unlock(&spectators_mutex);
}

static int fill_summary_now(SpectatorEntry *e, SpectatorUpdate *out,
                            int out_cap, int *out_count) {
  if (!e || !out || !out_count || out_cap <= 0)
    return -1;
  int needed = 1;
  for (int i = 0; i < summary_cache_count; i++) {
    WambleBoard *b = summary_cache[i];
    GameMode board_game_mode = b->board.game_mode;
    if (e->game_mode_filter != 0 &&
        !(e->game_mode_filter & (1u << board_game_mode)))
      continue;
    needed++;
  }
  if (out_cap - *out_count < needed)
    return -1;

  uint64_t generation = ++summary_generation_counter;
  SpectatorUpdate *reset = &out[*out_count];
  memset(reset, 0, sizeof(*reset));
  memcpy(reset->token, e->token, TOKEN_LENGTH);
  reset->addr = e->addr;
  reset->flags = WAMBLE_FLAG_UNRELIABLE;
  reset->summary_generation = generation;
  (*out_count)++;

  for (int i = 0; i < summary_cache_count; i++) {
    WambleBoard *b = summary_cache[i];
    GameMode board_game_mode = b->board.game_mode;
    if (e->game_mode_filter != 0 &&
        !(e->game_mode_filter & (1u << board_game_mode)))
      continue;
    SpectatorUpdate *u = &out[*out_count];
    memset(u, 0, sizeof(*u));
    memcpy(u->token, e->token, TOKEN_LENGTH);
    u->board_id = b->id;
    spectator_write_visible_fen(e->token, b, u->fen, sizeof(u->fen));
    u->addr = e->addr;
    u->flags = WAMBLE_FLAG_UNRELIABLE;
    u->summary_generation = generation;
    if (e->game_mode_visible && board_game_mode == GAME_MODE_CHESS960)
      u->flags |= WAMBLE_FLAG_BOARD_IS_960;
    (*out_count)++;
  }
  return 1;
}

int spectator_collect_updates(struct SpectatorUpdate *out, int max) {
  if (!out || max <= 0)
    return 0;
  const WambleConfig *cfg = get_config();
  double now = monotonic_seconds();
  double sum_interval = 0.0;
  double foc_interval = 0.0;
  if (cfg->spectator_summary_hz > 0)
    sum_interval = 1.0 / (double)cfg->spectator_summary_hz;
  if (cfg->spectator_focus_hz > 0)
    foc_interval = 1.0 / (double)cfg->spectator_focus_hz;

  wamble_mutex_lock(&spectators_mutex);
  if (summary_cache_built_wall == 0) {
    rebuild_summary_cache_locked(cfg->max_boards);
  }
  int out_count = 0;
  int port = cfg ? cfg->port : 0;
  int start = rr_index;
  int served_steps = 0;
  for (int step = 0; step < spectators_count; step++) {
    int i = (start + step) % (spectators_count > 0 ? spectators_count : 1);
    if (spectators_count <= 0)
      break;
    SpectatorEntry *e = &spectators[i];
    if (e->owner_port != port) {
      served_steps = step + 1;
      continue;
    }
    int retry = 0;
    if (e->state == SPECTATOR_STATE_SUMMARY) {
      int due =
          (e->last_summary_sent == 0.0) ||
          (sum_interval > 0.0 && (now - e->last_summary_sent) >= sum_interval);
      if (due) {
        if (fill_summary_now(e, out, max, &out_count) >= 0)
          e->last_summary_sent = now;
        else
          retry = 1;
      }
    } else if (e->state == SPECTATOR_STATE_FOCUS) {
      int due =
          (e->last_focus_sent == 0.0) ||
          (foc_interval > 0.0 && (now - e->last_focus_sent) >= foc_interval);
      if (due) {
        if (fill_focus_now(e, out, max, &out_count) >= 0)
          e->last_focus_sent = now;
        else
          retry = 1;
      }
    }
    if (retry)
      break;
    served_steps = step + 1;
    if (out_count >= max)
      break;
  }
  if (spectators_count > 0)
    rr_index = (start + served_steps) % spectators_count;
  wamble_mutex_unlock(&spectators_mutex);
  return out_count;
}
