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
  time_t last_summary_wall;
  double last_activity;
  int has_pending_notice;
  uint64_t pending_notice_board_id;
  char pending_notice[FEN_MAX_LENGTH];
  int capacity_bypass;
  int owner_port;
} SpectatorEntry;

static SpectatorEntry *spectators;
static int spectators_count;
static int spectators_capacity;
static wamble_mutex_t spectators_mutex;
static int rr_index = 0;

static WambleBoard **summary_cache = NULL;
static int summary_cache_count = 0;
static int summary_cache_capacity = 0;
static time_t summary_cache_built_wall = 0;

static int is_board_eligible(const WambleBoard *b);
static int cmp_boards(const void *a, const void *b);
static int spectator_current_port(void);
static int spectator_count_for_port_locked(int owner_port);
static int spectator_active_count_for_port_locked(int owner_port);

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
  snprintf(out_fen, out_fen_size, "%s", board->fen);
  if (!token)
    return;
  WambleFact facts[3];
  memset(facts, 0, sizeof(facts));
  int fact_count = wamble_collect_board_treatment_facts(board, facts, 3);
  WambleTreatmentAction actions[8];
  int action_count = 0;
  if (wamble_query_resolve_treatment_actions(
          token, wamble_runtime_profile_key(), "board.read",
          board->last_mover_treatment_group, facts, fact_count, actions, 8,
          &action_count) != DB_OK) {
    return;
  }
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
  if (spectator_count_for_port_locked(owner_port) >=
      get_config()->max_client_sessions) {
    return NULL;
  }
  if (spectators_count >= spectators_capacity) {
    int new_cap = spectators_capacity > 0 ? spectators_capacity * 2 : 16;
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
  e->last_summary_wall = 0;
  e->last_activity = monotonic_seconds();
  e->has_pending_notice = 0;
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

  spectators_capacity = get_config()->max_client_sessions;
  if (spectators_capacity <= 0) {
    wamble_mutex_unlock(&spectators_mutex);
    return SPECTATOR_INIT_ERR_NO_CAPACITY;
  }
  spectators = calloc((size_t)spectators_capacity, sizeof(SpectatorEntry));
  if (!spectators) {
    wamble_mutex_unlock(&spectators_mutex);
    return SPECTATOR_INIT_ERR_ALLOC;
  }

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
          e->pending_notice_board_id = e->focus_board_id;
          snprintf(e->pending_notice, sizeof(e->pending_notice),
                   "focus ended; switched to summary mode (board %" PRIu64 ")",
                   e->focus_board_id);
          wamble_runtime_event_publish(
              WAMBLE_RUNTIME_EVENT_PROFILE_ADMIN,
              PROFILE_ADMIN_STATUS_SPECTATOR_FOCUS_DISABLED_FALLBACK,
              wamble_runtime_profile_key());
        }
        e->state = SPECTATOR_STATE_SUMMARY;
        e->focus_board_id = 0;
        e->last_focus_sent = 0.0;
        e->capacity_bypass = 0;
        e->last_summary_wall = 0;
      } else {
        WambleBoard *b = get_board_by_id(e->focus_board_id);
        if (!b || !is_board_eligible(b)) {
          if (!e->has_pending_notice && e->focus_board_id) {
            e->has_pending_notice = 1;
            e->pending_notice_board_id = e->focus_board_id;
            snprintf(e->pending_notice, sizeof(e->pending_notice),
                     "focused game finished; switched to summary mode "
                     "(board %" PRIu64 ")",
                     e->focus_board_id);
            wamble_runtime_event_publish(
                WAMBLE_RUNTIME_EVENT_PROFILE_ADMIN,
                PROFILE_ADMIN_STATUS_SPECTATOR_BOARD_FINISHED_FALLBACK,
                wamble_runtime_profile_key());
          }
          e->state = SPECTATOR_STATE_SUMMARY;
          e->focus_board_id = 0;
          e->last_focus_sent = 0.0;
          e->capacity_bypass = 0;
          e->last_summary_wall = 0;
        }
      }
    }

    if (e->state == SPECTATOR_STATE_SUMMARY && cfg->spectator_summary_hz <= 0) {
      if (e->last_summary_sent == 0.0)
        e->last_summary_sent = now, e->last_summary_wall = wamble_now_wall();
    }
    if (e->state == SPECTATOR_STATE_FOCUS && cfg->spectator_focus_hz <= 0) {

      if (e->last_focus_sent == 0.0)
        e->last_focus_sent = now;
    }

    if (max_focus == 0 && e->state != SPECTATOR_STATE_IDLE &&
        !e->capacity_bypass) {
      if (!e->has_pending_notice) {
        e->has_pending_notice = 1;
        e->pending_notice_board_id = e->focus_board_id;
        snprintf(e->pending_notice, sizeof(e->pending_notice),
                 "spectating stopped; max-spectators is 0");
        wamble_runtime_event_publish(
            WAMBLE_RUNTIME_EVENT_PROFILE_ADMIN,
            PROFILE_ADMIN_STATUS_SPECTATOR_STOPPED_BY_ZERO_CAP,
            wamble_runtime_profile_key());
      }
      e->state = SPECTATOR_STATE_IDLE;
      e->focus_board_id = 0;
      e->last_focus_sent = 0.0;
      e->capacity_bypass = 0;
      e->last_summary_wall = 0;
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
    e->has_pending_notice = 0;
    e->pending_notice[0] = '\0';
    e->pending_notice_board_id = 0;
  }
  wamble_mutex_unlock(&spectators_mutex);
  return out_count;
}

SpectatorRequestStatus
spectator_handle_request(const struct WambleMsg *msg,
                         const struct sockaddr_in *cliaddr, int trust_tier,
                         int capacity_bypass, SpectatorState *out_state,
                         uint64_t *out_focus_board_id) {
  wamble_mutex_lock(&spectators_mutex);
  if (msg->ctrl == WAMBLE_CTRL_SPECTATE_STOP) {
    int owner_port = spectator_current_port();
    for (int i = 0; i < spectators_count; i++) {
      SpectatorEntry *e = &spectators[i];
      if (memcmp(e->token, msg->token, TOKEN_LENGTH) != 0 ||
          e->addr.sin_addr.s_addr != cliaddr->sin_addr.s_addr ||
          e->addr.sin_port != cliaddr->sin_port ||
          e->owner_port != owner_port) {
        continue;
      }
      e->state = SPECTATOR_STATE_IDLE;
      e->focus_board_id = 0;
      e->last_focus_sent = 0.0;
      e->capacity_bypass = 0;
      e->last_summary_wall = 0;
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
      e->last_summary_wall = 0;
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

static void fill_summary_now(SpectatorEntry *e, SpectatorUpdate *out,
                             int out_cap, int *out_count) {
  int use_changes = 0;
  if (get_config()->spectator_summary_mode &&
      strcmp(get_config()->spectator_summary_mode, "changes") == 0) {
    use_changes = 1;
  }

  time_t since = e->last_summary_wall;

  for (int i = 0; i < summary_cache_count; i++) {
    if (*out_count >= out_cap)
      break;
    SpectatorUpdate *u = &out[*out_count];
    memcpy(u->token, e->token, TOKEN_LENGTH);
    WambleBoard *b = summary_cache[i];
    if (use_changes) {
      if (since != 0 && b->last_move_time <= since)
        continue;
    }
    u->board_id = b->id;
    spectator_write_visible_fen(e->token, b, u->fen, sizeof(u->fen));
    u->addr = e->addr;
    (*out_count)++;
  }
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
  int scanned = 0;
  for (int step = 0; step < spectators_count; step++) {
    int i = (start + step) % (spectators_count > 0 ? spectators_count : 1);
    if (spectators_count <= 0)
      break;
    SpectatorEntry *e = &spectators[i];
    if (e->owner_port != port)
      continue;
    if (e->state == SPECTATOR_STATE_SUMMARY) {
      int due =
          (e->last_summary_sent == 0.0) ||
          (sum_interval > 0.0 && (now - e->last_summary_sent) >= sum_interval);
      if (due) {
        fill_summary_now(e, out, max, &out_count);
        e->last_summary_sent = now;
        e->last_summary_wall = wamble_now_wall();
      }
    } else if (e->state == SPECTATOR_STATE_FOCUS) {
      int due =
          (e->last_focus_sent == 0.0) ||
          (foc_interval > 0.0 && (now - e->last_focus_sent) >= foc_interval);
      if (due) {
        if (out_count < max) {
          WambleBoard *b = get_board_by_id(e->focus_board_id);
          if (b && is_board_eligible(b)) {
            SpectatorUpdate *u = &out[out_count];
            memcpy(u->token, e->token, TOKEN_LENGTH);
            u->board_id = b->id;
            spectator_write_visible_fen(e->token, b, u->fen, sizeof(u->fen));
            u->addr = e->addr;
            out_count++;
          }
        }
        e->last_focus_sent = now;
      }
    }
    scanned++;
    if (out_count >= max)
      break;
  }
  if (spectators_count > 0)
    rr_index = (start + scanned) % spectators_count;
  wamble_mutex_unlock(&spectators_mutex);
  return out_count;
}
