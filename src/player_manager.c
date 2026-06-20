#include "../include/wamble/wamble.h"
#include <string.h>
#if defined(__linux__)
#include <sys/random.h>
#endif

void wamble_emit_update_session_last_seen(const uint8_t *token);
void wamble_emit_create_session(const uint8_t *token, uint64_t player_id);
void wamble_emit_link_session_to_pubkey(const uint8_t *token,
                                        const uint8_t *public_key);
void wamble_emit_unlink_session_identity(const uint8_t *token);
void profile_runtime_manager_event_signal(void);

static WAMBLE_THREAD_LOCAL WamblePlayer *player_pool;
static WAMBLE_THREAD_LOCAL int num_players = 0;
static WAMBLE_THREAD_LOCAL wamble_mutex_t player_mutex;
static WAMBLE_THREAD_LOCAL int player_manager_mutex_held_depth = 0;

static int player_manager_mutex_lock(void) {
  int rc = wamble_mutex_lock(&player_mutex);
  if (rc == 0)
    player_manager_mutex_held_depth++;
  return rc;
}

static int player_manager_mutex_unlock(void) {
  if (player_manager_mutex_held_depth > 0)
    player_manager_mutex_held_depth--;
  return wamble_mutex_unlock(&player_mutex);
}

int wamble_architecture_player_lock_held(void) {
  return player_manager_mutex_held_depth > 0;
}

static WAMBLE_THREAD_LOCAL wamble_mutex_t rng_mutex;
static WAMBLE_THREAD_LOCAL int rng_initialized = 0;
static WAMBLE_THREAD_LOCAL uint64_t pcg_state = 0x853c49e6748fea9bULL;
static WAMBLE_THREAD_LOCAL uint64_t pcg_inc = 0xda3e39cb94b95bdbULL;

#define WAMBLE_LAST_SEEN_PERSIST_INTERVAL_SECONDS 60

static int should_persist_last_seen(time_t previous_seen, time_t now) {
  return previous_seen <= 0 ||
         (now - previous_seen) >= WAMBLE_LAST_SEEN_PERSIST_INTERVAL_SECONDS;
}

static inline uint32_t pcg32_random_r(void) {
  uint64_t oldstate = pcg_state;
  pcg_state = oldstate * 6364136223846793005ULL + (pcg_inc | 1ULL);
  uint32_t xorshifted = (uint32_t)(((oldstate >> 18u) ^ oldstate) >> 27u);
  uint32_t rot = (uint32_t)(oldstate >> 59u);
  return (xorshifted >> rot) | (xorshifted << ((-rot) & 31));
}

static uint64_t mix64(uint64_t x) {
  x ^= x >> 33;
  x *= 0xff51afd7ed558ccdULL;
  x ^= x >> 33;
  x *= 0xc4ceb9fe1a85ec53ULL;
  x ^= x >> 33;
  return x;
}

void rng_init(void) {
  wamble_mutex_lock(&rng_mutex);
  if (rng_initialized) {
    wamble_mutex_unlock(&rng_mutex);
    return;
  }

  uint64_t seed1 = (uint64_t)wamble_now_wall();
  uint64_t seed2 = (uint64_t)clock();
  uint64_t seed3 = (uint64_t)wamble_getpid();
  uint64_t seed4 = (uint64_t)(uintptr_t)&seed1;
  uint64_t entropy = mix64(seed1) ^ mix64(seed2) ^ mix64(seed3) ^ mix64(seed4);

  {
    uint64_t ur = 0;
    int have_os_entropy = 0;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||      \
    defined(__NetBSD__)
    arc4random_buf(&ur, sizeof ur);
    have_os_entropy = 1;
#elif defined(_WIN32)
    if (BCryptGenRandom(NULL, (PUCHAR)&ur, (ULONG)sizeof ur,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0) {
      have_os_entropy = 1;
    }
#elif defined(__linux__)
    ssize_t r = getrandom(&ur, sizeof ur, 0);
    if (r == (ssize_t)sizeof ur) {
      have_os_entropy = 1;
    }
#endif
    if (have_os_entropy) {
      entropy ^= ur;
    } else {
    }
  }

  pcg_state ^= mix64(entropy);
  pcg_inc ^= mix64(entropy << 1);
  (void)pcg32_random_r();

  rng_initialized = 1;
  wamble_mutex_unlock(&rng_mutex);
}

static uint64_t rng_u64(void) {
  wamble_mutex_lock(&rng_mutex);
  uint64_t hi = (uint64_t)pcg32_random_r();
  uint64_t lo = (uint64_t)pcg32_random_r();
  wamble_mutex_unlock(&rng_mutex);
  return (hi << 32) | lo;
}

double rng_double(void) {
  uint64_t r = rng_u64();
  r >>= 11;
  return (double)r * (1.0 / 9007199254740992.0);
}

void rng_bytes(uint8_t *out, size_t len) {
  if (!out || len == 0)
    return;
  size_t i = 0;
  while (i < len) {
    uint64_t r = rng_u64();
    for (int b = 0; b < 8 && i < len; b++, i++) {
      out[i] = (uint8_t)(r & 0xFF);
      r >>= 8;
    }
  }
}

#define PLAYER_MAP_SIZE (get_config()->max_players * 2)
static WAMBLE_THREAD_LOCAL int *player_index_map;
static WAMBLE_THREAD_LOCAL int player_manager_ready_flag = 0;

#define EXPIRED_SESSION_NOTIFICATION_MIN_CAP 32
static WAMBLE_THREAD_LOCAL ExpiredSessionNotification
    *expired_session_notifications;
static WAMBLE_THREAD_LOCAL int expired_session_notification_cap = 0;
static WAMBLE_THREAD_LOCAL int expired_session_notification_head = 0;
static WAMBLE_THREAD_LOCAL int expired_session_notification_count = 0;

static int ensure_expired_session_notification_capacity(int need) {
  if (need <= expired_session_notification_cap)
    return 0;
  int new_cap = expired_session_notification_cap > 0
                    ? expired_session_notification_cap
                    : EXPIRED_SESSION_NOTIFICATION_MIN_CAP;
  while (new_cap < need)
    new_cap *= 2;
  ExpiredSessionNotification *next =
      (ExpiredSessionNotification *)calloc((size_t)new_cap, sizeof(*next));
  if (!next)
    return -1;
  for (int i = 0; i < expired_session_notification_count; i++) {
    int src = (expired_session_notification_head + i) %
              expired_session_notification_cap;
    next[i] = expired_session_notifications[src];
  }
  free(expired_session_notifications);
  expired_session_notifications = next;
  expired_session_notification_cap = new_cap;
  expired_session_notification_head = 0;
  return 0;
}

static void
queue_expired_session_notification_locked(const uint8_t token[TOKEN_LENGTH]) {
  if (!token)
    return;
  if (ensure_expired_session_notification_capacity(
          expired_session_notification_count + 1) != 0) {
    return;
  }
  int slot =
      (expired_session_notification_head + expired_session_notification_count) %
      expired_session_notification_cap;
  memcpy(expired_session_notifications[slot].token, token, TOKEN_LENGTH);
  expired_session_notification_count++;
  profile_runtime_manager_event_signal();
}

int player_collect_expired_session_notifications(
    ExpiredSessionNotification *out, int max) {
  if (!out || max <= 0 || !player_manager_ready_flag)
    return 0;
  player_manager_mutex_lock();
  int n = expired_session_notification_count;
  if (n > max)
    n = max;
  for (int i = 0; i < n; i++) {
    int src = (expired_session_notification_head + i) %
              expired_session_notification_cap;
    out[i] = expired_session_notifications[src];
  }
  if (n > 0) {
    expired_session_notification_head =
        (expired_session_notification_head + n) %
        expired_session_notification_cap;
    expired_session_notification_count -= n;
  }
  player_manager_mutex_unlock();
  return n;
}

static void
apply_persistent_player_stats(WamblePlayer *player,
                              const WamblePersistentPlayerStats *stats);

static void hydrate_player_from_session(WamblePlayer *player,
                                        uint64_t session_id) {
  if (!player || session_id == 0)
    return;

  WamblePersistentPlayerStats stats = {0};
  if (wamble_query_get_session_player_stats(session_id, &stats) == DB_OK) {
    apply_persistent_player_stats(player, &stats);
    return;
  }
  player->score = 0.0;
  player->prediction_score = 0.0;
  player->rating = (double)get_config()->default_rating;
  player->games_played = 0;
  player->chess960_games_played = 0;
}

static void
apply_persistent_player_stats(WamblePlayer *player,
                              const WamblePersistentPlayerStats *stats) {
  if (!player || !stats)
    return;
  player->score = stats->score;
  player->prediction_score = stats->prediction_score;
  player->rating = (stats->rating > 0.0) ? stats->rating
                                         : (double)get_config()->default_rating;
  player->games_played = stats->games_played;
  player->chess960_games_played = stats->chess960_games_played;
}

static uint64_t token_hash(const uint8_t *token) {
  uint64_t h = 1469598103934665603ULL;
  if (!token)
    return h;
  for (int i = 0; i < TOKEN_LENGTH; i++) {
    h ^= token[i];
    h *= 1099511628211ULL;
  }
  h ^= h >> 33;
  h *= 0xff51afd7ed558ccdULL;
  h ^= h >> 33;
  h *= 0xc4ceb9fe1a85ec53ULL;
  h ^= h >> 33;
  return h;
}

static int player_slot_is_empty(const WamblePlayer *player) {
  if (!player)
    return 1;
  for (int i = 0; i < TOKEN_LENGTH; i++) {
    if (player->token[i] != 0)
      return 0;
  }
  return 1;
}

static int player_map_capacity(void) {
  int cap = PLAYER_MAP_SIZE;
  return cap > 0 ? cap : 0;
}

static int player_map_next(int idx, int cap) {
  idx++;
  if (idx >= cap)
    idx = 0;
  return idx;
}

static void player_map_put(const uint8_t *token, int index) {
  int cap = player_map_capacity();
  if (!player_index_map || !player_pool || !token || cap <= 0)
    return;
  uint64_t h = token_hash(token);
  int i = (int)(h % (uint64_t)cap);
  int first_tombstone = -1;
  for (int probe = 0; probe < cap; probe++) {
    int cur = player_index_map[i];
    if (cur == -1) {
      player_index_map[(first_tombstone >= 0) ? first_tombstone : i] = index;
      return;
    }
    if (cur == -2) {
      if (first_tombstone < 0)
        first_tombstone = i;
    } else if (tokens_equal(player_pool[cur].token, token)) {
      player_index_map[i] = index;
      return;
    }
    i = player_map_next(i, cap);
  }
}

static int player_map_get(const uint8_t *token) {
  int cap = player_map_capacity();
  if (!player_index_map || !player_pool || !token || cap <= 0)
    return -1;
  uint64_t h = token_hash(token);
  int i = (int)(h % (uint64_t)cap);
  for (int probe = 0; probe < cap; probe++) {
    int cur = player_index_map[i];
    if (cur == -1)
      return -1;
    if (cur >= 0 && tokens_equal(player_pool[cur].token, token))
      return cur;
    i = player_map_next(i, cap);
  }
  return -1;
}

static void player_map_delete(const uint8_t *token) {
  int cap = player_map_capacity();
  if (!player_index_map || !player_pool || !token || cap <= 0)
    return;
  uint64_t h = token_hash(token);
  int i = (int)(h % (uint64_t)cap);
  for (int probe = 0; probe < cap; probe++) {
    int cur = player_index_map[i];
    if (cur == -1)
      return;
    if (cur >= 0 && tokens_equal(player_pool[cur].token, token)) {
      player_index_map[i] = -2;
      return;
    }
    i = player_map_next(i, cap);
  }
}

static WamblePlayer *find_empty_player_slot(void) {
  for (int i = 0; i < get_config()->max_players; i++) {
    if (player_slot_is_empty(&player_pool[i])) {
      if (i >= num_players) {
        num_players = i + 1;
      }
      return &player_pool[i];
    }
  }
  return NULL;
}

void player_manager_init(void) {
  player_manager_ready_flag = 0;
  if (player_pool) {
    free(player_pool);
    free(player_index_map);
    wamble_mutex_destroy(&player_mutex);
    wamble_mutex_destroy(&rng_mutex);
  }
  free(expired_session_notifications);
  expired_session_notifications = NULL;
  expired_session_notification_cap = 0;
  expired_session_notification_head = 0;
  expired_session_notification_count = 0;
  if (get_config()->max_players <= 0)
    return;
  size_t nplayers = (size_t)get_config()->max_players;
  size_t nmap = (size_t)(get_config()->max_players * 2);
  player_pool = malloc(sizeof(WamblePlayer) * nplayers);
  player_index_map = malloc(sizeof(int) * nmap);
  if (!player_pool || !player_index_map) {
    free(player_pool);
    free(player_index_map);
    player_pool = NULL;
    player_index_map = NULL;
    return;
  }
  memset(player_pool, 0, sizeof(WamblePlayer) * nplayers);
  num_players = 0;
  wamble_mutex_init(&player_mutex);
  wamble_mutex_init(&rng_mutex);
  rng_init();
  for (int i = 0; i < PLAYER_MAP_SIZE; i++)
    player_index_map[i] = -1;
  player_manager_ready_flag = 1;
}

WamblePlayer *get_player_by_token(const uint8_t *token) {
  if (!token || !player_manager_ready_flag)
    return NULL;

  player_manager_mutex_lock();

  int idx = player_map_get(token);
  if (idx >= 0) {
    time_t now = wamble_now_wall();
    time_t previous_seen = player_pool[idx].last_seen_time;
    player_pool[idx].last_seen_time = now;
    if (should_persist_last_seen(previous_seen, now))
      wamble_emit_update_session_last_seen(token);
    player_manager_mutex_unlock();
    return &player_pool[idx];
  }
  player_manager_mutex_unlock();

  uint64_t session_id = 0;
  DbStatus st =
      wamble_query_get_persistent_session_by_token(token, &session_id);
  if (st != DB_OK || session_id == 0)
    return NULL;

  uint8_t session_pubkey[WAMBLE_PUBLIC_KEY_LENGTH] = {0};
  int session_has_identity = 0;
  DbStatus pk_st = wamble_query_get_session_public_key(
      session_id, session_pubkey, &session_has_identity);
  if (pk_st != DB_OK && pk_st != DB_NOT_FOUND)
    return NULL;

  WamblePlayer hydrated;
  memset(&hydrated, 0, sizeof(hydrated));
  memcpy(hydrated.token, token, TOKEN_LENGTH);
  if (session_has_identity) {
    memcpy(hydrated.public_key, session_pubkey, WAMBLE_PUBLIC_KEY_LENGTH);
    hydrated.has_persistent_identity = true;
  } else {
    hydrated.has_persistent_identity = false;
  }
  hydrated.last_seen_time = wamble_now_wall();
  hydrate_player_from_session(&hydrated, session_id);

  player_manager_mutex_lock();
  idx = player_map_get(token);
  if (idx >= 0) {
    WamblePlayer *existing = &player_pool[idx];
    time_t now = wamble_now_wall();
    time_t previous_seen = existing->last_seen_time;
    existing->last_seen_time = now;
    if (should_persist_last_seen(previous_seen, now))
      wamble_emit_update_session_last_seen(token);
    player_manager_mutex_unlock();
    return existing;
  }

  WamblePlayer *player = find_empty_player_slot();
  if (!player) {
    player_manager_mutex_unlock();
    return NULL;
  }
  *player = hydrated;
  player_map_put(player->token, (int)(player - player_pool));
  wamble_emit_update_session_last_seen(token);

  player_manager_mutex_unlock();
  return player;
}

int get_player_snapshot_by_token(const uint8_t *token, WamblePlayer *out) {
  if (!token || !out || !player_manager_ready_flag)
    return -1;

  memset(out, 0, sizeof(*out));
  player_manager_mutex_lock();

  int idx = player_map_get(token);
  if (idx >= 0) {
    *out = player_pool[idx];
    player_manager_mutex_unlock();
    return 0;
  }

  uint64_t session_id = 0;
  DbStatus st =
      wamble_query_get_persistent_session_by_token(token, &session_id);
  if (st == DB_OK && session_id > 0) {
    uint8_t session_pubkey[WAMBLE_PUBLIC_KEY_LENGTH] = {0};
    int session_has_identity = 0;
    DbStatus pk_st = wamble_query_get_session_public_key(
        session_id, session_pubkey, &session_has_identity);
    if (pk_st == DB_OK || pk_st == DB_NOT_FOUND) {
      memcpy(out->token, token, TOKEN_LENGTH);
      if (session_has_identity) {
        memcpy(out->public_key, session_pubkey, WAMBLE_PUBLIC_KEY_LENGTH);
        out->has_persistent_identity = true;
      }
      hydrate_player_from_session(out, session_id);
      player_manager_mutex_unlock();
      return 0;
    }
  }

  player_manager_mutex_unlock();
  memset(out, 0, sizeof(*out));
  return -1;
}

WamblePlayer *create_new_player(void) {
  if (!player_manager_ready_flag)
    return NULL;
  for (int global_attempt = 0;
       global_attempt < get_config()->max_token_attempts; global_attempt++) {
    player_manager_mutex_lock();

    WamblePlayer *player = find_empty_player_slot();
    if (!player) {
      player_manager_mutex_unlock();
      return NULL;
    }

    uint8_t candidate_token[TOKEN_LENGTH];
    int collision_found;
    int local_attempts = 0;

    do {
      rng_bytes(candidate_token, TOKEN_LENGTH);
      local_attempts++;

      collision_found = 0;
      for (int i = 0; i < num_players; i++) {
        if (&player_pool[i] != player &&
            tokens_equal(player_pool[i].token, candidate_token)) {
          collision_found = 1;
          break;
        }
      }
      if (!collision_found) {
        break;
      }
    } while (local_attempts < get_config()->max_token_local_attempts);

    if (local_attempts >= get_config()->max_token_local_attempts) {
      player_manager_mutex_unlock();
      continue;
    }

    memcpy(player->token, candidate_token, TOKEN_LENGTH);
    memset(player->public_key, 0, WAMBLE_PUBLIC_KEY_LENGTH);
    player->has_persistent_identity = 0;
    player->last_seen_time = wamble_now_wall();
    player->score = 0.0;
    player->prediction_score = 0.0;
    player->rating = (double)get_config()->default_rating;
    player->games_played = 0;
    player->chess960_games_played = 0;
    wamble_emit_create_session(candidate_token, 0);
    player_map_put(player->token, (int)(player - player_pool));
    player_manager_mutex_unlock();
    return player;
  }
  return NULL;
}

WamblePlayer *attach_persistent_identity(const uint8_t *token,
                                         const uint8_t *public_key) {
  if (!token || !public_key || !player_manager_ready_flag)
    return NULL;
  WamblePersistentPlayerStats stats = {0};
  DbStatus stats_status =
      wamble_query_get_persistent_player_stats(public_key, &stats);
  if (stats_status != DB_OK && stats_status != DB_NOT_FOUND)
    return NULL;

  player_manager_mutex_lock();
  int idx = player_map_get(token);
  if (idx < 0) {
    player_manager_mutex_unlock();
    return NULL;
  }
  WamblePlayer *player = &player_pool[idx];
  memcpy(player->public_key, public_key, WAMBLE_PUBLIC_KEY_LENGTH);
  player->has_persistent_identity = true;
  if (stats_status == DB_OK)
    apply_persistent_player_stats(player, &stats);
  wamble_emit_link_session_to_pubkey(player->token, public_key);
  player_manager_mutex_unlock();
  (void)board_emit_persistent_reservation_for_token(token);
  return player;
}

int detach_persistent_identity(const uint8_t *token) {
  if (!token || !player_manager_ready_flag)
    return -1;
  player_manager_mutex_lock();
  int idx = player_map_get(token);
  if (idx < 0) {
    player_manager_mutex_unlock();
    return -1;
  }
  WamblePlayer *player = &player_pool[idx];
  memset(player->public_key, 0, WAMBLE_PUBLIC_KEY_LENGTH);
  if (player->has_persistent_identity) {
    player->has_persistent_identity = false;
    wamble_emit_unlink_session_identity(player->token);
  }
  player_manager_mutex_unlock();
  return 0;
}

void player_manager_tick(void) {
  if (!player_manager_ready_flag)
    return;
  time_t now = wamble_now_wall();

  player_manager_mutex_lock();

  for (int i = 0; i < num_players; i++) {
    if (!player_slot_is_empty(&player_pool[i]) &&
        (now - player_pool[i].last_seen_time) >
            get_config()->token_expiration) {
      uint8_t old_token[TOKEN_LENGTH];
      memcpy(old_token, player_pool[i].token, TOKEN_LENGTH);
      queue_expired_session_notification_locked(old_token);
      player_map_delete(old_token);
      memset(&player_pool[i], 0, sizeof(player_pool[i]));
    }
  }
  while (num_players > 0 && player_slot_is_empty(&player_pool[num_players - 1]))
    num_players--;

  player_manager_mutex_unlock();
}

void discard_player_by_token(const uint8_t *token) {
  if (!token || !player_manager_ready_flag)
    return;
  player_manager_mutex_lock();
  int idx = player_map_get(token);
  if (idx >= 0) {
    uint8_t old_token[TOKEN_LENGTH];
    memcpy(old_token, player_pool[idx].token, TOKEN_LENGTH);
    player_map_delete(old_token);
    memset(&player_pool[idx], 0, sizeof(player_pool[idx]));
    while (num_players > 0 &&
           player_slot_is_empty(&player_pool[num_players - 1])) {
      num_players--;
    }
  }
  player_manager_mutex_unlock();
}
