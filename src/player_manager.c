#include "../include/wamble/wamble.h"
#include <string.h>
#if defined(__linux__)
#include <sys/random.h>
#endif

int crypto_eddsa_check(const uint8_t signature[WAMBLE_LOGIN_SIGNATURE_LENGTH],
                       const uint8_t public_key[WAMBLE_PUBLIC_KEY_LENGTH],
                       const uint8_t *message, size_t message_size);

static WAMBLE_THREAD_LOCAL WamblePlayer *player_pool;
static WAMBLE_THREAD_LOCAL int num_players = 0;
static WAMBLE_THREAD_LOCAL wamble_mutex_t player_mutex;

static WAMBLE_THREAD_LOCAL wamble_mutex_t rng_mutex;
static WAMBLE_THREAD_LOCAL int rng_initialized = 0;
static WAMBLE_THREAD_LOCAL uint64_t pcg_state = 0x853c49e6748fea9bULL;
static WAMBLE_THREAD_LOCAL uint64_t pcg_inc = 0xda3e39cb94b95bdbULL;

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

int wamble_ed25519_verify(const uint8_t *signature, const uint8_t *public_key,
                          const uint8_t *message, size_t message_size) {
  if (!signature || !public_key || (!message && message_size != 0))
    return -1;
  return crypto_eddsa_check(signature, public_key, message, message_size);
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

static void hydrate_player_from_session(WamblePlayer *player,
                                        uint64_t session_id) {
  if (!player || session_id == 0)
    return;

  double score = 0.0;
  if (wamble_query_get_player_total_score(session_id, &score) == DB_OK)
    player->score = score;

  double prediction_score = 0.0;
  if (wamble_query_get_player_prediction_score(session_id, &prediction_score) ==
      DB_OK)
    player->prediction_score = prediction_score;

  double rating = 0.0;
  if (wamble_query_get_player_rating(session_id, &rating) == DB_OK)
    player->rating =
        (rating > 0.0) ? rating : (double)get_config()->default_rating;
  else
    player->rating = (double)get_config()->default_rating;

  int games_played = 0;
  if (wamble_query_get_session_games_played(session_id, &games_played) == DB_OK)
    player->games_played = games_played;
  else
    player->games_played = 0;

  int chess960_games_played = 0;
  if (wamble_query_get_session_chess960_games_played(
          session_id, &chess960_games_played) == DB_OK)
    player->chess960_games_played = chess960_games_played;
  else
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

  wamble_mutex_lock(&player_mutex);

  int idx = player_map_get(token);
  if (idx >= 0) {
    player_pool[idx].last_seen_time = wamble_now_wall();
    wamble_emit_update_session_last_seen(token);
    wamble_mutex_unlock(&player_mutex);
    return &player_pool[idx];
  }

  uint64_t session_id = 0;
  DbStatus st =
      wamble_query_get_persistent_session_by_token(token, &session_id);
  if (st == DB_OK && session_id > 0) {
    WamblePlayer *player = find_empty_player_slot();
    if (player) {
      memcpy(player->token, token, TOKEN_LENGTH);
      memset(player->public_key, 0, WAMBLE_PUBLIC_KEY_LENGTH);
      player->has_persistent_identity = true;
      player->last_seen_time = wamble_now_wall();
      hydrate_player_from_session(player, session_id);
      player_map_put(player->token, (int)(player - player_pool));
      wamble_emit_update_session_last_seen(token);

      wamble_mutex_unlock(&player_mutex);
      return player;
    }
  }

  wamble_mutex_unlock(&player_mutex);
  return NULL;
}

WamblePlayer *create_new_player(void) {
  if (!player_manager_ready_flag)
    return NULL;
  for (int global_attempt = 0;
       global_attempt < get_config()->max_token_attempts; global_attempt++) {
    wamble_mutex_lock(&player_mutex);

    WamblePlayer *player = find_empty_player_slot();
    if (!player) {
      wamble_mutex_unlock(&player_mutex);
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
      wamble_mutex_unlock(&player_mutex);
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
    wamble_mutex_unlock(&player_mutex);
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

  wamble_mutex_lock(&player_mutex);
  int idx = player_map_get(token);
  if (idx < 0) {
    wamble_mutex_unlock(&player_mutex);
    return NULL;
  }
  WamblePlayer *player = &player_pool[idx];
  memcpy(player->public_key, public_key, WAMBLE_PUBLIC_KEY_LENGTH);
  player->has_persistent_identity = true;
  if (stats_status == DB_OK)
    apply_persistent_player_stats(player, &stats);
  wamble_emit_link_session_to_pubkey(player->token, public_key);
  wamble_mutex_unlock(&player_mutex);
  return player;
}

int detach_persistent_identity(const uint8_t *token) {
  if (!token || !player_manager_ready_flag)
    return -1;
  wamble_mutex_lock(&player_mutex);
  int idx = player_map_get(token);
  if (idx < 0) {
    wamble_mutex_unlock(&player_mutex);
    return -1;
  }
  WamblePlayer *player = &player_pool[idx];
  memset(player->public_key, 0, WAMBLE_PUBLIC_KEY_LENGTH);
  if (player->has_persistent_identity) {
    player->has_persistent_identity = false;
    wamble_emit_unlink_session_identity(player->token);
  }
  wamble_mutex_unlock(&player_mutex);
  return 0;
}

void player_manager_tick(void) {
  if (!player_manager_ready_flag)
    return;
  time_t now = wamble_now_wall();

  wamble_mutex_lock(&player_mutex);

  for (int i = 0; i < num_players; i++) {
    if (!player_slot_is_empty(&player_pool[i]) &&
        (now - player_pool[i].last_seen_time) >
            get_config()->token_expiration) {
      uint8_t old_token[TOKEN_LENGTH];
      memcpy(old_token, player_pool[i].token, TOKEN_LENGTH);
      player_map_delete(old_token);
      memset(&player_pool[i], 0, sizeof(player_pool[i]));
    }
  }
  while (num_players > 0 && player_slot_is_empty(&player_pool[num_players - 1]))
    num_players--;

  wamble_mutex_unlock(&player_mutex);
}

void discard_player_by_token(const uint8_t *token) {
  if (!token || !player_manager_ready_flag)
    return;
  wamble_mutex_lock(&player_mutex);
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
  wamble_mutex_unlock(&player_mutex);
}
