#include "../include/wamble/wamble.h"
#include <string.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/random.h>
#endif

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

  uint64_t seed1 = (uint64_t)time(NULL);
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

uint64_t rng_u64(void) {
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

static uint64_t token_hash(const uint8_t *token) {
  uint64_t h = 1469598103934665603ULL;
  for (int i = 0; i < 16; i++) {
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

static void player_map_put(const uint8_t *token, int index) {
  uint64_t h = token_hash(token);
  int mask = PLAYER_MAP_SIZE - 1;
  int i = (int)(h & (uint64_t)mask);
  int first_tombstone = -1;
  for (int probe = 0; probe < PLAYER_MAP_SIZE; probe++) {
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
    i = (i + 1) & mask;
  }
}

static int player_map_get(const uint8_t *token) {
  uint64_t h = token_hash(token);
  int mask = PLAYER_MAP_SIZE - 1;
  int i = (int)(h & (uint64_t)mask);
  for (int probe = 0; probe < PLAYER_MAP_SIZE; probe++) {
    int cur = player_index_map[i];
    if (cur == -1)
      return -1;
    if (cur >= 0 && tokens_equal(player_pool[cur].token, token))
      return cur;
    i = (i + 1) & mask;
  }
  return -1;
}

static void player_map_delete(const uint8_t *token) {
  uint64_t h = token_hash(token);
  int mask = PLAYER_MAP_SIZE - 1;
  int i = (int)(h & (uint64_t)mask);
  for (int probe = 0; probe < PLAYER_MAP_SIZE; probe++) {
    int cur = player_index_map[i];
    if (cur == -1)
      return;
    if (cur >= 0 && tokens_equal(player_pool[cur].token, token)) {
      player_index_map[i] = -2;
      return;
    }
    i = (i + 1) & mask;
  }
}

static WamblePlayer *find_empty_player_slot(void) {
  for (int i = 0; i < get_config()->max_players; i++) {
    int is_empty = 1;
    for (int j = 0; j < TOKEN_LENGTH; j++) {
      if (player_pool[i].token[j] != 0) {
        is_empty = 0;
        break;
      }
    }
    if (is_empty) {
      if (i >= num_players) {
        num_players = i + 1;
      }
      return &player_pool[i];
    }
  }
  return NULL;
}

void player_manager_init(void) {
  if (player_pool) {
    free(player_pool);
    free(player_index_map);
    wamble_mutex_destroy(&player_mutex);
    wamble_mutex_destroy(&rng_mutex);
  }
  player_pool =
      malloc(sizeof(WamblePlayer) * (size_t)get_config()->max_players);
  player_index_map =
      malloc(sizeof(int) * (size_t)(get_config()->max_players * 2));
  memset(player_pool, 0,
         sizeof(WamblePlayer) * (size_t)get_config()->max_players);
  num_players = 0;
  wamble_mutex_init(&player_mutex);
  wamble_mutex_init(&rng_mutex);
  rng_init();
  for (int i = 0; i < PLAYER_MAP_SIZE; i++)
    player_index_map[i] = -1;
}

WamblePlayer *get_player_by_token(const uint8_t *token) {
  if (!token)
    return NULL;

  wamble_mutex_lock(&player_mutex);

  int idx = player_map_get(token);
  if (idx >= 0) {
    player_pool[idx].last_seen_time = time(NULL);

    uint64_t session_id = db_get_session_by_token(token);
    if (session_id > 0) {
      db_async_update_session_last_seen(session_id);
    }
    wamble_mutex_unlock(&player_mutex);
    return &player_pool[idx];
  }

  uint64_t session_id = db_get_session_by_token(token);
  if (session_id > 0) {

    WamblePlayer *player = find_empty_player_slot();
    if (player) {
      memcpy(player->token, token, TOKEN_LENGTH);
      memset(player->public_key, 0, 32);
      player->has_persistent_identity = false;
      player->last_seen_time = time(NULL);
      player->score =
          db_get_player_total_score(session_id) + get_config()->default_rating;
      player->games_played = db_get_session_games_played(session_id);
      player_map_put(player->token, (int)(player - player_pool));
      db_async_update_session_last_seen(session_id);

      wamble_mutex_unlock(&player_mutex);
      return player;
    }
  }

  wamble_mutex_unlock(&player_mutex);
  return NULL;
}

WamblePlayer *create_new_player(void) {
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
        uint64_t existing_session = db_get_session_by_token(candidate_token);
        if (existing_session > 0) {
          collision_found = 1;
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
    memset(player->public_key, 0, 32);
    player->has_persistent_identity = 0;
    player->last_seen_time = time(NULL);
    player->score = get_config()->default_rating;
    player->games_played = 0;
    uint64_t session_id = db_create_session(candidate_token, 0);
    if (session_id == 0) {
      memset(player, 0, sizeof(WamblePlayer));
      wamble_mutex_unlock(&player_mutex);
      continue;
    }
    player_map_put(player->token, (int)(player - player_pool));
    wamble_mutex_unlock(&player_mutex);
    return player;
  }
  return NULL;
}

WamblePlayer *login_player(const uint8_t *public_key) {
  uint64_t player_id = db_get_player_by_public_key(public_key);
  if (player_id == 0) {
    player_id = db_create_player(public_key);
    if (player_id == 0) {
      return NULL;
    }
  }

  WamblePlayer *player = create_new_player();
  if (player) {
    memcpy(player->public_key, public_key, 32);
    player->has_persistent_identity = true;
    uint64_t session_id = db_get_session_by_token(player->token);
    if (session_id > 0) {
      db_async_link_session_to_player(session_id, player_id);
    }
  }
  return player;
}

void player_manager_tick(void) {
  time_t now = time(NULL);

  wamble_mutex_lock(&player_mutex);

  for (int i = 0; i < num_players; i++) {
    int is_empty = 1;
    for (int j = 0; j < TOKEN_LENGTH; j++) {
      if (player_pool[i].token[j] != 0) {
        is_empty = 0;
        break;
      }
    }

    if (!is_empty && (now - player_pool[i].last_seen_time) >
                         get_config()->token_expiration) {
      uint8_t old_token[TOKEN_LENGTH];
      memcpy(old_token, player_pool[i].token, TOKEN_LENGTH);
      memset(&player_pool[i], 0, sizeof(WamblePlayer));
      player_map_delete(old_token);
      if (i == num_players - 1) {
        num_players--;
      }
    }
  }

  wamble_mutex_unlock(&player_mutex);
}
