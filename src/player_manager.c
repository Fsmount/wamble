#include "../include/wamble/wamble.h"
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||      \
    defined(__NetBSD__)
#include <stdlib.h>
#elif defined(_WIN32)
#include <bcrypt.h>
#include <windows.h>
#elif defined(__linux__)
#include <sys/random.h>
#endif

static WamblePlayer player_pool[MAX_PLAYERS];
static int num_players = 0;
static pthread_mutex_t player_mutex = PTHREAD_MUTEX_INITIALIZER;

static const char base64url_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static pthread_mutex_t rng_mutex = PTHREAD_MUTEX_INITIALIZER;
static int rng_initialized = 0;
static uint64_t pcg_state = 0x853c49e6748fea9bULL;
static uint64_t pcg_inc = 0xda3e39cb94b95bdbULL;

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
  pthread_mutex_lock(&rng_mutex);
  if (rng_initialized) {
    pthread_mutex_unlock(&rng_mutex);
    return;
  }

  uint64_t seed1 = (uint64_t)time(NULL);
  uint64_t seed2 = (uint64_t)clock();
  uint64_t seed3 = (uint64_t)getpid();
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
    }
  }

  pcg_state ^= mix64(entropy);
  pcg_inc ^= mix64(entropy << 1);
  (void)pcg32_random_r();

  rng_initialized = 1;
  pthread_mutex_unlock(&rng_mutex);
}

uint64_t rng_u64(void) {
  pthread_mutex_lock(&rng_mutex);
  uint64_t hi = (uint64_t)pcg32_random_r();
  uint64_t lo = (uint64_t)pcg32_random_r();
  pthread_mutex_unlock(&rng_mutex);
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

#define PLAYER_MAP_SIZE (MAX_PLAYERS * 2)
static int player_index_map[PLAYER_MAP_SIZE];

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

static void player_map_init(void) {
  for (int i = 0; i < PLAYER_MAP_SIZE; i++)
    player_index_map[i] = -1;
}

static int tokens_equal(const uint8_t *token1, const uint8_t *token2);

static void player_map_put(const uint8_t *token, int index) {
  uint64_t h = token_hash(token);
  int mask = PLAYER_MAP_SIZE - 1;
  int i = (int)(h & mask);
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
  int i = (int)(h & mask);
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
  int i = (int)(h & mask);
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

static void generate_new_token(uint8_t *token_buffer) {
  rng_bytes(token_buffer, 16);
}

static int tokens_equal(const uint8_t *token1, const uint8_t *token2) {
  for (int i = 0; i < 16; i++) {
    if (token1[i] != token2[i]) {
      return 0;
    }
  }
  return 1;
}

static WamblePlayer *find_empty_player_slot(void) {
  for (int i = 0; i < MAX_PLAYERS; i++) {
    int is_empty = 1;
    for (int j = 0; j < 16; j++) {
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
  memset(player_pool, 0, sizeof(player_pool));
  num_players = 0;
  rng_init();
  player_map_init();
}

WamblePlayer *get_player_by_token(const uint8_t *token) {
  if (!token)
    return NULL;

  pthread_mutex_lock(&player_mutex);

  int idx = player_map_get(token);
  if (idx >= 0) {
    player_pool[idx].last_seen_time = time(NULL);

    uint64_t session_id = db_get_session_by_token(token);
    if (session_id > 0) {
      db_update_session_last_seen(session_id);
    }

    pthread_mutex_unlock(&player_mutex);
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
      player->score = db_get_player_total_score(session_id) + 1200.0;
      player->games_played = db_get_session_games_played(session_id);
      player_map_put(player->token, (int)(player - player_pool));
      db_update_session_last_seen(session_id);

      pthread_mutex_unlock(&player_mutex);
      return player;
    }
  }

  pthread_mutex_unlock(&player_mutex);
  return NULL;
}

WamblePlayer *create_new_player(void) {
  int max_attempts = 1000;

  for (int global_attempt = 0; global_attempt < max_attempts;
       global_attempt++) {
    pthread_mutex_lock(&player_mutex);

    WamblePlayer *player = find_empty_player_slot();
    if (!player) {
      pthread_mutex_unlock(&player_mutex);
      return NULL;
    }

    uint8_t candidate_token[16];
    int collision_found;
    int local_attempts = 0;
    int max_local_attempts = 100;

    do {
      generate_new_token(candidate_token);
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
    } while (local_attempts < max_local_attempts);

    if (local_attempts >= max_local_attempts) {
      pthread_mutex_unlock(&player_mutex);
      continue;
    }

    memcpy(player->token, candidate_token, 16);
    memset(player->public_key, 0, 32);
    player->has_persistent_identity = 0;
    player->last_seen_time = time(NULL);
    player->score = 1200.0;
    player->games_played = 0;
    uint64_t session_id = db_create_session(candidate_token, 0);
    if (session_id == 0) {
      memset(player, 0, sizeof(WamblePlayer));
      pthread_mutex_unlock(&player_mutex);
      continue;
    }
    player_map_put(player->token, (int)(player - player_pool));

    pthread_mutex_unlock(&player_mutex);
    return player;
  }
  return NULL;
}

void format_token_for_url(const uint8_t *token, char *url_buffer) {
  if (!token || !url_buffer)
    return;

  int j = 0;
  for (int i = 0; i < 16; i += 3) {
    uint32_t block = 0;
    int bytes_in_block = (i + 3 <= 16) ? 3 : (16 - i);

    for (int k = 0; k < bytes_in_block; k++) {
      block |= ((uint32_t)token[i + k]) << (8 * (2 - k));
    }

    for (int k = 0; k < 4; k++) {
      if (j >= 22)
        break;
      url_buffer[j++] = base64url_chars[(block >> (6 * (3 - k))) & 0x3F];
    }
  }

  url_buffer[22] = '\0';
}

int decode_token_from_url(const char *url_string, uint8_t *token_buffer) {
  if (!url_string || !token_buffer || strlen(url_string) != 22) {
    return -1;
  }

  uint8_t decode_table[256];
  memset(decode_table, 0xFF, 256);

  for (int i = 0; i < 64; i++) {
    decode_table[(unsigned char)base64url_chars[i]] = i;
  }

  memset(token_buffer, 0, 16);

  int token_pos = 0;
  for (int i = 0; i < 22; i += 4) {
    uint32_t block = 0;
    int valid_chars = 0;

    for (int j = 0; j < 4 && (i + j) < 22; j++) {
      unsigned char c = url_string[i + j];
      if (decode_table[c] == 0xFF) {
        return -1;
      }
      block |= ((uint32_t)decode_table[c]) << (6 * (3 - j));
      valid_chars++;
    }

    for (int j = 0; j < 3 && token_pos < 16; j++) {
      token_buffer[token_pos++] = (block >> (8 * (2 - j))) & 0xFF;
    }
  }

  return 0;
}

void player_manager_tick(void) {
  time_t now = time(NULL);

  pthread_mutex_lock(&player_mutex);

  for (int i = 0; i < num_players; i++) {
    int is_empty = 1;
    for (int j = 0; j < 16; j++) {
      if (player_pool[i].token[j] != 0) {
        is_empty = 0;
        break;
      }
    }

    if (!is_empty &&
        (now - player_pool[i].last_seen_time) > TOKEN_EXPIRATION_SECONDS) {
      uint8_t old_token[16];
      memcpy(old_token, player_pool[i].token, 16);
      memset(&player_pool[i], 0, sizeof(WamblePlayer));
      player_map_delete(old_token);
      if (i == num_players - 1) {
        num_players--;
      }
    }
  }

  pthread_mutex_unlock(&player_mutex);
}

void create_player(uint8_t *token) {
  WamblePlayer *player = create_new_player();
  if (player) {
    memcpy(token, player->token, TOKEN_LENGTH);
  } else {
    memset(token, 0, TOKEN_LENGTH);
  }
}
