#include "../include/wamble/wamble.h"
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAX_PLAYERS 1024
#define TOKEN_EXPIRATION_SECONDS 86400

static WamblePlayer player_pool[MAX_PLAYERS];
static int num_players = 0;
static pthread_mutex_t player_mutex = PTHREAD_MUTEX_INITIALIZER;

static const char base64url_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static void generate_new_token(uint8_t *token_buffer) {
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0) {
    for (int i = 0; i < 16; i++) {
      token_buffer[i] = rand() & 0xFF;
    }
    return;
  }

  ssize_t bytes_read = 0;
  while (bytes_read < 16) {
    ssize_t result = read(fd, token_buffer + bytes_read, 16 - bytes_read);
    if (result > 0) {
      bytes_read += result;
    }
  }
  close(fd);
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
  srand(time(NULL));
}

WamblePlayer *get_player_by_token(const uint8_t *token) {
  if (!token)
    return NULL;

  pthread_mutex_lock(&player_mutex);

  for (int i = 0; i < num_players; i++) {
    if (tokens_equal(player_pool[i].token, token)) {
      player_pool[i].last_seen_time = time(NULL);

      uint64_t session_id = db_get_session_by_token(token);
      if (session_id > 0) {
        db_update_session_last_seen(session_id);
      }

      pthread_mutex_unlock(&player_mutex);
      return &player_pool[i];
    }
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

      db_update_session_last_seen(session_id);

      pthread_mutex_unlock(&player_mutex);
      return player;
    }
  }

  pthread_mutex_unlock(&player_mutex);
  return NULL;
}

WamblePlayer *create_new_player(void) {
  pthread_mutex_lock(&player_mutex);

  WamblePlayer *player = find_empty_player_slot();
  if (!player) {
    pthread_mutex_unlock(&player_mutex);
    return NULL;
  }

  uint8_t candidate_token[16];
  int max_attempts = 1000;
  int attempts = 0;

  do {
    generate_new_token(candidate_token);
    attempts++;

    int collision_found = 0;
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
  } while (attempts < max_attempts);

  if (attempts >= max_attempts) {
    pthread_mutex_unlock(&player_mutex);
    return NULL;
  }

  memcpy(player->token, candidate_token, 16);
  memset(player->public_key, 0, 32);
  player->has_persistent_identity = 0;
  player->last_seen_time = time(NULL);
  player->score = 1200.0;
  player->games_played = 0;

  uint64_t session_id = db_create_session(candidate_token, 0);

  pthread_mutex_unlock(&player_mutex);
  return player;
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
      memset(&player_pool[i], 0, sizeof(WamblePlayer));
      if (i == num_players - 1) {
        num_players--;
      }
    }
  }

  pthread_mutex_unlock(&player_mutex);
}
