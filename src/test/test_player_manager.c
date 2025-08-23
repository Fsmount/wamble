#ifdef TEST_PLAYER_MANAGER

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../include/wamble/wamble.h"

uint64_t db_get_session_by_token(const uint8_t *token) {
  (void)token;
  return 0;
}
void db_update_session_last_seen(uint64_t session_id) { (void)session_id; }
double db_get_player_total_score(uint64_t session_id) {
  (void)session_id;
  return 0.0;
}
uint64_t db_create_session(const uint8_t *token, uint64_t player_id) {
  (void)token;
  (void)player_id;
  return 1;
}
int db_get_session_games_played(uint64_t session_id) {
  (void)session_id;
  return 0;
}

#include "../player_manager.c"

static bool are_tokens_equal(const uint8_t *t1, const uint8_t *t2) {
  return memcmp(t1, t2, TOKEN_LENGTH) == 0;
}

static bool test_player_creation_and_lookup() {
  WamblePlayer *p1 = create_new_player();
  if (!p1)
    return false;

  WamblePlayer *p2 = get_player_by_token(p1->token);
  if (!p2)
    return false;

  return p1 == p2;
}

static bool test_token_uniqueness() {
  WamblePlayer *p1 = create_new_player();
  WamblePlayer *p2 = create_new_player();
  if (!p1 || !p2)
    return false;

  return !are_tokens_equal(p1->token, p2->token);
}

static bool test_find_nonexistent_player() {
  uint8_t fake_token[TOKEN_LENGTH] = {0};
  WamblePlayer *p = get_player_by_token(fake_token);
  return p == NULL;
}

static bool test_url_token_conversion() {
  uint8_t original_token[TOKEN_LENGTH];
  generate_new_token(original_token);

  char url_buffer[32];
  format_token_for_url(original_token, url_buffer);

  if (strlen(url_buffer) != 22)
    return false;

  uint8_t decoded_token[TOKEN_LENGTH];
  int rc = decode_token_from_url(url_buffer, decoded_token);

  return rc == 0 && are_tokens_equal(original_token, decoded_token);
}

static bool test_player_pool_full() {

  for (int i = 0; i < MAX_PLAYERS; i++) {
    if (create_new_player() == NULL)
      return false;
  }
  WamblePlayer *extra_player = create_new_player();
  return extra_player == NULL;
}

static bool test_token_expiration() {
  WamblePlayer *p = create_new_player();
  if (!p)
    return false;

  uint8_t expired_token[TOKEN_LENGTH];
  memcpy(expired_token, p->token, TOKEN_LENGTH);

  p->last_seen_time = time(NULL) - TOKEN_EXPIRATION_SECONDS - 1;

  player_manager_tick();

  WamblePlayer *p_after_tick = get_player_by_token(expired_token);
  return p_after_tick == NULL;
}

typedef struct {
  const char *name;
  bool (*run)(void);
} TestCase;

static const TestCase cases[] = {
    {"player pool capacity", test_player_pool_full},
    {"token expiration", test_token_expiration},
};

int main(int argc, char **argv) {
  const char *filter = (argc > 1 ? argv[1] : "");
  int pass = 0, total = 0;

  for (size_t i = 0; i < (sizeof(cases) / sizeof((cases)[0])); ++i) {
    if (*filter && !strstr(cases[i].name, filter))
      continue;

    ++total;

    player_manager_init();
    if (cases[i].run()) {
      printf("%s PASSED\n", cases[i].name);
      ++pass;
    } else {
      printf("%s FAILED\n", cases[i].name);
    }
  }
  printf("%d/%d passed\n", pass, total);
  return (pass == total) ? 0 : 1;
}

#endif
