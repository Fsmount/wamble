#ifdef TEST_SPECTATOR

#include "../../include/wamble/wamble.h"
#include "../spectator_manager.c"
#include <stdio.h>
#include <string.h>

static WambleBoard g_boards[8];

WambleBoard *get_board_by_id(uint64_t board_id) {
  if (board_id == 0 ||
      board_id >= (uint64_t)(sizeof(g_boards) / sizeof(g_boards[0])))
    return NULL;
  WambleBoard *b = &g_boards[board_id];
  if (b->id != board_id)
    return NULL;
  return b;
}

static void init_board(uint64_t id, const char *fen, BoardState st) {
  memset(&g_boards[id], 0, sizeof(WambleBoard));
  g_boards[id].id = id;
  strncpy(g_boards[id].fen, fen, FEN_MAX_LENGTH - 1);
  g_boards[id].fen[FEN_MAX_LENGTH - 1] = '\0';
  g_boards[id].state = st;
  g_boards[id].last_move_time = time(NULL);
  g_boards[id].last_assignment_time = time(NULL) - 1;
}

static int test_summary_and_focus_flow(void) {
  SpectatorInitStatus si = spectator_manager_init();
  if (si != SPECTATOR_INIT_OK) {
    printf("spectator init failed: %d\n", (int)si);
    return 0;
  }

  static WambleConfig cfg_local;
  cfg_local = *get_config();
  cfg_local.max_client_sessions = 16;
  cfg_local.max_boards = 4;
  cfg_local.spectator_visibility = 0;
  cfg_local.spectator_max_focus_per_session = 1;
  cfg_local.spectator_summary_hz = 10;
  cfg_local.spectator_focus_hz = 50;
  cfg_local.spectator_summary_mode = strdup("changes");
  set_thread_config(&cfg_local);

  init_board(1, "startpos", BOARD_STATE_ACTIVE);
  init_board(2, "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1",
             BOARD_STATE_ACTIVE);
  init_board(3, "8/8/8/8/8/8/8/8 w - - 0 1", BOARD_STATE_RESERVED);
  init_board(4, "8/8/8/8/8/8/8/8 w - - 0 1", BOARD_STATE_DORMANT);

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)get_config()->port);
  addr.sin_addr.s_addr = htonl(0x7F000001);

  uint8_t tok1[TOKEN_LENGTH] = {1};
  uint8_t tok2[TOKEN_LENGTH] = {2};

  struct WambleMsg msum = {0};
  msum.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  memcpy(msum.token, tok1, TOKEN_LENGTH);
  msum.board_id = 0;
  SpectatorState st = SPECTATOR_STATE_IDLE;
  uint64_t focus = 0;
  SpectatorRequestStatus rs =
      spectator_handle_request(&msum, &addr, &st, &focus);
  if (rs != SPECTATOR_OK_SUMMARY || st != SPECTATOR_STATE_SUMMARY) {
    printf("summary request failed: rs=%d st=%d\n", rs, (int)st);
    return 0;
  }

  struct WambleMsg mfoc = {0};
  mfoc.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  memcpy(mfoc.token, tok2, TOKEN_LENGTH);
  mfoc.board_id = 1;
  st = SPECTATOR_STATE_IDLE;
  focus = 0;
  rs = spectator_handle_request(&mfoc, &addr, &st, &focus);
  if (rs != SPECTATOR_OK_FOCUS || st != SPECTATOR_STATE_FOCUS || focus != 1) {
    printf("focus request failed: rs=%d st=%d focus=%llu\n", rs, (int)st,
           focus);
    return 0;
  }

  SpectatorUpdate buf[16];
  int nupd = spectator_collect_updates(buf, 16);
  if (nupd <= 0) {
    printf("expected spectator updates, got %d\n", nupd);
    return 0;
  }
  int saw_sum = 0, saw_focus = 0;
  for (int i = 0; i < nupd; i++) {
    if (tokens_equal(buf[i].token, tok1))
      saw_sum = 1;
    if (tokens_equal(buf[i].token, tok2) && buf[i].board_id == 1)
      saw_focus = 1;
  }
  if (!saw_sum || !saw_focus) {
    printf("missing expected updates: sum=%d focus=%d\n", saw_sum, saw_focus);
    return 0;
  }

  g_boards[1].state = BOARD_STATE_DORMANT;
  spectator_manager_tick();
  int nnot = spectator_collect_notifications(buf, 16);
  if (nnot < 1) {
    printf("expected a notification after focus game finished\n");
    return 0;
  }

  spectator_manager_shutdown();
  return 1;
}

static int test_visibility_and_capacity(void) {
  SpectatorInitStatus si = spectator_manager_init();
  if (si != SPECTATOR_INIT_OK) {
    printf("spectator init failed: %d\n", (int)si);
    return 0;
  }
  static WambleConfig cfg_local;
  cfg_local = *get_config();
  cfg_local.spectator_visibility = 1;
  set_thread_config(&cfg_local);
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)get_config()->port);
  addr.sin_addr.s_addr = htonl(0x7F000001);
  uint8_t tok[TOKEN_LENGTH] = {3};
  struct WambleMsg m = {0};
  m.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  memcpy(m.token, tok, TOKEN_LENGTH);
  m.board_id = 0;
  SpectatorState st = SPECTATOR_STATE_IDLE;
  uint64_t focus = 0;
  SpectatorRequestStatus rs = spectator_handle_request(&m, &addr, &st, &focus);
  if (rs != SPECTATOR_ERR_VISIBILITY) {
    printf("expected visibility error, got %d\n", rs);
    spectator_manager_shutdown();
    return 0;
  }

  cfg_local = *get_config();
  cfg_local.spectator_visibility = 0;
  cfg_local.max_spectators = 1;
  set_thread_config(&cfg_local);

  init_board(1, "startpos", BOARD_STATE_ACTIVE);
  struct WambleMsg mf1 = {0}, mf2 = {0};
  uint8_t t1[TOKEN_LENGTH] = {4};
  uint8_t t2[TOKEN_LENGTH] = {5};
  mf1.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  mf1.board_id = 1;
  memcpy(mf1.token, t1, TOKEN_LENGTH);
  mf2.ctrl = WAMBLE_CTRL_SPECTATE_GAME;
  mf2.board_id = 1;
  memcpy(mf2.token, t2, TOKEN_LENGTH);
  st = SPECTATOR_STATE_IDLE;
  focus = 0;
  rs = spectator_handle_request(&mf1, &addr, &st, &focus);
  if (rs != SPECTATOR_OK_FOCUS) {
    printf("first focus not ok\n");
    spectator_manager_shutdown();
    return 0;
  }
  st = SPECTATOR_STATE_IDLE;
  focus = 0;
  rs = spectator_handle_request(&mf2, &addr, &st, &focus);
  if (rs != SPECTATOR_ERR_FULL) {
    printf("expected full, got %d\n", rs);
    spectator_manager_shutdown();
    return 0;
  }

  spectator_manager_shutdown();
  return 1;
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  char msg[128];
  (void)config_load(NULL, NULL, msg, sizeof(msg));
  struct {
    const char *name;
    int (*fn)(void);
  } tests[] = {
      {"summary+focus flow", test_summary_and_focus_flow},
      {"visibility and capacity", test_visibility_and_capacity},
  };
  int pass = 0, total = 0;
  for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
    total++;
    if (tests[i].fn()) {
      printf("%s PASSED\n", tests[i].name);
      pass++;
    }
  }
  printf("%d/%d passed\n", pass, total);
  return (pass == total) ? 0 : 1;
}

#endif
