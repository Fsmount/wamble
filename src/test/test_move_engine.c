#ifdef TEST_MOVE_ENGINE

#include "../include/wamble/wamble.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

extern int validate_and_apply_move(WambleBoard *wamble_board,
                                   const char *uci_move);

static int run_test(int (*test_func)(), const char *test_name) {
  printf("Running test: %s... ", test_name);
  int result = test_func();
  if (result) {
    printf("PASSED\n");
  } else {
    printf("FAILED\n");
  }
  return result;
}

static void get_fen_prefix(const char *fen, char *fen_prefix_str) {
  const char *p = fen;
  int space_count = 0;
  int i = 0;
  while (*p && space_count < 4) {
    if (*p == ' ') {
      space_count++;
    }
    fen_prefix_str[i++] = *p++;
  }
  fen_prefix_str[i] = '\0';
}

int test_legal_move() {
  WambleBoard board;
  strcpy(board.fen, "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1");
  int result = validate_and_apply_move(&board, "e2e4");
  char actual_fen_prefix[FEN_MAX_LENGTH];
  get_fen_prefix(board.fen, actual_fen_prefix);
  const char *expected_fen_prefix =
      "rnbqkbnr/pppppppp/8/8/4P3/8/PPPP1PPP/RNBQKBNR b KQkq e3";
  return result == 0 && strncmp(actual_fen_prefix, expected_fen_prefix,
                                strlen(expected_fen_prefix)) == 0;
}

int test_illegal_move() {
  WambleBoard board;
  strcpy(board.fen,
         "rnbqkbnr/pppppppp/8/8/4P3/8/PPPP1PPP/RNBQKBNR b KQkq e3 0 1");
  int result = validate_and_apply_move(&board, "e7e9");
  return result == -1;
}

int test_move_into_check() {
  WambleBoard board;
  strcpy(board.fen, "4k3/8/8/8/8/8/4q3/4K3 w - - 0 1");
  int result = validate_and_apply_move(&board, "d2d4");
  return result == -1;
}

int test_castling() {
  WambleBoard board;
  strcpy(board.fen, "r3k2r/pppppppp/8/8/8/8/PPPPPPPP/R3K2R w KQkq - 0 1");
  int result = validate_and_apply_move(&board, "e1g1");
  char actual_fen_prefix[FEN_MAX_LENGTH];
  get_fen_prefix(board.fen, actual_fen_prefix);
  const char *expected_fen_prefix =
      "r3k2r/pppppppp/8/8/8/8/PPPPPPPP/R4RK1 b kq";
  return result == 0 && strncmp(actual_fen_prefix, expected_fen_prefix,
                                strlen(expected_fen_prefix)) == 0;
}

int test_promotion() {
  WambleBoard board;
  strcpy(board.fen, "8/P7/8/8/8/8/8/k1K5 w - - 0 1");
  int result = validate_and_apply_move(&board, "a7a8q");
  const char *expected_fen_prefix = "Q7/8/8/8/8/8/8/k1K5 b - -";
  return result == 0 && strncmp(board.fen, expected_fen_prefix,
                                strlen(expected_fen_prefix)) == 0;
}

int test_en_passant() {
  WambleBoard board;
  strcpy(board.fen,
         "rnbqkbnr/pppppppp/8/8/3pP3/8/PPPP1PPP/RNBQKBNR b KQkq e3 0 3");
  int result = validate_and_apply_move(&board, "d4e3");
  const char *expected_fen_prefix =
      "rnbqkbnr/pppppppp/8/8/8/4p3/PPPP1PPP/RNBQKBNR w KQkq - 0 1";
  printf("\nActual FEN: %s\nExpected FEN Prefix: %s\n", board.fen,
         expected_fen_prefix);
  return result == 0 && strncmp(board.fen, expected_fen_prefix,
                                strlen(expected_fen_prefix)) == 0;
}

static void get_castling_from_fen(const char *fen, char *castling_str) {
  const char *p = fen;
  int space_count = 0;
  while (*p) {
    if (*p == ' ') {
      space_count++;
      if (space_count == 2) {
        p++;
        int i = 0;
        while (*p && *p != ' ') {
          castling_str[i++] = *p++;
        }
        castling_str[i] = '\0';
        return;
      }
    }
    p++;
  }
  strcpy(castling_str, "-");
}

int test_rook_capture_revokes_castling() {
  WambleBoard board;
  strcpy(board.fen, "r3k2r/8/8/8/8/8/8/R3K2R w KQkq - 0 1");
  int result = validate_and_apply_move(&board, "a1a8");

  char castling_rights[5];
  get_castling_from_fen(board.fen, castling_rights);

  return result == 0 && strchr(castling_rights, 'q') == NULL;
}

int test_invalid_en_passant_no_pawn() {
  WambleBoard board;
  strcpy(board.fen,
         "rnbqkbnr/pppp1ppp/8/4P3/8/8/PPPP1PPP/RNBQKBNR w KQkq e6 0 1");
  int result = validate_and_apply_move(&board, "e5d6");
  return result == -1;
}

int main() {
  printf("--- Move Engine Tests ---\n");
  int passed = 0;
  int total = 0;

  passed += run_test(test_legal_move, "Legal move (e2e4)");
  total++;

  passed += run_test(test_illegal_move, "Illegal Move (pawn hop)");
  total++;

  passed += run_test(test_move_into_check, "Illegal Move (exposes king)");
  total++;

  passed += run_test(test_castling, "White Kingside Castling");
  total++;

  passed += run_test(test_promotion, "White Pawn Promotion to Queen");
  total++;

  passed += run_test(test_en_passant, "Black En Passant Capture");
  total++;

  passed += run_test(test_rook_capture_revokes_castling,
                     "Rook Capture Revokes Castling");
  total++;

  passed +=
      run_test(test_invalid_en_passant_no_pawn, "Invalid En Passant (no pawn)");
  total++;

  printf("--- Summary ---\n");
  printf("%d/%d tests passed.\n", passed, total);

  return (passed == total) ? 0 : 1;
}

#endif