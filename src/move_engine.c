#include "../include/wamble/wamble.h"

#include <string.h>

Piece char2piece(char c) {
  switch (c) {
  case 'P':
    return WPAWN;
  case 'N':
    return WKNIGHT;
  case 'B':
    return WBISHOP;
  case 'R':
    return WROOK;
  case 'Q':
    return WQUEEN;
  case 'K':
    return WKING;
  case 'p':
    return BPAWN;
  case 'n':
    return BKNIGHT;
  case 'b':
    return BBISHOP;
  case 'r':
    return BROOK;
  case 'q':
    return BQUEEN;
  case 'k':
    return BKING;
  default:
    return EMPTY;
  }
}

char piece2char(Piece p) {
  static const char map[] = ".PNBRQK.pnbrqk";
  if (p >= sizeof(map) - 1) {
    return '.';
  }
  return map[p];
}

int board_init_from_fen(Board *b, const char *fen) {
  if (!b || !fen) {
    return -1;
  }
  memset(b->sq, 0, sizeof(b->sq));
  b->side = 0;
  b->castle = 0;
  b->ep = -1;
  b->halfmove = 0;
  b->fullmove = 1;
  // TODO: parse FEN string and populate board accordingly.
  (void)fen;
  return 0;
}

void board_to_fen(const Board *b, char *out) {
  if (!b || !out) {
    return;
  }
  // TODO: produce a correct FEN string from the board state.
  strcpy(out, "8/8/8/8/8/8/8/8 w - - 0 1");
}

int move_is_legal(const Board *b, const char *uci) {
  (void)b;
  (void)uci;
  // TODO: implement psuedo move generation and legality checks
  return 0;
}

int board_apply_move(Board *b, const char *uci) {
  if (!b || !uci) {
    return -1;
  }
  if (!move_is_legal(b, uci)) {
    return -1;
  }
  // TODO: update board state to actually apply the move
  return 0;
}

#ifdef TEST_MOVE_ENGINE
#include <assert.h>
#include <stdio.h>

int main(void) {
  Board b;
  const char *start = "8/8/8/8/8/8/8/8 w - - 0 1";
  char out[128];

  assert(board_init_from_fen(&b, start) == 0);
  board_to_fen(&b, out);
  assert(strcmp(out, start) == 0);

  puts("FEN works ig?");
  return 0;
}
#endif
