#ifndef WAMBLE_H
#define WAMBLE_H

#include <stddef.h>
#include <stdint.h>


typedef enum {
  EMPTY = 0,
  WPAWN = 1,
  WKNIGHT,
  WBISHOP,
  WROOK,
  WQUEEN,
  WKING,
  BPAWN = 9,
  BKNIGHT,
  BBISHOP,
  BROOK,
  BQUEEN,
  BKING
} Piece;

typedef struct {  
  uint8_t sq[128];
  uint8_t side;
  uint8_t castle;
  int8_t ep;
  uint16_t halfmove;
  uint32_t fullmove;
} Board;

static inline int is_white(uint8_t p) { return p && p < WPAWN; }
static inline int is_black(uint8_t p) { return p >= BPAWN; }
static inline uint8_t flip_colour(uint8_t p) { return p ^ 8; }

Piece char2piece(char c);
char piece2char(Piece p);
int board_init_from_fen(Board *b, const char *fen);
void board_to_fen(const Board *b, char *out);
int move_is_legal(const Board *b, const char *uci);
int board_apply_move(Board *b, const char *uci);

#endif
