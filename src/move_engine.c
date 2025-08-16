#include "../include/wamble/wamble.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

static int tokens_equal(const uint8_t *token1, const uint8_t *token2) {
  for (int i = 0; i < 16; i++) {
    if (token1[i] != token2[i]) {
      return 0;
    }
  }
  return 1;
}

static const Bitboard KNIGHT_ATTACKS[64] = {
    0x0000000000020400ULL, 0x0000000000050800ULL, 0x00000000000a1100ULL,
    0x0000000000142200ULL, 0x0000000000284400ULL, 0x0000000000508800ULL,
    0x0000000000a01000ULL, 0x0000000000402000ULL, 0x0000000002040004ULL,
    0x0000000005080008ULL, 0x000000000a110011ULL, 0x0000000014220022ULL,
    0x0000000028440044ULL, 0x0000000050880088ULL, 0x00000000a0100010ULL,
    0x0000000040200020ULL, 0x0000000204000402ULL, 0x0000000508000805ULL,
    0x0000000a1100110aULL, 0x0000001422002214ULL, 0x0000002844004428ULL,
    0x0000005088008850ULL, 0x000000a0100010a0ULL, 0x0000004020002040ULL,
    0x0000020400040200ULL, 0x0000050800080500ULL, 0x00000a1100110a00ULL,
    0x0000142200221400ULL, 0x0000284400442800ULL, 0x0000508800885000ULL,
    0x0000a0100010a000ULL, 0x0000402000204000ULL, 0x0002040004020000ULL,
    0x0005080008050000ULL, 0x000a1100110a0000ULL, 0x0014220022140000ULL,
    0x0028440044280000ULL, 0x0050880088500000ULL, 0x00a0100010a00000ULL,
    0x0040200020400000ULL, 0x0204000402000000ULL, 0x0508000805000000ULL,
    0x0a1100110a000000ULL, 0x1422002214000000ULL, 0x2844004428000000ULL,
    0x5088008850000000ULL, 0xa0100010a0000000ULL, 0x4020002040000000ULL,
    0x0400040200000000ULL, 0x0800080500000000ULL, 0x1100110a00000000ULL,
    0x2200221400000000ULL, 0x4400442800000000ULL, 0x8800885000000000ULL,
    0x100010a000000000ULL, 0x2000204000000000ULL, 0x0004020000000000ULL,
    0x0008050000000000ULL, 0x00110a0000000000ULL, 0x0022140000000000ULL,
    0x0044280000000000ULL, 0x0088500000000000ULL, 0x0010a00000000000ULL,
    0x0020400000000000ULL};

static const Bitboard KING_ATTACKS[64] = {
    0x0000000000000302ULL, 0x0000000000000705ULL, 0x0000000000000e0aULL,
    0x0000000000001c14ULL, 0x0000000000003828ULL, 0x0000000000007050ULL,
    0x000000000000e0a0ULL, 0x000000000000c040ULL, 0x0000000000030203ULL,
    0x0000000000070507ULL, 0x00000000000e0a0eULL, 0x00000000001c141cULL,
    0x0000000000382838ULL, 0x0000000000705070ULL, 0x0000000000e0a0e0ULL,
    0x0000000000c040c0ULL, 0x0000000003020300ULL, 0x0000000007050700ULL,
    0x000000000e0a0e00ULL, 0x000000001c141c00ULL, 0x0000000038283800ULL,
    0x0000000070507000ULL, 0x00000000e0a0e000ULL, 0x00000000c040c000ULL,
    0x0000000302030000ULL, 0x0000000705070000ULL, 0x0000000e0a0e0000ULL,
    0x0000001c141c0000ULL, 0x0000003828380000ULL, 0x0000007050700000ULL,
    0x000000e0a0e00000ULL, 0x000000c040c00000ULL, 0x0000030203000000ULL,
    0x0000070507000000ULL, 0x00000e0a0e000000ULL, 0x00001c141c000000ULL,
    0x0000382838000000ULL, 0x0000705070000000ULL, 0x0000e0a0e0000000ULL,
    0x0000c040c0000000ULL, 0x0003020300000000ULL, 0x0007050700000000ULL,
    0x000e0a0e00000000ULL, 0x001c141c00000000ULL, 0x0038283800000000ULL,
    0x0070507000000000ULL, 0x00e0a0e000000000ULL, 0x00c040c000000000ULL,
    0x0302030000000000ULL, 0x0705070000000000ULL, 0x0e0a0e0000000000ULL,
    0x1c141c0000000000ULL, 0x3828380000000000ULL, 0x7050700000000000ULL,
    0xe0a0e00000000000ULL, 0xc040c00000000000ULL, 0x0203000000000000ULL,
    0x0507000000000000ULL, 0x0a0e000000000000ULL, 0x141c000000000000ULL,
    0x2838000000000000ULL, 0x5070000000000000ULL, 0xa0e0000000000000ULL,
    0x40c0000000000000ULL};

static inline int square_to_index(int file, int rank) {
  return rank * 8 + file;
}

static inline void index_to_square(int index, int *file, int *rank) {
  *file = index % 8;
  *rank = index / 8;
}

static inline int get_lsb(Bitboard bb) { return __builtin_ctzll(bb); }

static inline Bitboard pop_lsb(Bitboard *bb) {
  int sq = get_lsb(*bb);
  *bb &= *bb - 1;
  return get_bit(sq);
}

static inline int count_bits(Bitboard bb) { return __builtin_popcountll(bb); }

static int uci_to_squares(const char *uci, int *from, int *to) {
  if (strlen(uci) < 4)
    return -1;

  int from_file = uci[0] - 'a';
  int from_rank = uci[1] - '1';
  int to_file = uci[2] - 'a';
  int to_rank = uci[3] - '1';

  if (from_file < 0 || from_file >= 8 || from_rank < 0 || from_rank >= 8 ||
      to_file < 0 || to_file >= 8 || to_rank < 0 || to_rank >= 8) {
    return -1;
  }

  *from = square_to_index(from_file, from_rank);
  *to = square_to_index(to_file, to_rank);
  return 0;
}

static Bitboard generate_rook_attacks(int square, Bitboard occupied) {
  Bitboard attacks = 0ULL;
  int file, rank;
  index_to_square(square, &file, &rank);

  for (int r = rank + 1; r < 8; r++) {
    int sq = square_to_index(file, r);
    attacks |= get_bit(sq);
    if (occupied & get_bit(sq))
      break;
  }

  for (int r = rank - 1; r >= 0; r--) {
    int sq = square_to_index(file, r);
    attacks |= get_bit(sq);
    if (occupied & get_bit(sq))
      break;
  }

  for (int f = file + 1; f < 8; f++) {
    int sq = square_to_index(f, rank);
    attacks |= get_bit(sq);
    if (occupied & get_bit(sq))
      break;
  }

  for (int f = file - 1; f >= 0; f--) {
    int sq = square_to_index(f, rank);
    attacks |= get_bit(sq);
    if (occupied & get_bit(sq))
      break;
  }

  return attacks;
}

static Bitboard generate_bishop_attacks(int square, Bitboard occupied) {
  Bitboard attacks = 0ULL;
  int file, rank;
  index_to_square(square, &file, &rank);

  for (int f = file + 1, r = rank + 1; f < 8 && r < 8; f++, r++) {
    int sq = square_to_index(f, r);
    attacks |= get_bit(sq);
    if (occupied & get_bit(sq))
      break;
  }

  for (int f = file - 1, r = rank + 1; f >= 0 && r < 8; f--, r++) {
    int sq = square_to_index(f, r);
    attacks |= get_bit(sq);
    if (occupied & get_bit(sq))
      break;
  }

  for (int f = file + 1, r = rank - 1; f < 8 && r >= 0; f++, r--) {
    int sq = square_to_index(f, r);
    attacks |= get_bit(sq);
    if (occupied & get_bit(sq))
      break;
  }

  for (int f = file - 1, r = rank - 1; f >= 0 && r >= 0; f--, r--) {
    int sq = square_to_index(f, r);
    attacks |= get_bit(sq);
    if (occupied & get_bit(sq))
      break;
  }

  return attacks;
}

static inline Bitboard generate_pawn_attacks(int square, int color) {
  Bitboard attacks = 0ULL;
  int file, rank;
  index_to_square(square, &file, &rank);

  int direction = (color == 0) ? 1 : -1;
  int attack_rank = rank + direction;

  if (attack_rank >= 0 && attack_rank < 8) {
    if (file > 0) {
      attacks |= get_bit(square_to_index(file - 1, attack_rank));
    }
    if (file < 7) {
      attacks |= get_bit(square_to_index(file + 1, attack_rank));
    }
  }

  return attacks;
}

static int is_square_attacked(const Board *board, int square, int by_color) {
  Bitboard occupied = board->occupied[0] | board->occupied[1];

  int pawn_piece = (by_color == 0) ? WHITE_PAWN : BLACK_PAWN;
  Bitboard enemy_pawns = board->pieces[pawn_piece];
  while (enemy_pawns) {
    int pawn_sq = get_lsb(enemy_pawns);
    if (generate_pawn_attacks(pawn_sq, by_color) & get_bit(square)) {
      return 1;
    }
    pop_lsb(&enemy_pawns);
  }

  int knight_piece = (by_color == 0) ? WHITE_KNIGHT : BLACK_KNIGHT;
  if (board->pieces[knight_piece] & KNIGHT_ATTACKS[square]) {
    return 1;
  }

  int bishop_piece = (by_color == 0) ? WHITE_BISHOP : BLACK_BISHOP;
  int queen_piece = (by_color == 0) ? WHITE_QUEEN : BLACK_QUEEN;
  Bitboard attackers = board->pieces[bishop_piece] | board->pieces[queen_piece];
  while (attackers) {
    int attacker_sq = get_lsb(attackers);
    if (generate_bishop_attacks(attacker_sq, occupied) & get_bit(square)) {
      return 1;
    }
    pop_lsb(&attackers);
  }

  int rook_piece = (by_color == 0) ? WHITE_ROOK : BLACK_ROOK;
  attackers = board->pieces[rook_piece] | board->pieces[queen_piece];
  while (attackers) {
    int attacker_sq = get_lsb(attackers);
    if (generate_rook_attacks(attacker_sq, occupied) & get_bit(square)) {
      return 1;
    }
    pop_lsb(&attackers);
  }

  int king_piece = (by_color == 0) ? WHITE_KING : BLACK_KING;
  if (board->pieces[king_piece] & KING_ATTACKS[square]) {
    return 1;
  }

  return 0;
}

static int is_king_in_check(const Board *board, int color) {
  int king_piece = (color == 0) ? WHITE_KING : BLACK_KING;
  Bitboard king_bb = board->pieces[king_piece];

  return is_square_attacked(board, get_lsb(king_bb), 1 - color);
}

static inline void remove_castling_right(Board *board, char right) {
  char new_castling[5] = {0};
  int idx = 0;

  for (int i = 0; board->castling[i]; i++) {
    if (board->castling[i] != right) {
      new_castling[idx++] = board->castling[i];
    }
  }

  strcpy(board->castling, new_castling);

  if (strlen(board->castling) == 0) {
    strcpy(board->castling, "-");
  }
}

MoveInfo make_move_bitboard(Board *board, const Move *move) {
  MoveInfo info = {.captured_square = -1,
                   .captured_piece_type = -1,
                   .prev_en_passant = "--",
                   .prev_castling = "----",
                   .prev_halfmove_clock = 0,
                   .prev_fullmove_number = 0,
                   .moving_piece_color = 0};

  info.prev_halfmove_clock = board->halfmove_clock;
  info.prev_fullmove_number = board->fullmove_number;
  strncpy(info.prev_en_passant, board->en_passant,
          sizeof(info.prev_en_passant) - 1);
  strncpy(info.prev_castling, board->castling, sizeof(info.prev_castling) - 1);

  int from = move->from;
  int to = move->to;
  int color = board->turn == 'w' ? 0 : 1;
  info.moving_piece_color = color;

  int piece_type = -1;
  for (int i = 0; i < 12; i++) {
    if (board->pieces[i] & get_bit(from)) {
      piece_type = i;
      break;
    }
  }

  if (piece_type == -1)
    return info;

  board->pieces[piece_type] &= ~get_bit(from);
  board->occupied[color] &= ~get_bit(from);

  int captured_piece = 0;
  for (int i = 0; i < 12; i++) {
    if (board->pieces[i] & get_bit(to)) {
      info.captured_piece_type = i;
      info.captured_square = to;
      board->pieces[i] &= ~get_bit(to);
      int captured_color = (i < 6) ? 0 : 1;
      board->occupied[captured_color] &= ~get_bit(to);
      captured_piece = 1;

      int captured_rook_white = (i == WHITE_ROOK);
      int captured_rook_black = (i == BLACK_ROOK);

      if (captured_rook_white && to == 0) {
        remove_castling_right(board, 'Q');
      } else if (captured_rook_white && to == 7) {
        remove_castling_right(board, 'K');
      } else if (captured_rook_black && to == 56) {
        remove_castling_right(board, 'q');
      } else if (captured_rook_black && to == 63) {
        remove_castling_right(board, 'k');
      }
      break;
    }
  }

  if (move->promotion) {
    int promoted_piece;
    switch (move->promotion) {
    case 'q':
      promoted_piece = color == 0 ? WHITE_QUEEN : BLACK_QUEEN;
      break;
    case 'r':
      promoted_piece = color == 0 ? WHITE_ROOK : BLACK_ROOK;
      break;
    case 'b':
      promoted_piece = color == 0 ? WHITE_BISHOP : BLACK_BISHOP;
      break;
    case 'n':
      promoted_piece = color == 0 ? WHITE_KNIGHT : BLACK_KNIGHT;
      break;
    default:
      promoted_piece = piece_type;
      break;
    }
    board->pieces[promoted_piece] |= get_bit(to);
  } else {
    board->pieces[piece_type] |= get_bit(to);
  }

  board->occupied[color] |= get_bit(to);

  int king_piece = color == 0 ? WHITE_KING : BLACK_KING;
  if (piece_type == king_piece && abs(from - to) == 2) {
    int rook_piece = color == 0 ? WHITE_ROOK : BLACK_ROOK;
    if (to == from + 2) {
      int rook_from = from + 3;
      int rook_to = from + 1;
      board->pieces[rook_piece] &= ~get_bit(rook_from);
      board->pieces[rook_piece] |= get_bit(rook_to);
      board->occupied[color] &= ~get_bit(rook_from);
      board->occupied[color] |= get_bit(rook_to);
    } else {
      int rook_from = from - 4;
      int rook_to = from - 1;
      board->pieces[rook_piece] &= ~get_bit(rook_from);
      board->pieces[rook_piece] |= get_bit(rook_to);
      board->occupied[color] &= ~get_bit(rook_from);
      board->occupied[color] |= get_bit(rook_to);
    }
  }

  int pawn_piece = color == 0 ? WHITE_PAWN : BLACK_PAWN;
  if (piece_type == pawn_piece && board->en_passant[0] != '-') {
    int ep_file = board->en_passant[0] - 'a';
    int ep_rank = board->en_passant[1] - '1';
    int ep_square = square_to_index(ep_file, ep_rank);

    if (to == ep_square) {
      int captured_pawn_square = color == 0 ? ep_square - 8 : ep_square + 8;
      int enemy_pawn = color == 0 ? BLACK_PAWN : WHITE_PAWN;
      board->pieces[enemy_pawn] &= ~get_bit(captured_pawn_square);
      board->occupied[1 - color] &= ~get_bit(captured_pawn_square);
      captured_piece = 1;
      info.captured_piece_type = enemy_pawn;
      info.captured_square = captured_pawn_square;
    }
  }

  if (piece_type == king_piece) {

    if (color == 0) {
      remove_castling_right(board, 'K');
      remove_castling_right(board, 'Q');
    } else {
      remove_castling_right(board, 'k');
      remove_castling_right(board, 'q');
    }
  } else if (piece_type == (color == 0 ? WHITE_ROOK : BLACK_ROOK)) {

    if (color == 0) {
      if (from == 0)
        remove_castling_right(board, 'Q');
      else if (from == 7)
        remove_castling_right(board, 'K');
    } else {
      if (from == 56)
        remove_castling_right(board, 'q');
      else if (from == 63)
        remove_castling_right(board, 'k');
    }
  }

  strcpy(board->en_passant, "-");

  if (piece_type == pawn_piece && abs(to - from) == 16) {

    int ep_square = (from + to) / 2;
    int file, rank;
    index_to_square(ep_square, &file, &rank);
    board->en_passant[0] = 'a' + file;
    board->en_passant[1] = '1' + rank;
    board->en_passant[2] = '\0';
  }

  if (piece_type == pawn_piece || captured_piece) {
    board->halfmove_clock = 0;
  } else {
    board->halfmove_clock++;
  }

  if (color == 1) {
    board->fullmove_number++;
  }

  board->turn = (board->turn == 'w') ? 'b' : 'w';
  return info;
}

void unmake_move_bitboard(Board *board, const Move *move,
                          const MoveInfo *info) {
  int from = move->from;
  int to = move->to;
  int moving_piece_color = info->moving_piece_color;

  board->turn = (moving_piece_color == 0) ? 'w' : 'b';

  board->halfmove_clock = info->prev_halfmove_clock;
  board->fullmove_number = info->prev_fullmove_number;

  strncpy(board->en_passant, info->prev_en_passant,
          sizeof(board->en_passant) - 1);
  strncpy(board->castling, info->prev_castling, sizeof(board->castling) - 1);

  int piece_type_at_to = -1;
  for (int i = 0; i < 12; i++) {
    if (board->pieces[i] & get_bit(to)) {
      piece_type_at_to = i;
      break;
    }
  }

  if (move->promotion) {

    board->pieces[piece_type_at_to] &= ~get_bit(to);
    board->occupied[moving_piece_color] &= ~get_bit(to);

    int pawn_type = (moving_piece_color == 0) ? WHITE_PAWN : BLACK_PAWN;
    board->pieces[pawn_type] |= get_bit(from);
    board->occupied[moving_piece_color] |= get_bit(from);
  } else {

    board->pieces[piece_type_at_to] &= ~get_bit(to);
    board->occupied[moving_piece_color] &= ~get_bit(to);
    board->pieces[piece_type_at_to] |= get_bit(from);
    board->occupied[moving_piece_color] |= get_bit(from);
  }

  if (info->captured_piece_type != -1) {
    board->pieces[info->captured_piece_type] |= get_bit(info->captured_square);
    int captured_color = (info->captured_piece_type < 6) ? 0 : 1;
    board->occupied[captured_color] |= get_bit(info->captured_square);
  }

  int king_piece = (moving_piece_color == 0) ? WHITE_KING : BLACK_KING;
  if (piece_type_at_to == king_piece && abs(from - to) == 2) {
    int rook_piece = (moving_piece_color == 0) ? WHITE_ROOK : BLACK_ROOK;
    if (to == from + 2) {

      board->pieces[rook_piece] &= ~get_bit(from + 1);
      board->occupied[moving_piece_color] &= ~get_bit(from + 1);
      board->pieces[rook_piece] |= get_bit(from + 3);
      board->occupied[moving_piece_color] |= get_bit(from + 3);
    } else {

      board->pieces[rook_piece] &= ~get_bit(from - 1);
      board->occupied[moving_piece_color] &= ~get_bit(from - 1);
      board->pieces[rook_piece] |= get_bit(from - 4);
      board->occupied[moving_piece_color] |= get_bit(from - 4);
    }
  }

  if (move->promotion == 0 &&
      (piece_type_at_to == WHITE_PAWN || piece_type_at_to == BLACK_PAWN) &&
      info->captured_piece_type != -1 &&
      (info->captured_piece_type == WHITE_PAWN ||
       info->captured_piece_type == BLACK_PAWN) &&
      info->captured_square != to) {

    int captured_color = (info->captured_piece_type < 6) ? 0 : 1;
    board->occupied[captured_color] |= get_bit(info->captured_square);
  }
}

static int generate_legal_moves_bitboard(Board *board, Move *moves) {
  const int color = (board->turn == 'w') ? 0 : 1;
  const Bitboard own = board->occupied[color];
  const Bitboard enemy = board->occupied[1 - color];
  const Bitboard occ = own | enemy;

  int ep_sq = -1;
  if (board->en_passant[0] != '-') {
    ep_sq =
        square_to_index(board->en_passant[0] - 'a', board->en_passant[1] - '1');
  }

  int move_count = 0;

  for (int piece = color * 6; piece < (color + 1) * 6; ++piece) {
    Bitboard bb = board->pieces[piece];

    while (bb) {
      const int from = get_lsb(bb);
      Bitboard attacks = 0ULL;

      switch (piece % 6) {

      case 0: {
        int file, rank;
        index_to_square(from, &file, &rank);

        const int dir = (color == 0) ? 1 : -1;
        const int start_rank = (color == 0) ? 1 : 6;

        int fwd = from + dir * 8;
        if (!(occ & get_bit(fwd))) {
          attacks |= get_bit(fwd);

          if (rank == start_rank) {
            int fwd2 = fwd + dir * 8;
            if (!(occ & get_bit(fwd2)))
              attacks |= get_bit(fwd2);
          }
        }

        const Bitboard pawn_atks = generate_pawn_attacks(from, color);
        attacks |= pawn_atks & enemy;

        if (ep_sq >= 0 && (pawn_atks & get_bit(ep_sq)))
          attacks |= get_bit(ep_sq);
        break;
      }

      case 1:
        attacks = KNIGHT_ATTACKS[from] & ~own;
        break;
      case 2:
        attacks = generate_bishop_attacks(from, occ) & ~own;
        break;
      case 3:
        attacks = generate_rook_attacks(from, occ) & ~own;
        break;
      case 4:
        attacks = (generate_bishop_attacks(from, occ) |
                   generate_rook_attacks(from, occ)) &
                  ~own;
        break;

      case 5: {
        attacks = KING_ATTACKS[from] & ~own;
        const int king_start =
            (color == 0) ? WHITE_KING_START : BLACK_KING_START;

        if (from == king_start && !is_square_attacked(board, from, 1 - color)) {

          if (strchr(board->castling, color ? 'k' : 'K') &&
              !(occ & (get_bit(from + 1) | get_bit(from + 2))) &&
              !is_square_attacked(board, from + 1, 1 - color) &&
              !is_square_attacked(board, from + 2, 1 - color))
            attacks |= get_bit(from + 2);

          if (strchr(board->castling, color ? 'q' : 'Q') &&
              !(occ &
                (get_bit(from - 1) | get_bit(from - 2) | get_bit(from - 3))) &&
              !is_square_attacked(board, from - 1, 1 - color) &&
              !is_square_attacked(board, from - 2, 1 - color))
            attacks |= get_bit(from - 2);
        }
        break;
      }
      }

      while (attacks) {
        const int to = get_lsb(attacks);
        const int to_rank = to / 8;
        const bool is_pawn = (piece % 6 == 0);

        const char promos[4] = {'q', 'r', 'b', 'n'};
        const int promo_needed = is_pawn && ((color == 0 && to_rank == 7) ||
                                             (color == 1 && to_rank == 0));

        const int variants = promo_needed ? 4 : 1;
        for (int v = 0; v < variants; ++v) {
          Move m = {from, to, promo_needed ? promos[v] : 0};

          MoveInfo info = make_move_bitboard(board, &m);
          if (!is_king_in_check(board, color)) {
            moves[move_count++] = m;
          }
          unmake_move_bitboard(board, &m, &info);
        }

        pop_lsb(&attacks);
      }

      pop_lsb(&bb);
    }
  }
  return move_count;
}

static void update_game_result(WambleBoard *wamble_board) {
  Board *board = &wamble_board->board;
  int color = (board->turn == 'w') ? 0 : 1;

  Move legal_moves[256];
  int num_legal_moves = generate_legal_moves_bitboard(board, legal_moves);

  if (num_legal_moves == 0) {
    if (is_king_in_check(board, color)) {
      wamble_board->result =
          (color == 0) ? GAME_RESULT_BLACK_WINS : GAME_RESULT_WHITE_WINS;
    } else {
      wamble_board->result = GAME_RESULT_DRAW;
    }
  } else if (board->halfmove_clock >= 100) {
    wamble_board->result = GAME_RESULT_DRAW;
  }
}

int parse_fen_to_bitboard(const char *fen, Board *board) {
  memset(board, 0, sizeof(Board));

  const char *p = fen;
  int square = 56;

  while (*p && *p != ' ') {
    if (*p == '/') {
      square -= 16;
    } else if (isdigit(*p)) {
      square += *p - '0';
    } else {
      int piece_type = -1;
      switch (*p) {
      case 'P':
        piece_type = WHITE_PAWN;
        break;
      case 'N':
        piece_type = WHITE_KNIGHT;
        break;
      case 'B':
        piece_type = WHITE_BISHOP;
        break;
      case 'R':
        piece_type = WHITE_ROOK;
        break;
      case 'Q':
        piece_type = WHITE_QUEEN;
        break;
      case 'K':
        piece_type = WHITE_KING;
        break;
      case 'p':
        piece_type = BLACK_PAWN;
        break;
      case 'n':
        piece_type = BLACK_KNIGHT;
        break;
      case 'b':
        piece_type = BLACK_BISHOP;
        break;
      case 'r':
        piece_type = BLACK_ROOK;
        break;
      case 'q':
        piece_type = BLACK_QUEEN;
        break;
      case 'k':
        piece_type = BLACK_KING;
        break;
      }

      if (piece_type != -1) {
        board->pieces[piece_type] |= get_bit(square);
        int color = piece_type < 6 ? 0 : 1;
        board->occupied[color] |= get_bit(square);
      }
      square++;
    }
    p++;
  }
  p++;

  board->turn = *p;
  p += 2;

  int i = 0;
  while (*p && *p != ' ') {
    board->castling[i++] = *p++;
  }
  board->castling[i] = '\0';
  p++;

  i = 0;
  while (*p && *p != ' ') {
    board->en_passant[i++] = *p++;
  }
  board->en_passant[i] = '\0';
  p++;

  board->halfmove_clock = strtol(p, (char **)&p, 10);
  board->fullmove_number = strtol(p, NULL, 10);

  return 0;
}

static void int_to_str(char *buf, int val) {
  int i = 0;
  int is_negative = 0;

  if (val == 0) {
    buf[i++] = '0';
    buf[i] = '\0';
    return;
  }

  if (val < 0) {
    is_negative = 1;
    val = -val;
  }

  while (val != 0) {
    buf[i++] = (val % 10) + '0';
    val /= 10;
  }

  if (is_negative) {
    buf[i++] = '-';
  }

  buf[i] = '\0';

  int start = 0;
  int end = i - 1;
  while (start < end) {
    char temp = buf[start];
    buf[start] = buf[end];
    buf[end] = temp;
    start++;
    end--;
  }
}

void bitboard_to_fen(const Board *board, char *fen) {
  char *fen_ptr = fen;

  for (int rank = 7; rank >= 0; rank--) {
    int empty_count = 0;
    for (int file = 0; file < 8; file++) {
      int square = square_to_index(file, rank);
      char piece = '.';

      for (int p = 0; p < 12; p++) {
        if (board->pieces[p] & get_bit(square)) {
          const char piece_chars[] = "PNBRQKpnbrqk";
          piece = piece_chars[p];
          break;
        }
      }

      if (piece == '.') {
        empty_count++;
      } else {
        if (empty_count > 0) {
          *fen_ptr++ = empty_count + '0';
          empty_count = 0;
        }
        *fen_ptr++ = piece;
      }
    }

    if (empty_count > 0) {
      *fen_ptr++ = empty_count + '0';
    }

    if (rank > 0) {
      *fen_ptr++ = '/';
    }
  }

  *fen_ptr++ = ' ';
  *fen_ptr++ = board->turn;
  *fen_ptr++ = ' ';

  if (strlen(board->castling) > 0) {
    strcpy(fen_ptr, board->castling);
  } else {
    strcpy(fen_ptr, "-");
  }
  fen_ptr += strlen(fen_ptr);

  *fen_ptr++ = ' ';

  if (strlen(board->en_passant) > 0) {
    strcpy(fen_ptr, board->en_passant);
  } else {
    strcpy(fen_ptr, "-");
  }
  fen_ptr += strlen(fen_ptr);

  *fen_ptr++ = ' ';
  char num_buf[10];
  int_to_str(num_buf, board->halfmove_clock);
  strcpy(fen_ptr, num_buf);
  fen_ptr += strlen(fen_ptr);

  *fen_ptr++ = ' ';
  int_to_str(num_buf, board->fullmove_number);
  strcpy(fen_ptr, num_buf);
  fen_ptr += strlen(fen_ptr);

  *fen_ptr = '\0';
}

int validate_and_apply_move(WambleBoard *wamble_board, WamblePlayer *player,
                            const char *uci_move) {
  if (!wamble_board || !uci_move || !player) {
    return -1;
  }

  if (!tokens_equal(wamble_board->reservation_player_token, player->token)) {
    return -1;
  }

  bool is_white_turn = (wamble_board->board.turn == 'w');
  if (wamble_board->reserved_for_white != is_white_turn) {
    return -1;
  }

  Board *board = &wamble_board->board;
  int from, to;
  if (uci_to_squares(uci_move, &from, &to) != 0) {
    return -1;
  }
  char promotion = (strlen(uci_move) == 5) ? tolower(uci_move[4]) : 0;
  Move candidate_move = {from, to, promotion};

  Move legal_moves[256];
  int num_legal = generate_legal_moves_bitboard(board, legal_moves);

  int move_is_legal = 0;
  for (int i = 0; i < num_legal; i++) {
    if (legal_moves[i].from == from && legal_moves[i].to == to &&
        legal_moves[i].promotion == promotion) {
      move_is_legal = 1;
      break;
    }
  }
  if (!move_is_legal) {
    return -1;
  }

  make_move_bitboard(board, &candidate_move);

  uint64_t session_id = db_get_session_by_token(player->token);
  if (session_id > 0) {
    db_record_move(wamble_board->id, session_id, uci_move,
                   board->fullmove_number);
  }

  bitboard_to_fen(board, wamble_board->fen);

  db_update_board(wamble_board->id, wamble_board->fen, "ACTIVE");

  update_game_result(wamble_board);

  if (wamble_board->result != GAME_RESULT_IN_PROGRESS) {
    update_player_ratings(wamble_board);
    calculate_and_distribute_pot(wamble_board->id);
    archive_board(wamble_board->id);
  }

  return 0;
}