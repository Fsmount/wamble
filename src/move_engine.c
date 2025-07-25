#include "../include/wamble/wamble.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BOARD_SIZE 8

typedef struct {
  int x, y;
} Coord;

typedef struct {
  Coord from;
  Coord to;
  char promotion;
} Move;

static int uci_to_coords(const char *uci, Coord *from, Coord *to);
static int is_square_attacked(const char board[BOARD_SIZE][BOARD_SIZE], int x,
                              int y, char attacker_color);
static void find_king(const char board[BOARD_SIZE][BOARD_SIZE], char color,
                      int *king_x, int *king_y);
static void make_move(char board[BOARD_SIZE][BOARD_SIZE], const Move *move);
static int generate_legal_moves(const char board[BOARD_SIZE][BOARD_SIZE],
                                char turn, const char *castling,
                                const char *en_passant, Move *legal_moves);
static int parse_fen(const char *fen, char board[BOARD_SIZE][BOARD_SIZE],
                     char *turn, char *castling, char *en_passant);
static void generate_fen(char *fen_str,
                         const char board[BOARD_SIZE][BOARD_SIZE], char turn,
                         const char *castling, const char *en_passant);
static void apply_move_to_state(char board[BOARD_SIZE][BOARD_SIZE], char *turn,
                                char *castling, char *en_passant,
                                const Move *move);

int validate_and_apply_move(WambleBoard *wamble_board, const char *uci_move) {
  if (!wamble_board || !uci_move) {
    return -1;
  }

  char board[BOARD_SIZE][BOARD_SIZE];
  char turn;
  char castling[5];
  char en_passant[3];
  Move legal_moves[256];
  int num_legal_moves;

  if (parse_fen(wamble_board->fen, board, &turn, castling, en_passant) != 0) {
    return -1;
  }

  num_legal_moves =
      generate_legal_moves(board, turn, castling, en_passant, legal_moves);

  Coord from, to;
  if (uci_to_coords(uci_move, &from, &to) != 0) {
    return -1;
  }

  char promotion_piece = (strlen(uci_move) == 5) ? tolower(uci_move[4]) : 0;

  int move_is_legal = 0;
  Move valid_move;
  for (int i = 0; i < num_legal_moves; i++) {
    if (legal_moves[i].from.x == from.x && legal_moves[i].from.y == from.y &&
        legal_moves[i].to.x == to.x && legal_moves[i].to.y == to.y &&
        legal_moves[i].promotion == promotion_piece) {
      move_is_legal = 1;
      valid_move = legal_moves[i];
      break;
    }
  }

  if (!move_is_legal) {
    return -1;
  }

  apply_move_to_state(board, &turn, castling, en_passant, &valid_move);

  generate_fen(wamble_board->fen, board, turn, castling, en_passant);
  wamble_board->last_move_time = time(NULL);
  wamble_board->result = GAME_RESULT_IN_PROGRESS;

  return 0;
}

static int uci_to_coords(const char *uci, Coord *from, Coord *to) {
  if (strlen(uci) < 4)
    return -1;
  from->x = uci[0] - 'a';
  from->y = uci[1] - '1';
  to->x = uci[2] - 'a';
  to->y = uci[3] - '1';
  if (from->x < 0 || from->x >= 8 || from->y < 0 || from->y >= 8 || to->x < 0 ||
      to->x >= 8 || to->y < 0 || to->y >= 8) {
    return -1;
  }
  return 0;
}

static void find_king(const char board[BOARD_SIZE][BOARD_SIZE], char color,
                      int *king_x, int *king_y) {
  char king_char = (color == 'w') ? 'K' : 'k';
  for (int y = 0; y < BOARD_SIZE; y++) {
    for (int x = 0; x < BOARD_SIZE; x++) {
      if (board[y][x] == king_char) {
        *king_x = x;
        *king_y = y;
        return;
      }
    }
  }
}

static int is_square_attacked(const char board[BOARD_SIZE][BOARD_SIZE], int x,
                              int y, char attacker_color) {

  int dx[] = {-1, -1, -1, 0, 0, 1, 1, 1};
  int dy[] = {-1, 0, 1, -1, 1, -1, 0, 1};
  int nx, ny;

  for (int i = 0; i < 8; ++i) {
    nx = x + dx[i];
    ny = y + dy[i];
    if (nx >= 0 && nx < 8 && ny >= 0 && ny < 8 &&
        board[ny][nx] == ((attacker_color == 'w') ? 'K' : 'k'))
      return 1;
  }

  int kn_dx[] = {-2, -2, -1, -1, 1, 1, 2, 2};
  int kn_dy[] = {-1, 1, -2, 2, -2, 2, -1, 1};

  for (int i = 0; i < 8; ++i) {
    nx = x + kn_dx[i];
    ny = y + kn_dy[i];
    if (nx >= 0 && nx < 8 && ny >= 0 && ny < 8 &&
        board[ny][nx] == ((attacker_color == 'w') ? 'N' : 'n'))
      return 1;
  }

  int pawn_dir = (attacker_color == 'w') ? 1 : -1;
  if (y - pawn_dir >= 0 && y - pawn_dir < 8) {
    if (x > 0 &&
        board[y - pawn_dir][x - 1] == ((attacker_color == 'w') ? 'P' : 'p'))
      return 1;
    if (x < 7 &&
        board[y - pawn_dir][x + 1] == ((attacker_color == 'w') ? 'P' : 'p'))
      return 1;
  }

  static const int ROOK_ATTACK_DX[] = {-1, 1, 0, 0};
  static const int ROOK_ATTACK_DY[] = {0, 0, -1, 1};

  for (int i = 0; i < 4; ++i) {
    nx = x;
    ny = y;
    while (1) {
      nx += ROOK_ATTACK_DX[i];
      ny += ROOK_ATTACK_DY[i];
      if (nx < 0 || nx >= 8 || ny < 0 || ny >= 8)
        break;
      if (board[ny][nx] != '.') {
        if (board[ny][nx] == ((attacker_color == 'w') ? 'R' : 'r') ||
            board[ny][nx] == ((attacker_color == 'w') ? 'Q' : 'q'))
          return 1;
        break;
      }
    }
  }

  static const int BISHOP_ATTACK_DX[] = {-1, -1, 1, 1};
  static const int BISHOP_ATTACK_DY[] = {-1, 1, -1, 1};

  for (int i = 0; i < 4; ++i) {
    nx = x;
    ny = y;
    while (1) {
      nx += BISHOP_ATTACK_DX[i];
      ny += BISHOP_ATTACK_DY[i];
      if (nx < 0 || nx >= 8 || ny < 0 || ny >= 8)
        break;
      if (board[ny][nx] != '.') {
        if (board[ny][nx] == ((attacker_color == 'w') ? 'B' : 'b') ||
            board[ny][nx] == ((attacker_color == 'w') ? 'Q' : 'q'))
          return 1;
        break;
      }
    }
  }
  return 0;
}

static void make_move(char board[BOARD_SIZE][BOARD_SIZE], const Move *move) {
  char piece = board[move->from.y][move->from.x];
  char final_piece = piece;

  if (move->promotion) {
    final_piece =
        (isupper(piece)) ? toupper(move->promotion) : tolower(move->promotion);
  }

  board[move->to.y][move->to.x] = final_piece;

  board[move->from.y][move->from.x] = '.';

  if (toupper(piece) == 'K' && abs(move->from.x - move->to.x) == 2) {
    if (move->to.x == 6) {
      board[move->from.y][5] = board[move->from.y][7];
      board[move->from.y][7] = '.';
    } else {
      board[move->from.y][3] = board[move->from.y][0];
      board[move->from.y][0] = '.';
    }
  }
}

static int generate_pawn_moves(const char board[BOARD_SIZE][BOARD_SIZE], int x,
                               int y, char turn, const char *en_passant,
                               Move *moves) {
  int count = 0;
  int dir = (turn == 'w') ? 1 : -1;
  int start_row = (turn == 'w') ? 1 : 6;

  if (y + dir < 0 || y + dir >= 8)
    return 0;

  if (board[y + dir][x] == '.') {

    if ((turn == 'w' && y + dir == 7) || (turn == 'b' && y + dir == 0)) {
      moves[count++] = (Move){{x, y}, {x, y + dir}, 'q'};
      moves[count++] = (Move){{x, y}, {x, y + dir}, 'r'};
      moves[count++] = (Move){{x, y}, {x, y + dir}, 'b'};
      moves[count++] = (Move){{x, y}, {x, y + dir}, 'n'};
    } else {
      moves[count++] = (Move){{x, y}, {x, y + dir}, 0};
    }

    if (y == start_row && board[y + 2 * dir][x] == '.') {
      moves[count++] = (Move){{x, y}, {x, y + 2 * dir}, 0};
    }
  }

  for (int dx = -1; dx <= 1; dx += 2) {
    if (x + dx < 0 || x + dx >= 8)
      continue;

    char target = board[y + dir][x + dx];

    if (target != '.' && ((turn == 'w' && islower(target)) ||
                          (turn == 'b' && isupper(target)))) {

      if ((turn == 'w' && y + dir == 7) || (turn == 'b' && y + dir == 0)) {
        moves[count++] = (Move){{x, y}, {x + dx, y + dir}, 'q'};
        moves[count++] = (Move){{x, y}, {x + dx, y + dir}, 'r'};
        moves[count++] = (Move){{x, y}, {x + dx, y + dir}, 'b'};
        moves[count++] = (Move){{x, y}, {x + dx, y + dir}, 'n'};
      } else {
        moves[count++] = (Move){{x, y}, {x + dx, y + dir}, 0};
      }
    }

    if (en_passant[0] != '-') {
      int ep_x = en_passant[0] - 'a';
      int ep_y = en_passant[1] - '1';

      int captured_pawn_y = y;
      int captured_pawn_x = ep_x;
      char captured_pawn = board[captured_pawn_y][captured_pawn_x];

      if (ep_x == x + dx && ep_y == y + dir) {
        if ((turn == 'w' && captured_pawn == 'p') ||
            (turn == 'b' && captured_pawn == 'P')) {
          moves[count++] = (Move){{x, y}, {ep_x, ep_y}, 0};
        }
      }
    }
  }

  return count;
}

static int generate_sliding_moves(const char board[BOARD_SIZE][BOARD_SIZE],
                                  int x, int y, char turn, Move *moves,
                                  const int *dx, const int *dy, int num_dirs) {
  int count = 0;
  for (int i = 0; i < num_dirs; i++) {
    for (int step = 1; step < BOARD_SIZE; step++) {
      int nx = x + dx[i] * step;
      int ny = y + dy[i] * step;
      if (nx < 0 || nx >= 8 || ny < 0 || ny >= 8)
        break;
      char target = board[ny][nx];
      if (target == '.') {
        moves[count++] = (Move){{x, y}, {nx, ny}, 0};
      } else {
        if ((turn == 'w' && islower(target)) ||
            (turn == 'b' && isupper(target))) {
          moves[count++] = (Move){{x, y}, {nx, ny}, 0};
        }
        break;
      }
    }
  }
  return count;
}

static int generate_rook_moves(const char board[BOARD_SIZE][BOARD_SIZE], int x,
                               int y, char turn, Move *moves) {
  const int dx[] = {0, 0, 1, -1};
  const int dy[] = {1, -1, 0, 0};
  return generate_sliding_moves(board, x, y, turn, moves, dx, dy, 4);
}

static int generate_bishop_moves(const char board[BOARD_SIZE][BOARD_SIZE],
                                 int x, int y, char turn, Move *moves) {
  const int dx[] = {1, 1, -1, -1};
  const int dy[] = {1, -1, 1, -1};
  return generate_sliding_moves(board, x, y, turn, moves, dx, dy, 4);
}

static int generate_queen_moves(const char board[BOARD_SIZE][BOARD_SIZE], int x,
                                int y, char turn, Move *moves) {
  int count = 0;
  count += generate_rook_moves(board, x, y, turn, &moves[count]);
  count += generate_bishop_moves(board, x, y, turn, &moves[count]);
  return count;
}

static int generate_knight_moves(const char board[BOARD_SIZE][BOARD_SIZE],
                                 int x, int y, char turn, Move *moves) {
  int count = 0;
  const int dx[] = {1, 1, 2, 2, -1, -1, -2, -2};
  const int dy[] = {2, -2, 1, -1, 2, -2, 1, -1};
  for (int i = 0; i < 8; i++) {
    int nx = x + dx[i];
    int ny = y + dy[i];
    if (nx >= 0 && nx < 8 && ny >= 0 && ny < 8) {
      char target = board[ny][nx];
      if (target == '.' || (turn == 'w' && islower(target)) ||
          (turn == 'b' && isupper(target))) {
        moves[count++] = (Move){{x, y}, {nx, ny}, 0};
      }
    }
  }
  return count;
}

static int generate_king_moves(const char board[BOARD_SIZE][BOARD_SIZE], int x,
                               int y, char turn, const char *castling,
                               Move *moves) {
  int count = 0;
  const int dx[] = {0, 0, 1, -1, 1, 1, -1, -1};
  const int dy[] = {1, -1, 0, 0, 1, -1, 1, -1};
  for (int i = 0; i < 8; i++) {
    int nx = x + dx[i];
    int ny = y + dy[i];
    if (nx >= 0 && nx < 8 && ny >= 0 && ny < 8) {
      char target = board[ny][nx];
      if (target == '.' || (turn == 'w' && islower(target)) ||
          (turn == 'b' && isupper(target))) {
        moves[count++] = (Move){{x, y}, {nx, ny}, 0};
      }
    }
  }

  char opponent_color = (turn == 'w') ? 'b' : 'w';

  if (turn == 'w') {

    if (strchr(castling, 'K') && board[0][5] == '.' && board[0][6] == '.' &&
        !is_square_attacked(board, 4, 0, opponent_color) &&
        !is_square_attacked(board, 5, 0, opponent_color) &&
        !is_square_attacked(board, 6, 0, opponent_color)) {
      moves[count++] = (Move){{4, 0}, {6, 0}, 0};
    }

    if (strchr(castling, 'Q') && board[0][1] == '.' && board[0][2] == '.' &&
        board[0][3] == '.' &&
        !is_square_attacked(board, 4, 0, opponent_color) &&
        !is_square_attacked(board, 3, 0, opponent_color) &&
        !is_square_attacked(board, 2, 0, opponent_color)) {
      moves[count++] = (Move){{4, 0}, {2, 0}, 0};
    }
  } else {

    if (strchr(castling, 'k') && board[7][5] == '.' && board[7][6] == '.' &&
        !is_square_attacked(board, 4, 7, opponent_color) &&
        !is_square_attacked(board, 5, 7, opponent_color) &&
        !is_square_attacked(board, 6, 7, opponent_color)) {
      moves[count++] = (Move){{4, 7}, {6, 7}, 0};
    }

    if (strchr(castling, 'q') && board[7][1] == '.' && board[7][2] == '.' &&
        board[7][3] == '.' &&
        !is_square_attacked(board, 4, 7, opponent_color) &&
        !is_square_attacked(board, 3, 7, opponent_color) &&
        !is_square_attacked(board, 2, 7, opponent_color)) {
      moves[count++] = (Move){{4, 7}, {2, 7}, 0};
    }
  }
  return count;
}

static void apply_move_to_state(char board[BOARD_SIZE][BOARD_SIZE], char *turn,
                                char *castling, char *en_passant,
                                const Move *move) {
  char piece = board[move->from.y][move->from.x];

  if (toupper(piece) == 'P' && board[move->to.y][move->to.x] == '.' &&
      abs(move->from.x - move->to.x) == 1) {
    if (*turn == 'w') {
      board[move->to.y - 1][move->to.x] = '.';
    } else {
      board[move->to.y + 1][move->to.x] = '.';
    }
  }

  strcpy(en_passant, "-");

  if (toupper(piece) == 'P' && abs(move->from.y - move->to.y) == 2) {
    en_passant[0] = move->from.x + 'a';
    en_passant[1] = (*turn == 'w') ? '3' : '6';
    en_passant[2] = '\0';
  }

  char new_castling[5] = "";
  int new_castling_idx = 0;
  char captured_piece = board[move->to.y][move->to.x];

  for (int i = 0; i < strlen(castling); i++) {
    if (castling[i] != '-') {
      int revoke = 0;

      if (toupper(piece) == 'K') {
        if (*turn == 'w') {
          if (castling[i] == 'K' || castling[i] == 'Q')
            revoke = 1;
        } else {
          if (castling[i] == 'k' || castling[i] == 'q')
            revoke = 1;
        }
      }

      else if (toupper(piece) == 'R') {
        if (*turn == 'w') {
          if (move->from.x == 0 && move->from.y == 0 && castling[i] == 'Q')
            revoke = 1;
          if (move->from.x == 7 && move->from.y == 0 && castling[i] == 'K')
            revoke = 1;
        } else {
          if (move->from.x == 0 && move->from.y == 7 && castling[i] == 'q')
            revoke = 1;
          if (move->from.x == 7 && move->from.y == 7 && castling[i] == 'k')
            revoke = 1;
        }
      }

      if (toupper(captured_piece) == 'R') {
        if (move->to.x == 0 && move->to.y == 0 && castling[i] == 'Q')
          revoke = 1;
        if (move->to.x == 7 && move->to.y == 0 && castling[i] == 'K')
          revoke = 1;
        if (move->to.x == 0 && move->to.y == 7 && castling[i] == 'q')
          revoke = 1;
        if (move->to.x == 7 && move->to.y == 7 && castling[i] == 'k')
          revoke = 1;
      }

      if (!revoke) {
        new_castling[new_castling_idx++] = castling[i];
      }
    }
  }
  new_castling[new_castling_idx] = '\0';
  strcpy(castling, new_castling);

  make_move(board, move);

  *turn = (*turn == 'w') ? 'b' : 'w';
}

static int generate_legal_moves(const char board[BOARD_SIZE][BOARD_SIZE],
                                char turn, const char *castling,
                                const char *en_passant, Move *legal_moves) {
  int pseudo_legal_count = 0;
  Move pseudo_legal_moves[256];

  for (int y = 0; y < BOARD_SIZE; y++) {
    for (int x = 0; x < BOARD_SIZE; x++) {
      char piece = board[y][x];
      if (piece == '.' || (turn == 'w' && islower(piece)) ||
          (turn == 'b' && isupper(piece))) {
        continue;
      }

      switch (toupper(piece)) {
      case 'P':
        pseudo_legal_count +=
            generate_pawn_moves(board, x, y, turn, en_passant,
                                &pseudo_legal_moves[pseudo_legal_count]);
        break;
      case 'R':
        pseudo_legal_count += generate_rook_moves(
            board, x, y, turn, &pseudo_legal_moves[pseudo_legal_count]);
        break;
      case 'N':
        pseudo_legal_count += generate_knight_moves(
            board, x, y, turn, &pseudo_legal_moves[pseudo_legal_count]);
        break;
      case 'B':
        pseudo_legal_count += generate_bishop_moves(
            board, x, y, turn, &pseudo_legal_moves[pseudo_legal_count]);
        break;
      case 'Q':
        pseudo_legal_count += generate_queen_moves(
            board, x, y, turn, &pseudo_legal_moves[pseudo_legal_count]);
        break;
      case 'K':
        pseudo_legal_count +=
            generate_king_moves(board, x, y, turn, castling,
                                &pseudo_legal_moves[pseudo_legal_count]);
        break;
      }
    }
  }

  int legal_count = 0;
  char temp_board[BOARD_SIZE][BOARD_SIZE];
  int king_x, king_y;
  char opponent_color = (turn == 'w') ? 'b' : 'w';

  for (int i = 0; i < pseudo_legal_count; i++) {
    memcpy(temp_board, board, sizeof(temp_board));
    make_move(temp_board, &pseudo_legal_moves[i]);
    find_king(temp_board, turn, &king_x, &king_y);
    if (!is_square_attacked(temp_board, king_x, king_y, opponent_color)) {
      legal_moves[legal_count++] = pseudo_legal_moves[i];
    }
  }
  return legal_count;
}

static int parse_fen(const char *fen, char board[BOARD_SIZE][BOARD_SIZE],
                     char *turn, char *castling, char *en_passant) {
  memset(board, '.', sizeof(char) * BOARD_SIZE * BOARD_SIZE);
  int x = 0, y = 7;
  const char *p = fen;

  while (*p && *p != ' ') {
    if (*p == '/') {
      y--;
      x = 0;
    } else if (isdigit(*p)) {
      x += *p - '0';
    } else {
      if (x < BOARD_SIZE && y >= 0)
        board[y][x++] = *p;
    }
    p++;
  }
  p++;

  *turn = *p;
  p += 2;

  int i = 0;
  while (*p && *p != ' ')
    castling[i++] = *p++;
  castling[i] = '\0';
  p++;

  i = 0;
  while (*p && *p != ' ')
    en_passant[i++] = *p++;
  en_passant[i] = '\0';

  return 0;
}

static void generate_fen(char *fen_str,
                         const char board[BOARD_SIZE][BOARD_SIZE], char turn,
                         const char *castling, const char *en_passant) {
  char *fen_ptr = fen_str;

  for (int y = 7; y >= 0; y--) {
    int empty_count = 0;
    for (int x = 0; x < BOARD_SIZE; x++) {
      if (board[y][x] == '.') {
        empty_count++;
      } else {
        if (empty_count > 0) {
          *fen_ptr++ = empty_count + '0';
          empty_count = 0;
        }
        *fen_ptr++ = board[y][x];
      }
    }
    if (empty_count > 0) {
      *fen_ptr++ = empty_count + '0';
    }
    if (y > 0) {
      *fen_ptr++ = '/';
    }
  }

  sprintf(fen_ptr, " %c %s %s 0 1", turn,
          (strlen(castling) > 0 ? castling : "-"),
          (strlen(en_passant) > 0 ? en_passant : "-"));
}
