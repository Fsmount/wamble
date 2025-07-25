#ifndef WAMBLE_H
#define WAMBLE_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#define FEN_MAX_LENGTH 90
#define MAX_UCI_LENGTH 6
#define TOKEN_LENGTH 16

#define get_bit(square) (1ULL << (square))
#define get_square(file, rank) ((rank) * 8 + (file))

#define KINGSIDE_CASTLE (1 << 0)
#define QUEENSIDE_CASTLE (1 << 1)

typedef unsigned long long Bitboard;

#define WHITE_PAWN 0
#define WHITE_KNIGHT 1
#define WHITE_BISHOP 2
#define WHITE_ROOK 3
#define WHITE_QUEEN 4
#define WHITE_KING 5
#define BLACK_PAWN 6
#define BLACK_KNIGHT 7
#define BLACK_BISHOP 8
#define BLACK_ROOK 9
#define BLACK_QUEEN 10
#define BLACK_KING 11

#define WHITE_KING_START 4
#define BLACK_KING_START 60

typedef struct {
  int from;
  int to;
  char promotion;
} Move;

typedef struct {
  int captured_piece_type;
  int captured_square;
  char prev_en_passant[3];
  char prev_castling[5];
  int prev_halfmove_clock;
  int prev_fullmove_number;
  int moving_piece_color;
} MoveInfo;

typedef struct {
  Bitboard pieces[12];
  Bitboard occupied[2];
  char turn;
  char castling[5];
  char en_passant[3];
  int halfmove_clock;
  int fullmove_number;
} Board;

typedef enum {
  BOARD_STATE_ACTIVE,
  BOARD_STATE_RESERVED,
  BOARD_STATE_DORMANT,
  BOARD_STATE_ARCHIVED
} BoardState;

typedef enum {
  GAME_RESULT_IN_PROGRESS,
  GAME_RESULT_WHITE_WINS,
  GAME_RESULT_BLACK_WINS,
  GAME_RESULT_DRAW
} GameResult;

#pragma pack(push, 1)
struct WambleMsg {
  uint8_t ctrl;
  uint8_t token[TOKEN_LENGTH];
  uint64_t board_id;
  uint8_t uci_len;
  char uci[MAX_UCI_LENGTH];
};
#pragma pack(pop)

typedef struct WambleBoard {
  char fen[FEN_MAX_LENGTH];
  Board board;
  uint64_t id;
  BoardState state;
  GameResult result;
  time_t last_move_time;
  uint64_t reservation_player_id;
  time_t reservation_time;
} WambleBoard;

int validate_and_apply_move(Board *board, const char *uci_move);

int parse_fen_to_bitboard(const char *fen, Board *board);
void bitboard_to_fen(const Board *board, char *fen);

MoveInfo make_move_bitboard(Board *board, const Move *move);
void unmake_move_bitboard(Board *board, const Move *move, const MoveInfo *info);

static inline int square_to_index(int file, int rank);
static inline void index_to_square(int index, int *file, int *rank);

typedef struct {
  uint64_t id;
  uint64_t board_id;
  uint64_t player_id;
  char uci_move[MAX_UCI_LENGTH];
  time_t timestamp;
} WambleMove;

typedef struct {
  uint64_t id;
  uint8_t token[TOKEN_LENGTH];
  uint8_t public_key[32];
} WamblePlayer;

void board_manager_init(void);
WambleBoard *get_or_create_board(void);
void release_board(uint64_t board_id);
void archive_board(uint64_t board_id);

void calculate_and_distribute_pot(uint64_t board_id);

WamblePlayer *get_player_by_token(const uint8_t *token);
void create_player(uint8_t *token);

void start_network_listener(void);
void send_response(const struct WambleMsg *msg);

#endif
