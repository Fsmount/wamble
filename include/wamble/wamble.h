#ifndef WAMBLE_H
#define WAMBLE_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#define FEN_MAX_LENGTH 90
#define MAX_UCI_LENGTH 6
#define TOKEN_LENGTH 16
#define STATUS_MAX_LENGTH 17

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

typedef struct WamblePlayer {
  uint8_t token[TOKEN_LENGTH];
  uint8_t public_key[32];
  bool has_persistent_identity;
  time_t last_seen_time;
  double score;
  int games_played;
} WamblePlayer;

typedef struct WambleBoard {
  char fen[FEN_MAX_LENGTH];
  Board board;
  uint64_t id;
  BoardState state;
  GameResult result;
  time_t last_move_time;
  time_t creation_time;
  time_t last_assignment_time;
  uint8_t reservation_player_token[TOKEN_LENGTH];
  bool reserved_for_white;
  time_t reservation_time;
} WambleBoard;

int validate_and_apply_move(WambleBoard *wamble_board, WamblePlayer *player,
                            const char *uci_move);

int parse_fen_to_bitboard(const char *fen, Board *board);
void bitboard_to_fen(const Board *board, char *fen);

MoveInfo make_move_bitboard(Board *board, const Move *move);
void unmake_move_bitboard(Board *board, const Move *move, const MoveInfo *info);

static inline int square_to_index(int file, int rank);
static inline void index_to_square(int index, int *file, int *rank);

typedef enum { GAME_PHASE_EARLY, GAME_PHASE_MID, GAME_PHASE_END } GamePhase;

#define GAME_PHASE_EARLY_THRESHOLD 10
#define GAME_PHASE_MID_THRESHOLD 30

#define NEW_PLAYER_GAMES_THRESHOLD 10

typedef struct WambleMove {
  uint64_t id;
  uint64_t board_id;
  uint8_t player_token[TOKEN_LENGTH];
  char uci_move[MAX_UCI_LENGTH];
  time_t timestamp;
  bool is_white_move;
} WambleMove;

void board_manager_init(void);
WambleBoard *find_board_for_player(WamblePlayer *player);
void release_board(uint64_t board_id);
void archive_board(uint64_t board_id);
void update_player_ratings(WambleBoard *board);
int get_moves_for_board(uint64_t board_id, WambleMove **moves);
WambleBoard *get_board_by_id(uint64_t board_id);

WamblePlayer *get_player_by_id(uint64_t player_id);
int start_board_manager_thread(void);

void calculate_and_distribute_pot(uint64_t board_id);

void player_manager_init(void);
WamblePlayer *find_player_by_token(const uint8_t *token);
WamblePlayer *create_new_player(void);
void format_token_for_url(const uint8_t *token, char *url_buffer);
int decode_token_from_url(const char *url_string, uint8_t *token_buffer);
void player_manager_tick(void);

WamblePlayer *get_player_by_token(const uint8_t *token);
void create_player(uint8_t *token);

void start_network_listener(void);
void send_response(const struct WambleMsg *msg);

GamePhase get_game_phase(WambleBoard *board);

int db_init(const char *connection_string);
void db_cleanup(void);

uint64_t db_create_session(const uint8_t *token, uint64_t player_id);
uint64_t db_get_session_by_token(const uint8_t *token);
void db_update_session_last_seen(uint64_t session_id);

uint64_t db_create_board(const char *fen);
int db_update_board(uint64_t board_id, const char *fen, const char *status);
int db_get_board(uint64_t board_id, char *fen_out, char *status_out);
int db_get_boards_by_status(const char *status, uint64_t *board_ids,
                            int max_boards);

int db_record_move(uint64_t board_id, uint64_t session_id, const char *move_uci,
                   int move_number);
int db_get_moves_for_board(uint64_t board_id, WambleMove *moves_out,
                           int max_moves);

int db_create_reservation(uint64_t board_id, uint64_t session_id,
                          int timeout_seconds);
void db_cleanup_expired_reservations(void);
void db_remove_reservation(uint64_t board_id);

int db_record_game_result(uint64_t board_id, char winning_side);
int db_record_payout(uint64_t board_id, uint64_t session_id, double points);
double db_get_player_total_score(uint64_t session_id);

int db_get_active_session_count(void);
int db_get_longest_game_moves(void);
int db_get_session_games_played(uint64_t session_id);

void db_expire_reservations(void);
void db_archive_inactive_boards(int timeout_seconds);

#endif