#ifndef WAMBLE_H
#define WAMBLE_H

#include <stdint.h>
#include <time.h>

#define FEN_MAX_LENGTH 90
#define MAX_UCI_LENGTH 6
#define TOKEN_LENGTH 16

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

typedef struct {
  uint64_t id;
  char fen[FEN_MAX_LENGTH];
  BoardState state;
  GameResult result;
  time_t last_move_time;
  uint64_t reservation_player_id;
  time_t reservation_time;
} WambleBoard;

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
int validate_and_apply_move(WambleBoard *board, const char *uci_move);

void board_manager_init();
WambleBoard *get_or_create_board();
void release_board(uint64_t board_id);
void archive_board(uint64_t board_id);

void calculate_and_distribute_pot(uint64_t board_id);

WamblePlayer *get_player_by_token(const uint8_t *token);
void create_player(uint8_t *token);

void start_network_listener();
void send_response(const struct WambleMsg *msg);

#endif
