#include "../include/wamble/wamble.h"
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void handle_message(int sockfd, const struct WambleMsg *msg,
                    const struct sockaddr_in *cliaddr);

int main(int argc, char *argv[]) {
  if (db_init("dbname=wamble user=wamble password=wamble host=localhost") !=
      0) {
    fprintf(stderr, "Failed to initialize database\n");
    return 1;
  }

  player_manager_init();
  board_manager_init();

  if (start_board_manager_thread() != 0) {
    fprintf(stderr, "Failed to start board manager thread\n");
    return 1;
  }

  start_network_listener();

  int sockfd = create_and_bind_socket();
  if (sockfd < 0) {
    fprintf(stderr, "Failed to create and bind socket\n");
    return 1;
  }

  printf("Server listening on port %d\n", WAMBLE_DEFAULT_PORT);

  time_t last_cleanup = time(NULL);

  while (1) {
    struct WambleMsg msg;
    struct sockaddr_in cliaddr;
    int n = receive_message(sockfd, &msg, &cliaddr);
    if (n > 0) {
      handle_message(sockfd, &msg, &cliaddr);
    }

    time_t now = time(NULL);
    if (now - last_cleanup > 60) {
      cleanup_expired_sessions();
      last_cleanup = now;
    }
  }

  db_cleanup();

  return 0;
}

static void handle_client_hello(int sockfd, const struct WambleMsg *msg,
                                const struct sockaddr_in *cliaddr) {
  printf("Received Client Hello\n");

  WamblePlayer *player = get_player_by_token(msg->token);
  if (!player) {
    player = create_new_player();
    if (!player) {
      fprintf(stderr, "Failed to create new player\n");
      return;
    }
  }

  WambleBoard *board = find_board_for_player(player);
  if (!board) {
    fprintf(stderr, "Failed to find board for player\n");
    return;
  }

  struct WambleMsg response;
  response.ctrl = WAMBLE_CTRL_SERVER_HELLO;
  memcpy(response.token, player->token, TOKEN_LENGTH);
  response.board_id = board->id;
  response.seq_num = 0;
  response.uci_len = 0;
  strncpy(response.fen, board->fen, FEN_MAX_LENGTH);

  if (send_reliable_message(sockfd, &response, cliaddr, 100, 3) != 0) {
    fprintf(stderr, "Failed to send reliable response to client hello\n");
  }
}

static void handle_player_move(int sockfd, const struct WambleMsg *msg,
                               const struct sockaddr_in *cliaddr) {
  printf("Received Player Move\n");

  WamblePlayer *player = get_player_by_token(msg->token);
  if (!player) {
    fprintf(stderr, "Move from unknown player\n");
    return;
  }

  WambleBoard *board = get_board_by_id(msg->board_id);
  if (!board) {
    fprintf(stderr, "Move for unknown board: %lu\n", msg->board_id);
    return;
  }

  char uci_move[MAX_UCI_LENGTH + 1];
  uint8_t uci_len =
      msg->uci_len < MAX_UCI_LENGTH ? msg->uci_len : MAX_UCI_LENGTH;
  memcpy(uci_move, msg->uci, uci_len);
  uci_move[uci_len] = '\0';

  if (validate_and_apply_move(board, player, uci_move) == 0) {
    printf("Move %s on board %lu validated and applied\n", uci_move, board->id);

    release_board(board->id);

    if (board->result != GAME_RESULT_IN_PROGRESS) {
      printf("Game on board %lu has ended. Result: %d\n", board->id,
             board->result);
    }

    WambleBoard *next_board = find_board_for_player(player);
    if (!next_board) {
      fprintf(stderr, "Failed to find next board for player after move\n");
      return;
    }

    struct WambleMsg response;
    response.ctrl = WAMBLE_CTRL_BOARD_UPDATE;
    memcpy(response.token, player->token, TOKEN_LENGTH);
    response.board_id = next_board->id;
    response.seq_num = 0;
    response.uci_len = 0;
    strncpy(response.fen, next_board->fen, FEN_MAX_LENGTH);

    if (send_reliable_message(sockfd, &response, cliaddr, 100, 3) != 0) {
      fprintf(stderr, "Failed to send reliable response to player move\n");
    } else {
      printf("Player moved to new board %lu\n", next_board->id);
    }
  } else {
    fprintf(stderr, "Invalid move %s on board %lu by player\n", uci_move,
            board->id);
  }
}

void handle_message(int sockfd, const struct WambleMsg *msg,
                    const struct sockaddr_in *cliaddr) {

  if (msg->ctrl != WAMBLE_CTRL_ACK) {
    send_ack(sockfd, msg, cliaddr);
  }

  switch (msg->ctrl) {
  case WAMBLE_CTRL_CLIENT_HELLO:
    handle_client_hello(sockfd, msg, cliaddr);
    break;
  case WAMBLE_CTRL_PLAYER_MOVE:
    handle_player_move(sockfd, msg, cliaddr);
    break;
  case WAMBLE_CTRL_ACK:

    break;
  default:
    printf("Unknown message type: 0x%02x\n", msg->ctrl);
    break;
  }
}
