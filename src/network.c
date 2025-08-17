#include "../include/wamble/wamble.h"
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int network_port = WAMBLE_DEFAULT_PORT;
static int network_timeout_ms = WAMBLE_DEFAULT_TIMEOUT_MS;
static int network_max_retries = WAMBLE_DEFAULT_MAX_RETRIES;

static WambleClientSession client_sessions[MAX_CLIENT_SESSIONS];
static int num_sessions = 0;
static uint32_t global_seq_num = 1;

void set_network_timeouts(int timeout_ms, int max_retries) {
  if (timeout_ms > 0)
    network_timeout_ms = timeout_ms;
  if (max_retries > 0)
    network_max_retries = max_retries;
}

static int addr_equal(const struct sockaddr_in *addr1,
                      const struct sockaddr_in *addr2) {
  return addr1->sin_addr.s_addr == addr2->sin_addr.s_addr &&
         addr1->sin_port == addr2->sin_port;
}

static WambleClientSession *
find_client_session(const struct sockaddr_in *addr) {
  for (int i = 0; i < num_sessions; i++) {
    if (addr_equal(&client_sessions[i].addr, addr)) {
      return &client_sessions[i];
    }
  }
  return NULL;
}

static WambleClientSession *
create_client_session(const struct sockaddr_in *addr, const uint8_t *token) {
  if (num_sessions >= MAX_CLIENT_SESSIONS) {
    return NULL;
  }

  WambleClientSession *session = &client_sessions[num_sessions++];
  session->addr = *addr;
  memcpy(session->token, token, TOKEN_LENGTH);
  session->last_seq_num = 0;
  session->last_seen = time(NULL);
  session->next_seq_num = 1;
  return session;
}

int validate_message(const struct WambleMsg *msg, size_t received_size) {

  if (received_size != sizeof(struct WambleMsg)) {
    return -1;
  }

  if (msg->ctrl != WAMBLE_CTRL_CLIENT_HELLO &&
      msg->ctrl != WAMBLE_CTRL_SERVER_HELLO &&
      msg->ctrl != WAMBLE_CTRL_PLAYER_MOVE &&
      msg->ctrl != WAMBLE_CTRL_BOARD_UPDATE && msg->ctrl != WAMBLE_CTRL_ACK) {
    return -1;
  }

  if (msg->uci_len > MAX_UCI_LENGTH) {
    return -1;
  }

  if (msg->ctrl != WAMBLE_CTRL_ACK) {
    int token_valid = 0;
    for (int i = 0; i < TOKEN_LENGTH; i++) {
      if (msg->token[i] != 0) {
        token_valid = 1;
        break;
      }
    }
    if (!token_valid) {
      return -1;
    }
  }

  return 0;
}

int is_duplicate_message(const struct sockaddr_in *addr, uint32_t seq_num) {
  WambleClientSession *session = find_client_session(addr);
  if (!session) {
    return 0;
  }

  return seq_num <= session->last_seq_num;
}

void update_client_session(const struct sockaddr_in *addr, const uint8_t *token,
                           uint32_t seq_num) {
  WambleClientSession *session = find_client_session(addr);
  if (!session) {
    session = create_client_session(addr, token);
    if (!session) {
      return;
    }
  }

  session->last_seq_num = seq_num;
  session->last_seen = time(NULL);
  memcpy(session->token, token, TOKEN_LENGTH);
}

int create_and_bind_socket_on_port(int port) {
  network_port = port;
  return create_and_bind_socket();
}

int create_and_bind_socket(void) {
  int sockfd;
  struct sockaddr_in servaddr;

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket creation failed");
    return -1;
  }

  int optval = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) <
      0) {
    perror("setsockopt SO_REUSEADDR failed");
  }

  int buffer_size = WAMBLE_BUFFER_SIZE;
  if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &buffer_size,
                 sizeof(buffer_size)) < 0) {
    perror("setsockopt SO_RCVBUF failed");
  }
  if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &buffer_size,
                 sizeof(buffer_size)) < 0) {
    perror("setsockopt SO_SNDBUF failed");
  }

  memset(&servaddr, 0, sizeof(servaddr));

  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = INADDR_ANY;
  servaddr.sin_port = htons(network_port);

  if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
    perror("bind failed");
    close(sockfd);
    return -1;
  }

  return sockfd;
}

int receive_message(int sockfd, struct WambleMsg *msg,
                    struct sockaddr_in *cliaddr) {
  socklen_t len = sizeof(*cliaddr);
  ssize_t bytes_received =
      recvfrom(sockfd, msg, sizeof(*msg), 0, (struct sockaddr *)cliaddr, &len);

  if (bytes_received <= 0) {
    return bytes_received;
  }

  if (validate_message(msg, bytes_received) != 0) {
    fprintf(stderr, "Received invalid message from client\n");
    return -1;
  }

  if (msg->ctrl != WAMBLE_CTRL_ACK &&
      is_duplicate_message(cliaddr, msg->seq_num)) {
    fprintf(stderr, "Received duplicate message (seq %u)\n", msg->seq_num);
    return -1;
  }

  if (msg->ctrl != WAMBLE_CTRL_ACK) {
    update_client_session(cliaddr, msg->token, msg->seq_num);
  }

  return bytes_received;
}

void send_ack(int sockfd, const struct WambleMsg *msg,
              const struct sockaddr_in *cliaddr) {
  struct WambleMsg ack_msg;
  ack_msg.ctrl = WAMBLE_CTRL_ACK;
  memcpy(ack_msg.token, msg->token, TOKEN_LENGTH);
  ack_msg.board_id = msg->board_id;
  ack_msg.seq_num = msg->seq_num;
  ack_msg.uci_len = 0;
  memset(ack_msg.uci, 0, MAX_UCI_LENGTH);
  memset(ack_msg.fen, 0, FEN_MAX_LENGTH);

  sendto(sockfd, &ack_msg, sizeof(ack_msg), 0, (const struct sockaddr *)cliaddr,
         sizeof(*cliaddr));
}

int wait_for_ack(int sockfd, uint32_t expected_seq, int timeout_ms) {
  fd_set readfds;
  struct timeval timeout;

  timeout.tv_sec = timeout_ms / 1000;
  timeout.tv_usec = (timeout_ms % 1000) * 1000;

  FD_ZERO(&readfds);
  FD_SET(sockfd, &readfds);

  int result = select(sockfd + 1, &readfds, NULL, NULL, &timeout);
  if (result <= 0) {
    return -1;
  }

  struct WambleMsg ack_msg;
  struct sockaddr_in cliaddr;
  socklen_t len = sizeof(cliaddr);

  int bytes_received = recvfrom(sockfd, &ack_msg, sizeof(ack_msg), 0,
                                (struct sockaddr *)&cliaddr, &len);

  if (bytes_received > 0 && ack_msg.ctrl == WAMBLE_CTRL_ACK &&
      ack_msg.seq_num == expected_seq) {
    return 0;
  }

  return -1;
}

int send_reliable_message(int sockfd, const struct WambleMsg *msg,
                          const struct sockaddr_in *cliaddr, int timeout_ms,
                          int max_retries) {
  if (timeout_ms <= 0)
    timeout_ms = network_timeout_ms;
  if (max_retries <= 0)
    max_retries = network_max_retries;

  struct WambleMsg reliable_msg = *msg;

  WambleClientSession *session = find_client_session(cliaddr);
  if (!session) {
    session = create_client_session(cliaddr, msg->token);
    if (!session) {

      reliable_msg.seq_num = global_seq_num++;
    } else {
      reliable_msg.seq_num = session->next_seq_num++;
    }
  } else {
    reliable_msg.seq_num = session->next_seq_num++;
  }

  for (int attempt = 0; attempt < max_retries; attempt++) {
    int bytes_sent = sendto(sockfd, &reliable_msg, sizeof(reliable_msg), 0,
                            (const struct sockaddr *)cliaddr, sizeof(*cliaddr));

    if (bytes_sent < 0) {
      perror("sendto failed");
      return -1;
    }

    if (wait_for_ack(sockfd, reliable_msg.seq_num, timeout_ms) == 0) {
      return 0;
    }

    fprintf(stderr, "Message timeout on attempt %d/%d (seq %u)\n", attempt + 1,
            max_retries, reliable_msg.seq_num);
  }

  return -1;
}

void start_network_listener(void) {
  printf("Network listener started on port %d\n", network_port);
  printf("Timeout: %dms, Max retries: %d\n", network_timeout_ms,
         network_max_retries);
}

void send_response(const struct WambleMsg *msg) {

  printf("Broadcasting response (ctrl: 0x%02x, seq: %u)\n", msg->ctrl,
         msg->seq_num);
}

void cleanup_expired_sessions(void) {
  time_t now = time(NULL);
  int write_idx = 0;

  for (int read_idx = 0; read_idx < num_sessions; read_idx++) {
    if (now - client_sessions[read_idx].last_seen < SESSION_TIMEOUT_SECONDS) {
      if (write_idx != read_idx) {
        client_sessions[write_idx] = client_sessions[read_idx];
      }
      write_idx++;
    }
  }

  if (write_idx != num_sessions) {
    printf("Cleaned up %d expired client sessions\n", num_sessions - write_idx);
    num_sessions = write_idx;
  }
}
