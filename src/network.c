#include "../include/wamble/wamble.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

static int network_port = WAMBLE_DEFAULT_PORT;
static int network_timeout_ms = WAMBLE_DEFAULT_TIMEOUT_MS;
static int network_max_retries = WAMBLE_DEFAULT_MAX_RETRIES;

static WambleClientSession client_sessions[MAX_CLIENT_SESSIONS];
static int num_sessions = 0;
static uint32_t global_seq_num = 1;

#define SESSION_MAP_SIZE (MAX_CLIENT_SESSIONS * 2)
static int session_index_map[SESSION_MAP_SIZE];

static inline uint64_t mix64_s(uint64_t x) {
  x ^= x >> 33;
  x *= 0xff51afd7ed558ccdULL;
  x ^= x >> 33;
  x *= 0xc4ceb9fe1a85ec53ULL;
  x ^= x >> 33;
  return x;
}

static inline uint64_t addr_hash_key(const struct sockaddr_in *addr) {
  uint64_t ip = (uint64_t)addr->sin_addr.s_addr;
  uint64_t port = (uint64_t)addr->sin_port;
  return mix64_s((ip << 16) ^ port);
}

static void session_map_init(void) {
  for (int i = 0; i < SESSION_MAP_SIZE; i++)
    session_index_map[i] = -1;
}

static void session_map_put(const struct sockaddr_in *addr, int index) {
  uint64_t h = addr_hash_key(addr);
  int mask = SESSION_MAP_SIZE - 1;
  int i = (int)(h & mask);
  for (int probe = 0; probe < SESSION_MAP_SIZE; probe++) {
    if (session_index_map[i] == -1) {
      session_index_map[i] = index;
      return;
    }
    int cur = session_index_map[i];
    if (cur >= 0) {
      const struct sockaddr_in *saddr = &client_sessions[cur].addr;
      if (saddr->sin_addr.s_addr == addr->sin_addr.s_addr &&
          saddr->sin_port == addr->sin_port) {
        session_index_map[i] = index;
        return;
      }
    }
    i = (i + 1) & mask;
  }
}

static int session_map_get(const struct sockaddr_in *addr) {
  uint64_t h = addr_hash_key(addr);
  int mask = SESSION_MAP_SIZE - 1;
  int i = (int)(h & mask);
  for (int probe = 0; probe < SESSION_MAP_SIZE; probe++) {
    int cur = session_index_map[i];
    if (cur == -1)
      return -1;
    if (cur >= 0) {
      const struct sockaddr_in *saddr = &client_sessions[cur].addr;
      if (saddr->sin_addr.s_addr == addr->sin_addr.s_addr &&
          saddr->sin_port == addr->sin_port)
        return cur;
    }
    i = (i + 1) & mask;
  }
  return -1;
}

static uint64_t host_to_net64(uint64_t host_val) {
  uint64_t net_val = 0;
  for (int i = 0; i < 8; i++) {
    net_val = (net_val << 8) | ((host_val >> (8 * i)) & 0xFF);
  }
  return net_val;
}

static uint64_t net_to_host64(uint64_t net_val) {
  uint64_t host_val = 0;
  for (int i = 0; i < 8; i++) {
    host_val = (host_val << 8) | ((net_val >> (8 * i)) & 0xFF);
  }
  return host_val;
}

int serialize_wamble_msg(const struct WambleMsg *msg, uint8_t *buffer) {
  uint8_t *ptr = buffer;

  *ptr++ = msg->ctrl;

  memcpy(ptr, msg->token, TOKEN_LENGTH);
  ptr += TOKEN_LENGTH;

  uint64_t board_id_net = host_to_net64(msg->board_id);
  memcpy(ptr, &board_id_net, 8);
  ptr += 8;

  uint32_t seq_num_net = htonl(msg->seq_num);
  memcpy(ptr, &seq_num_net, 4);
  ptr += 4;

  *ptr++ = msg->uci_len;

  memcpy(ptr, msg->uci, MAX_UCI_LENGTH);
  ptr += MAX_UCI_LENGTH;

  memcpy(ptr, msg->fen, FEN_MAX_LENGTH);
  ptr += FEN_MAX_LENGTH;

  return ptr - buffer;
}

int deserialize_wamble_msg(const uint8_t *buffer, size_t buffer_size,
                           struct WambleMsg *msg) {
  if (buffer_size < WAMBLE_SERIALIZED_SIZE) {
    return -1;
  }

  const uint8_t *ptr = buffer;

  msg->ctrl = *ptr++;

  memcpy(msg->token, ptr, TOKEN_LENGTH);
  ptr += TOKEN_LENGTH;

  uint64_t board_id_net;
  memcpy(&board_id_net, ptr, 8);
  msg->board_id = net_to_host64(board_id_net);
  ptr += 8;

  uint32_t seq_num_net;
  memcpy(&seq_num_net, ptr, 4);
  msg->seq_num = ntohl(seq_num_net);
  ptr += 4;

  msg->uci_len = *ptr++;

  memcpy(msg->uci, ptr, MAX_UCI_LENGTH);
  ptr += MAX_UCI_LENGTH;

  memcpy(msg->fen, ptr, FEN_MAX_LENGTH);
  ptr += FEN_MAX_LENGTH;

  return 0;
}

void set_network_timeouts(int timeout_ms, int max_retries) {
  LOG_INFO("Setting network timeouts: timeout_ms=%d, max_retries=%d",
           timeout_ms, max_retries);
  if (timeout_ms > 0)
    network_timeout_ms = timeout_ms;
  if (max_retries > 0)
    network_max_retries = max_retries;
}

static WambleClientSession *
find_client_session(const struct sockaddr_in *addr) {
  int idx = session_map_get(addr);
  if (idx >= 0)
    return &client_sessions[idx];
  return NULL;
}

static WambleClientSession *
create_client_session(const struct sockaddr_in *addr, const uint8_t *token) {
  if (num_sessions >= MAX_CLIENT_SESSIONS) {
    LOG_WARN("Maximum number of client sessions reached (%d)",
             MAX_CLIENT_SESSIONS);
    return NULL;
  }

  WambleClientSession *session = &client_sessions[num_sessions++];
  session->addr = *addr;
  memcpy(session->token, token, TOKEN_LENGTH);
  session->last_seq_num = 0;
  session->last_seen = time(NULL);
  session->next_seq_num = 1;
  session_map_put(addr, (int)(session - client_sessions));
  char ip_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(addr->sin_addr), ip_str, INET_ADDRSTRLEN);
  LOG_INFO("Created new client session for %s:%d", ip_str,
           ntohs(addr->sin_port));
  return session;
}

int validate_message(const struct WambleMsg *msg, size_t received_size) {
  if (received_size != WAMBLE_SERIALIZED_SIZE) {
    LOG_WARN("Invalid message size: expected %d, got %zu",
             WAMBLE_SERIALIZED_SIZE, received_size);
    return -1;
  }

  if (msg->ctrl != WAMBLE_CTRL_CLIENT_HELLO &&
      msg->ctrl != WAMBLE_CTRL_SERVER_HELLO &&
      msg->ctrl != WAMBLE_CTRL_PLAYER_MOVE &&
      msg->ctrl != WAMBLE_CTRL_BOARD_UPDATE && msg->ctrl != WAMBLE_CTRL_ACK) {
    LOG_WARN("Invalid message control code: 0x%02x", msg->ctrl);
    return -1;
  }

  if (msg->uci_len > MAX_UCI_LENGTH) {
    LOG_WARN("Invalid uci_len: %d (max is %d)", msg->uci_len, MAX_UCI_LENGTH);
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
      LOG_WARN("Message with empty token received");
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

  uint32_t diff = seq_num - session->last_seq_num;
  if (diff == 0) {
    return 1;
  }
  if (diff > (UINT32_MAX / 2u)) {
    return 1;
  }
  return 0;
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

  LOG_DEBUG("Attempting to create socket");
  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    LOG_FATAL("socket creation failed: %s", strerror(errno));
    return -1;
  }
  LOG_INFO("Socket created successfully (sockfd: %d)", sockfd);

  int optval = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) <
      0) {
    LOG_WARN("setsockopt SO_REUSEADDR failed: %s", strerror(errno));
  }

  int buffer_size = WAMBLE_BUFFER_SIZE;
  if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &buffer_size,
                 sizeof(buffer_size)) < 0) {
    LOG_WARN("setsockopt SO_RCVBUF failed: %s", strerror(errno));
  }
  if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &buffer_size,
                 sizeof(buffer_size)) < 0) {
    LOG_WARN("setsockopt SO_SNDBUF failed: %s", strerror(errno));
  }

  memset(&servaddr, 0, sizeof(servaddr));

  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = INADDR_ANY;
  servaddr.sin_port = htons(network_port);

  LOG_DEBUG("Attempting to bind socket to port %d", network_port);
  if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
    LOG_FATAL("bind failed: %s", strerror(errno));
    close(sockfd);
    return -1;
  }
  LOG_INFO("Socket bound successfully to port %d", network_port);

  int flags = fcntl(sockfd, F_GETFL, 0);
  if (flags >= 0) {
    (void)fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    LOG_DEBUG("Socket set to non-blocking mode");
  }

  LOG_DEBUG("Initializing session map");
  session_map_init();

  return sockfd;
}

int receive_message(int sockfd, struct WambleMsg *msg,
                    struct sockaddr_in *cliaddr) {
  socklen_t len = sizeof(*cliaddr);
  static uint8_t receive_buffer[WAMBLE_SERIALIZED_SIZE];

  ssize_t bytes_received =
      recvfrom(sockfd, receive_buffer, WAMBLE_SERIALIZED_SIZE, 0,
               (struct sockaddr *)cliaddr, &len);

  if (bytes_received <= 0) {
    LOG_DEBUG("recvfrom returned %zd", bytes_received);
    return bytes_received;
  }

  LOG_DEBUG("Received %zd bytes from client", bytes_received);

  if (deserialize_wamble_msg(receive_buffer, bytes_received, msg) != 0) {
    LOG_WARN("Failed to deserialize message from client");
    return -1;
  }
  LOG_DEBUG("Deserialized message: ctrl=0x%02x, seq=%u", msg->ctrl,
            msg->seq_num);

  if (validate_message(msg, bytes_received) != 0) {
    LOG_WARN("Received invalid message from client");
    return -1;
  }
  LOG_DEBUG("Message validated successfully");

  if (msg->ctrl != WAMBLE_CTRL_ACK &&
      is_duplicate_message(cliaddr, msg->seq_num)) {
    LOG_DEBUG("Received duplicate message (seq %u)", msg->seq_num);
    return -1;
  }

  if (msg->ctrl != WAMBLE_CTRL_ACK) {
    update_client_session(cliaddr, msg->token, msg->seq_num);
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(cliaddr->sin_addr), ip_str, INET_ADDRSTRLEN);
    LOG_DEBUG("Updated client session for %s:%d (seq: %u)", ip_str,
              ntohs(cliaddr->sin_port), msg->seq_num);
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

  static uint8_t send_buffer[WAMBLE_SERIALIZED_SIZE];
  int serialized_size = serialize_wamble_msg(&ack_msg, send_buffer);

  char ip_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(cliaddr->sin_addr), ip_str, INET_ADDRSTRLEN);
  LOG_DEBUG(
      "Sending ACK for message (ctrl: 0x%02x, seq: %u, board_id: %lu) to %s:%d",
      msg->ctrl, msg->seq_num, msg->board_id, ip_str, ntohs(cliaddr->sin_port));

  sendto(sockfd, send_buffer, serialized_size, 0,
         (const struct sockaddr *)cliaddr, sizeof(*cliaddr));
}

int wait_for_ack(int sockfd, uint32_t expected_seq, int timeout_ms) {
  fd_set readfds;
  struct timeval timeout;

  LOG_DEBUG("Waiting for ACK with expected sequence %u (timeout: %dms)",
            expected_seq, timeout_ms);

  timeout.tv_sec = timeout_ms / 1000;
  timeout.tv_usec = (timeout_ms % 1000) * 1000;

  FD_ZERO(&readfds);
  FD_SET(sockfd, &readfds);

  int result = select(sockfd + 1, &readfds, NULL, NULL, &timeout);
  if (result == -1) {
    LOG_WARN("select failed while waiting for ACK: %s", strerror(errno));
    return -1;
  } else if (result == 0) {
    LOG_DEBUG("select timed out while waiting for ACK for seq %u",
              expected_seq);
    return -1;
  }

  static uint8_t ack_buffer[WAMBLE_SERIALIZED_SIZE];
  struct WambleMsg ack_msg;
  struct sockaddr_in cliaddr;
  socklen_t len = sizeof(cliaddr);

  int bytes_received = recvfrom(sockfd, ack_buffer, WAMBLE_SERIALIZED_SIZE, 0,
                                (struct sockaddr *)&cliaddr, &len);

  if (bytes_received > 0) {
    if (deserialize_wamble_msg(ack_buffer, bytes_received, &ack_msg) == 0 &&
        ack_msg.ctrl == WAMBLE_CTRL_ACK && ack_msg.seq_num == expected_seq) {
      LOG_DEBUG("Received ACK for expected sequence %u", expected_seq);
      return 0;
    }
  }
  LOG_DEBUG("Did not receive expected ACK for sequence %u", expected_seq);

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
  char ip_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(cliaddr->sin_addr), ip_str, INET_ADDRSTRLEN);

  if (!session) {
    LOG_DEBUG(
        "No session found for %s:%d, creating new session for reliable message",
        ip_str, ntohs(cliaddr->sin_port));
    session = create_client_session(cliaddr, msg->token);
    if (!session) {
      LOG_ERROR("Failed to create client session for %s:%d", ip_str,
                ntohs(cliaddr->sin_port));
      reliable_msg.seq_num = global_seq_num++;
      if (global_seq_num > (UINT32_MAX - 1000)) {
        global_seq_num = 1;
      }
    } else {
      reliable_msg.seq_num = session->next_seq_num++;
      LOG_DEBUG("Created new session for %s:%d, assigned seq_num %u", ip_str,
                ntohs(cliaddr->sin_port), reliable_msg.seq_num);
    }
  } else {
    reliable_msg.seq_num = session->next_seq_num++;
    LOG_DEBUG("Using existing session for %s:%d, assigned seq_num %u", ip_str,
              ntohs(cliaddr->sin_port), reliable_msg.seq_num);
  }

  static uint8_t send_buffer[WAMBLE_SERIALIZED_SIZE];
  int serialized_size = serialize_wamble_msg(&reliable_msg, send_buffer);

  LOG_DEBUG("Attempting to send reliable message (ctrl: 0x%02x, seq: %u, "
            "board_id: %lu) to %s:%d",
            reliable_msg.ctrl, reliable_msg.seq_num, reliable_msg.board_id,
            ip_str, ntohs(cliaddr->sin_port));

  for (int attempt = 0; attempt < max_retries; attempt++) {
    int bytes_sent = sendto(sockfd, send_buffer, serialized_size, 0,
                            (const struct sockaddr *)cliaddr, sizeof(*cliaddr));

    if (bytes_sent < 0) {
      LOG_ERROR("sendto failed: %s", strerror(errno));
      return -1;
    }
    LOG_DEBUG("Sent %d bytes (attempt %d/%d) for seq %u to %s:%d", bytes_sent,
              attempt + 1, max_retries, reliable_msg.seq_num, ip_str,
              ntohs(cliaddr->sin_port));

    if (wait_for_ack(sockfd, reliable_msg.seq_num, timeout_ms) == 0) {
      LOG_DEBUG("Received ACK for seq %u from %s:%d", reliable_msg.seq_num,
                ip_str, ntohs(cliaddr->sin_port));
      return 0;
    }

    LOG_WARN("Message timeout on attempt %d/%d (seq %u) for %s:%d", attempt + 1,
             max_retries, reliable_msg.seq_num, ip_str,
             ntohs(cliaddr->sin_port));
  }

  LOG_ERROR("Failed to send reliable message (ctrl: 0x%02x, seq: %u) to %s:%d "
            "after %d retries",
            reliable_msg.ctrl, reliable_msg.seq_num, ip_str,
            ntohs(cliaddr->sin_port), max_retries);
  return -1;
}

void start_network_listener(void) {
  LOG_INFO("Network listener started on port %d", network_port);
  LOG_INFO("Timeout: %dms, Max retries: %d", network_timeout_ms,
           network_max_retries);
}

void send_response(const struct WambleMsg *msg) {

  LOG_INFO("Broadcasting response (ctrl: 0x%02x, seq: %u)", msg->ctrl,
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
    LOG_INFO("Cleaned up %d expired client sessions", num_sessions - write_idx);
    num_sessions = write_idx;
    session_map_init();
    for (int i = 0; i < num_sessions; i++) {
      session_map_put(&client_sessions[i].addr, i);
    }
  }
}

static const char base64url_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_ ";

void format_token_for_url(const uint8_t *token, char *url_buffer) {
  if (!token || !url_buffer)
    return;

  int j = 0;
  for (int i = 0; i < 16; i += 3) {
    uint32_t block = 0;
    int bytes_in_block = (i + 3 <= 16) ? 3 : (16 - i);

    for (int k = 0; k < bytes_in_block; k++) {
      block |= ((uint32_t)token[i + k]) << (8 * (2 - k));
    }

    for (int k = 0; k < 4; k++) {
      if (j >= 22)
        break;
      url_buffer[j++] = base64url_chars[(block >> (6 * (3 - k))) & 0x3F];
    }
  }

  url_buffer[22] = '\0';
}

int decode_token_from_url(const char *url_string, uint8_t *token_buffer) {
  if (!url_string || !token_buffer || strlen(url_string) != 22) {
    return -1;
  }

  uint8_t decode_table[256];
  memset(decode_table, 0xFF, 256);

  for (int i = 0; i < 64; i++) {
    decode_table[(unsigned char)base64url_chars[i]] = i;
  }

  memset(token_buffer, 0, 16);

  int token_pos = 0;
  for (int i = 0; i < 22; i += 4) {
    uint32_t block = 0;
    int valid_chars = 0;

    for (int j = 0; j < 4 && (i + j) < 22; j++) {
      unsigned char c = url_string[i + j];
      if (decode_table[c] == 0xFF) {
        return -1;
      }
      block |= ((uint32_t)decode_table[c]) << (6 * (3 - j));
      valid_chars++;
    }

    for (int j = 0; j < 3 && token_pos < 16; j++) {
      token_buffer[token_pos++] = (block >> (8 * (2 - j))) & 0xFF;
    }
  }

  return 0;
}
