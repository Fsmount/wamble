#include "../include/wamble/wamble.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#pragma pack(push, 1)
typedef struct WambleHeader {
  uint8_t ctrl;
  uint8_t flags;
  uint8_t version;
  uint8_t reserved;
  uint8_t token[TOKEN_LENGTH];
  uint64_t board_id;
  uint32_t seq_num;
  uint16_t payload_len;
} WambleHeader;
#pragma pack(pop)

#define WAMBLE_HEADER_SIZE (sizeof(WambleHeader))
#define WAMBLE_MAX_PACKET_SIZE (WAMBLE_HEADER_SIZE + WAMBLE_MAX_PAYLOAD)

static __thread WambleClientSession *client_sessions;
static __thread int num_sessions = 0;
static __thread uint32_t global_seq_num = 1;

#define SESSION_MAP_SIZE (get_config()->max_client_sessions * 2)
static __thread int *session_index_map;

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

int serialize_wamble_msg(const struct WambleMsg *msg, uint8_t *buffer,
                         size_t buffer_capacity, size_t *out_len,
                         uint8_t flags) {
  if (!buffer || buffer_capacity < WAMBLE_HEADER_SIZE)
    return -1;

  WambleHeader hdr = {0};
  hdr.ctrl = msg->ctrl;
  hdr.flags = flags;
  hdr.version = WAMBLE_PROTO_VERSION;
  hdr.reserved = 0;
  memcpy(hdr.token, msg->token, TOKEN_LENGTH);
  hdr.board_id = host_to_net64(msg->board_id);
  hdr.seq_num = htonl(msg->seq_num);

  uint8_t payload[WAMBLE_MAX_PAYLOAD];
  size_t payload_len = 0;

  switch (msg->ctrl) {
  case WAMBLE_CTRL_CLIENT_HELLO:
  case WAMBLE_CTRL_ACK:
  case WAMBLE_CTRL_LIST_PROFILES:
  case WAMBLE_CTRL_CLIENT_GOODBYE:
  case WAMBLE_CTRL_LOGOUT:
  case WAMBLE_CTRL_GET_PLAYER_STATS:
    payload_len = 0;
    break;
  case WAMBLE_CTRL_PLAYER_MOVE: {
    size_t need = 1 + (size_t)msg->uci_len;
    if (need > WAMBLE_MAX_PAYLOAD)
      return -1;
    payload[0] = msg->uci_len;
    memcpy(&payload[1], msg->uci, msg->uci_len);
    payload_len = need;
    break;
  }
  case WAMBLE_CTRL_SERVER_HELLO:
  case WAMBLE_CTRL_BOARD_UPDATE:
  case WAMBLE_CTRL_SERVER_NOTIFICATION:
  case WAMBLE_CTRL_SPECTATE_UPDATE: {
    size_t len = strnlen(msg->fen, FEN_MAX_LENGTH);
    if (len > WAMBLE_MAX_PAYLOAD)
      return -1;
    memcpy(payload, msg->fen, len);
    payload_len = len;
    break;
  }
  case WAMBLE_CTRL_PROFILE_INFO: {

    size_t len = strnlen(msg->fen, FEN_MAX_LENGTH);
    if (len > WAMBLE_MAX_PAYLOAD)
      return -1;
    memcpy(payload, msg->fen, len);
    payload_len = len;
    break;
  }
  case WAMBLE_CTRL_GET_PROFILE_INFO: {

    size_t need = 1 + (size_t)msg->uci_len;
    if (need > WAMBLE_MAX_PAYLOAD)
      return -1;
    payload[0] = msg->uci_len;
    if (msg->uci_len)
      memcpy(&payload[1], msg->uci, msg->uci_len);
    payload_len = need;
    break;
  }
  case WAMBLE_CTRL_PROFILES_LIST: {

    size_t len = strnlen(msg->fen, FEN_MAX_LENGTH);
    if (len > WAMBLE_MAX_PAYLOAD)
      return -1;
    memcpy(payload, msg->fen, len);
    payload_len = len;
    break;
  }
  case WAMBLE_CTRL_ERROR: {

    uint16_t code_net = htons(msg->error_code);
    size_t reason_len = strnlen(msg->error_reason, FEN_MAX_LENGTH);
    if (reason_len > 255)
      reason_len = 255;
    if (3 + reason_len > WAMBLE_MAX_PAYLOAD)
      return -1;
    payload[0] = (uint8_t)(code_net >> 8);
    payload[1] = (uint8_t)(code_net & 0xFF);
    payload[2] = (uint8_t)reason_len;
    if (reason_len)
      memcpy(&payload[3], msg->error_reason, reason_len);
    payload_len = 3 + reason_len;
    break;
  }
  case WAMBLE_CTRL_SPECTATE_GAME: {

    payload_len = 0;
    break;
  }
  case WAMBLE_CTRL_LOGIN_REQUEST: {

    payload_len = 0;
    break;
  }
  case WAMBLE_CTRL_PLAYER_STATS_DATA: {
    WamblePlayer *player = get_player_by_token(msg->token);
    if (player) {

      uint64_t bits = 0;
      memcpy(&bits, &player->score, sizeof(double));
      uint64_t be = host_to_net64(bits);
      for (int i = 0; i < 8; i++) {
        payload[i] = (uint8_t)((be >> (8 * (7 - i))) & 0xFF);
      }
      uint32_t gp = (uint32_t)player->games_played;
      uint32_t gp_be = htonl(gp);
      memcpy(payload + 8, &gp_be, 4);
      payload_len = 12;
    }
    break;
  }
  case WAMBLE_CTRL_LOGIN_FAILED: {

    uint16_t code_net = htons(msg->error_code);
    size_t reason_len = strnlen(msg->error_reason, FEN_MAX_LENGTH);
    if (reason_len > 255)
      reason_len = 255;
    if (3 + reason_len > WAMBLE_MAX_PAYLOAD)
      return -1;
    payload[0] = (uint8_t)(code_net >> 8);
    payload[1] = (uint8_t)(code_net & 0xFF);
    payload[2] = (uint8_t)reason_len;
    if (reason_len)
      memcpy(&payload[3], msg->error_reason, reason_len);
    payload_len = 3 + reason_len;
    break;
  }
  default:

    payload_len = 0;
    break;
  }

  hdr.payload_len = htons((uint16_t)payload_len);

  if (WAMBLE_HEADER_SIZE + payload_len > buffer_capacity)
    return -1;

  memcpy(buffer, &hdr, sizeof(hdr));
  if (payload_len > 0)
    memcpy(buffer + WAMBLE_HEADER_SIZE, payload, payload_len);
  if (out_len)
    *out_len = WAMBLE_HEADER_SIZE + payload_len;
  return 0;
}

int deserialize_wamble_msg(const uint8_t *buffer, size_t buffer_size,
                           struct WambleMsg *msg, uint8_t *out_flags) {
  if (!buffer || buffer_size < WAMBLE_HEADER_SIZE || !msg)
    return -1;
  WambleHeader hdr;
  memcpy(&hdr, buffer, sizeof(hdr));
  size_t payload_len = ntohs(hdr.payload_len);
  if (buffer_size < WAMBLE_HEADER_SIZE + payload_len)
    return -1;

  memset(msg, 0, sizeof(*msg));
  msg->ctrl = hdr.ctrl;
  msg->flags = hdr.flags;
  memcpy(msg->token, hdr.token, TOKEN_LENGTH);
  msg->board_id = net_to_host64(hdr.board_id);
  msg->seq_num = ntohl(hdr.seq_num);
  if (out_flags)
    *out_flags = hdr.flags;

  const uint8_t *payload = buffer + WAMBLE_HEADER_SIZE;

  switch (hdr.ctrl) {
  case WAMBLE_CTRL_CLIENT_HELLO:
  case WAMBLE_CTRL_ACK:
  case WAMBLE_CTRL_LIST_PROFILES:
  case WAMBLE_CTRL_CLIENT_GOODBYE:
  case WAMBLE_CTRL_SPECTATE_GAME:
  case WAMBLE_CTRL_LOGOUT:

    break;
  case WAMBLE_CTRL_PLAYER_MOVE: {
    if (payload_len < 1)
      return -1;
    msg->uci_len = payload[0];
    if ((size_t)msg->uci_len > MAX_UCI_LENGTH ||
        (size_t)msg->uci_len > payload_len - 1)
      return -1;
    memcpy(msg->uci, &payload[1], msg->uci_len);
    break;
  }
  case WAMBLE_CTRL_SERVER_HELLO:
  case WAMBLE_CTRL_BOARD_UPDATE:
  case WAMBLE_CTRL_SERVER_NOTIFICATION:
  case WAMBLE_CTRL_SPECTATE_UPDATE:
  case WAMBLE_CTRL_ERROR:
  case WAMBLE_CTRL_PROFILES_LIST: {

    if (hdr.ctrl == WAMBLE_CTRL_ERROR) {
      if (payload_len < 3)
        return -1;
      uint16_t code_net = (uint16_t)((payload[0] << 8) | payload[1]);
      uint8_t rlen = payload[2];
      if ((size_t)3 + rlen > payload_len)
        return -1;
      msg->error_code = ntohs(code_net);
      size_t copy = rlen < FEN_MAX_LENGTH - 1 ? rlen : (FEN_MAX_LENGTH - 1);
      if (copy)
        memcpy(msg->error_reason, &payload[3], copy);
      msg->error_reason[copy] = '\0';
    } else {
      size_t copy =
          payload_len < FEN_MAX_LENGTH - 1 ? payload_len : (FEN_MAX_LENGTH - 1);
      memcpy(msg->fen, payload, copy);
      msg->fen[copy] = '\0';
    }
    break;
  }
  case WAMBLE_CTRL_LOGIN_FAILED: {
    if (payload_len < 3)
      return -1;
    uint16_t code_net = (uint16_t)((payload[0] << 8) | payload[1]);
    uint8_t rlen = payload[2];
    if ((size_t)3 + rlen > payload_len)
      return -1;
    msg->error_code = ntohs(code_net);
    size_t copy = rlen < FEN_MAX_LENGTH - 1 ? rlen : (FEN_MAX_LENGTH - 1);
    if (copy)
      memcpy(msg->error_reason, &payload[3], copy);
    msg->error_reason[copy] = '\0';
    break;
  }
  case WAMBLE_CTRL_PROFILE_INFO: {

    size_t copy =
        payload_len < FEN_MAX_LENGTH - 1 ? payload_len : (FEN_MAX_LENGTH - 1);
    memcpy(msg->fen, payload, copy);
    msg->fen[copy] = '\0';
    break;
  }
  case WAMBLE_CTRL_GET_PROFILE_INFO: {

    if (payload_len < 1)
      return -1;
    msg->uci_len = payload[0];
    if ((size_t)msg->uci_len > MAX_UCI_LENGTH ||
        (size_t)msg->uci_len > payload_len - 1)
      return -1;
    if (msg->uci_len)
      memcpy(msg->uci, &payload[1], msg->uci_len);
    break;
  }
  case WAMBLE_CTRL_PLAYER_STATS_DATA: {
    if (payload_len < 12)
      return -1;
    uint64_t be = 0;
    for (int i = 0; i < 8; i++) {
      be = (be << 8) | payload[i];
    }
    uint64_t host = net_to_host64(be);
    double score = 0.0;
    memcpy(&score, &host, sizeof(double));

    (void)score;

    if (payload_len >= 12) {
      uint32_t gp_be = 0;
      memcpy(&gp_be, payload + 8, 4);
      (void)gp_be;
    }
    break;
  }
  case WAMBLE_CTRL_LOGIN_REQUEST: {
    if (payload_len == 32) {
      memcpy(msg->login_pubkey, payload, 32);
    }
    break;
  }
  default:
    break;
  }
  return 0;
}

static WambleClientSession *
find_client_session(const struct sockaddr_in *addr) {
  int idx = session_map_get(addr);
  if (idx >= 0)
    return &client_sessions[idx];
  return NULL;
}

static WambleClientSession *find_client_session_by_token(const uint8_t *token) {
  for (int i = 0; i < num_sessions; i++) {
    if (memcmp(client_sessions[i].token, token, TOKEN_LENGTH) == 0)
      return &client_sessions[i];
  }
  return NULL;
}

static WambleClientSession *
create_client_session(const struct sockaddr_in *addr, const uint8_t *token) {
  if (num_sessions >= get_config()->max_client_sessions) {
    LOG_WARN("Maximum number of client sessions reached (%d)",
             get_config()->max_client_sessions);
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
  if (msg->ctrl != WAMBLE_CTRL_CLIENT_HELLO &&
      msg->ctrl != WAMBLE_CTRL_SERVER_HELLO &&
      msg->ctrl != WAMBLE_CTRL_PLAYER_MOVE &&
      msg->ctrl != WAMBLE_CTRL_BOARD_UPDATE && msg->ctrl != WAMBLE_CTRL_ACK &&
      msg->ctrl != WAMBLE_CTRL_LIST_PROFILES &&
      msg->ctrl != WAMBLE_CTRL_PROFILE_INFO &&
      msg->ctrl != WAMBLE_CTRL_GET_PROFILE_INFO &&
      msg->ctrl != WAMBLE_CTRL_PROFILES_LIST &&
      msg->ctrl != WAMBLE_CTRL_ERROR &&
      msg->ctrl != WAMBLE_CTRL_SERVER_NOTIFICATION &&
      msg->ctrl != WAMBLE_CTRL_CLIENT_GOODBYE &&
      msg->ctrl != WAMBLE_CTRL_SPECTATE_GAME &&
      msg->ctrl != WAMBLE_CTRL_SPECTATE_UPDATE &&
      msg->ctrl != WAMBLE_CTRL_LOGIN_REQUEST &&
      msg->ctrl != WAMBLE_CTRL_LOGOUT &&
      msg->ctrl != WAMBLE_CTRL_LOGIN_SUCCESS &&
      msg->ctrl != WAMBLE_CTRL_LOGIN_FAILED &&
      msg->ctrl != WAMBLE_CTRL_GET_PLAYER_STATS &&
      msg->ctrl != WAMBLE_CTRL_PLAYER_STATS_DATA) {
    LOG_WARN("Invalid message control code: 0x%02x", msg->ctrl);
    return -1;
  }

  if (msg->uci_len > MAX_UCI_LENGTH) {
    LOG_WARN("Invalid uci_len: %d (max is %d)", msg->uci_len, MAX_UCI_LENGTH);
    return -1;
  }

  {
    int token_valid = 0;
    for (int i = 0; i < TOKEN_LENGTH; i++) {
      if (msg->token[i] != 0) {
        token_valid = 1;
        break;
      }
    }
    if (!token_valid) {
      LOG_WARN("Message with empty token received (ctrl=0x%02x)", msg->ctrl);
      return -1;
    }
  }

  return 0;
}

int is_duplicate_message(const struct sockaddr_in *addr, const uint8_t *token,
                         uint32_t seq_num) {
  WambleClientSession *session = find_client_session(addr);
  if (!session) {
    session = find_client_session_by_token(token);
  }
  if (!session) {
    return 0;
  }

  uint32_t last = session->last_seq_num;
  uint32_t d_forward = seq_num - last;
  if (d_forward == 0)
    return 1;
  if (d_forward <= (UINT32_MAX / 2u)) {
    return 0;
  }

  uint32_t d_back = last - seq_num;
  if (d_back <= WAMBLE_DUP_WINDOW)
    return 1;
  return 0;
}

void update_client_session(const struct sockaddr_in *addr, const uint8_t *token,
                           uint32_t seq_num) {
  WambleClientSession *session = find_client_session(addr);
  if (!session) {
    session = find_client_session_by_token(token);
    if (session) {

      uint32_t diff = seq_num - session->last_seq_num;
      if (diff != 0 && diff <= (UINT32_MAX / 2u)) {
        session->addr = *addr;
        session_map_put(addr, (int)(session - client_sessions));
      }
    } else {
      session = create_client_session(addr, token);
      if (!session)
        return;
    }
  }

  session->last_seq_num = seq_num;
  session->last_seen = time(NULL);
  memcpy(session->token, token, TOKEN_LENGTH);
}

void network_init_thread_state(void) {
  if (!client_sessions) {
    client_sessions =
        malloc(sizeof(WambleClientSession) * get_config()->max_client_sessions);
  }
  if (!session_index_map) {
    session_index_map =
        malloc(sizeof(int) * (get_config()->max_client_sessions * 2));
  }
  num_sessions = 0;
  session_map_init();
}

int create_and_bind_socket(int port) {
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

  int buffer_size = get_config()->buffer_size;
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
  servaddr.sin_port = htons(port);

  LOG_DEBUG("Attempting to bind socket to port %d", port);
  if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
    LOG_FATAL("bind failed: %s", strerror(errno));
    close(sockfd);
    return -1;
  }
  LOG_INFO("Socket bound successfully to port %d", port);

  int flags = fcntl(sockfd, F_GETFL, 0);
  if (flags >= 0) {
    (void)fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    LOG_DEBUG("Socket set to non-blocking mode");
  }

  LOG_DEBUG("Initializing session map");
  network_init_thread_state();

  return sockfd;
}

int receive_message(int sockfd, struct WambleMsg *msg,
                    struct sockaddr_in *cliaddr) {
  socklen_t len = sizeof(*cliaddr);
  static uint8_t receive_buffer[WAMBLE_MAX_PACKET_SIZE];

  ssize_t bytes_received =
      recvfrom(sockfd, receive_buffer, WAMBLE_MAX_PACKET_SIZE, 0,
               (struct sockaddr *)cliaddr, &len);

  if (bytes_received <= 0) {
    LOG_DEBUG("recvfrom returned %zd", bytes_received);
    return bytes_received;
  }

  LOG_DEBUG("Received %zd bytes from client", bytes_received);

  uint8_t flags = 0;
  if (deserialize_wamble_msg(receive_buffer, (size_t)bytes_received, msg,
                             &flags) != 0) {
    LOG_WARN("Failed to deserialize message from client");
    return -1;
  }
  LOG_DEBUG("Deserialized message: ctrl=0x%02x, seq=%u", msg->ctrl,
            msg->seq_num);

  if (validate_message(msg, (size_t)bytes_received) != 0) {
    LOG_WARN("Received invalid message from client");
    return -1;
  }
  LOG_DEBUG("Message validated successfully");

  if (msg->ctrl != WAMBLE_CTRL_ACK &&
      (msg->flags & WAMBLE_FLAG_UNRELIABLE) == 0 &&
      is_duplicate_message(cliaddr, msg->token, msg->seq_num)) {
    LOG_DEBUG("Received duplicate message (seq %u)", msg->seq_num);
    return -1;
  }

  if (msg->ctrl != WAMBLE_CTRL_ACK &&
      (msg->flags & WAMBLE_FLAG_UNRELIABLE) == 0) {
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

  static uint8_t send_buffer[WAMBLE_MAX_PACKET_SIZE];
  size_t serialized_size = 0;
  if (serialize_wamble_msg(&ack_msg, send_buffer, sizeof(send_buffer),
                           &serialized_size, 0) != 0) {
    LOG_WARN("Failed to serialize ACK");
    return;
  }

  char ip_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(cliaddr->sin_addr), ip_str, INET_ADDRSTRLEN);
  LOG_DEBUG(
      "Sending ACK for message (ctrl: 0x%02x, seq: %u, board_id: %lu) to %s:%d",
      msg->ctrl, msg->seq_num, msg->board_id, ip_str, ntohs(cliaddr->sin_port));

  sendto(sockfd, send_buffer, (int)serialized_size, 0,
         (const struct sockaddr *)cliaddr, sizeof(*cliaddr));
}

int wait_for_ack(int sockfd, const uint8_t *expected_token,
                 uint32_t expected_seq, int timeout_ms) {
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

  static uint8_t ack_buffer[WAMBLE_MAX_PACKET_SIZE];
  struct WambleMsg ack_msg;
  struct sockaddr_in cliaddr;
  socklen_t len = sizeof(cliaddr);

  int bytes_received = recvfrom(sockfd, ack_buffer, WAMBLE_MAX_PACKET_SIZE, 0,
                                (struct sockaddr *)&cliaddr, &len);

  if (bytes_received > 0) {
    uint8_t flags = 0;
    if (deserialize_wamble_msg(ack_buffer, (size_t)bytes_received, &ack_msg,
                               &flags) == 0 &&
        ack_msg.ctrl == WAMBLE_CTRL_ACK && ack_msg.seq_num == expected_seq &&
        memcmp(ack_msg.token, expected_token, TOKEN_LENGTH) == 0) {
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
    timeout_ms = get_config()->timeout_ms;
  if (max_retries <= 0)
    max_retries = get_config()->max_retries;

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

  static uint8_t send_buffer[WAMBLE_MAX_PACKET_SIZE];
  size_t serialized_size = 0;
  if (serialize_wamble_msg(&reliable_msg, send_buffer, sizeof(send_buffer),
                           &serialized_size, 0) != 0) {
    LOG_ERROR("Failed to serialize reliable message");
    return -1;
  }

  LOG_DEBUG("Attempting to send reliable message (ctrl: 0x%02x, seq: %u, "
            "board_id: %lu) to %s:%d",
            reliable_msg.ctrl, reliable_msg.seq_num, reliable_msg.board_id,
            ip_str, ntohs(cliaddr->sin_port));

  int current_timeout = timeout_ms;
  for (int attempt = 0; attempt < max_retries; attempt++) {
    int bytes_sent = sendto(sockfd, send_buffer, (int)serialized_size, 0,
                            (const struct sockaddr *)cliaddr, sizeof(*cliaddr));

    if (bytes_sent < 0) {
      LOG_ERROR("sendto failed: %s", strerror(errno));
      return -1;
    }
    LOG_DEBUG("Sent %d bytes (attempt %d/%d) for seq %u to %s:%d", bytes_sent,
              attempt + 1, max_retries, reliable_msg.seq_num, ip_str,
              ntohs(cliaddr->sin_port));

    if (wait_for_ack(sockfd, reliable_msg.token, reliable_msg.seq_num,
                     current_timeout) == 0) {
      LOG_DEBUG("Received ACK for seq %u from %s:%d", reliable_msg.seq_num,
                ip_str, ntohs(cliaddr->sin_port));
      return 0;
    }

    LOG_WARN("Message timeout on attempt %d/%d (seq %u) for %s:%d", attempt + 1,
             max_retries, reliable_msg.seq_num, ip_str,
             ntohs(cliaddr->sin_port));
    if (current_timeout < 8000) {
      int next = current_timeout * 2;
      current_timeout = next > 8000 ? 8000 : next;
    }
  }

  LOG_ERROR("Failed to send reliable message (ctrl: 0x%02x, seq: %u) to %s:%d "
            "after %d retries",
            reliable_msg.ctrl, reliable_msg.seq_num, ip_str,
            ntohs(cliaddr->sin_port), max_retries);
  return -1;
}

void start_network_listener(void) {
  LOG_INFO("Network listener started on port %d", get_config()->port);
  LOG_INFO("Timeout: %dms, Max retries: %d", get_config()->timeout_ms,
           get_config()->max_retries);
}

void send_response(const struct WambleMsg *msg) {

  LOG_INFO("Broadcasting response (ctrl: 0x%02x, seq: %u)", msg->ctrl,
           msg->seq_num);
}

void cleanup_expired_sessions(void) {
  time_t now = time(NULL);
  int write_idx = 0;

  for (int read_idx = 0; read_idx < num_sessions; read_idx++) {
    if (now - client_sessions[read_idx].last_seen <
        get_config()->session_timeout) {
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
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

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
