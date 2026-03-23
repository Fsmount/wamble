#ifndef WAMBLE_CLIENT_H
#define WAMBLE_CLIENT_H

#include "wamble.h"

void format_token_for_url(const uint8_t *token, char *url_buffer);
int decode_token_from_url(const char *url_string, uint8_t *token_buffer);

#define WAMBLE_TRANSPORT_WS 1
#define WAMBLE_TRANSPORT_UDP 2
#define WAMBLE_CLIENT_WS_FRAME_MAX 4096

#define WAMBLE_CLIENT_DEFAULT_TIMEOUT_MS 500
#define WAMBLE_CLIENT_DEFAULT_MAX_RETRIES 4

#define WAMBLE_CLIENT_MNEMONIC_WORDLIST_COUNT 2048
#define WAMBLE_CLIENT_MNEMONIC_WORD_COUNT 12
#define WAMBLE_CLIENT_MNEMONIC_WORD_MIN 2
#define WAMBLE_CLIENT_MNEMONIC_WORD_MAX 4
#define WAMBLE_CLIENT_MNEMONIC_BITS_PER_WORD 11
#define WAMBLE_CLIENT_MNEMONIC_ENTROPY_BITS 128
#define WAMBLE_CLIENT_MNEMONIC_CHECKSUM_BITS                                   \
  ((WAMBLE_CLIENT_MNEMONIC_WORD_COUNT *                                        \
    WAMBLE_CLIENT_MNEMONIC_BITS_PER_WORD) -                                    \
   WAMBLE_CLIENT_MNEMONIC_ENTROPY_BITS)
#define WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH                                     \
  (WAMBLE_CLIENT_MNEMONIC_ENTROPY_BITS / 8)
#define WAMBLE_CLIENT_MNEMONIC_TEXT_MAX                                        \
  ((WAMBLE_CLIENT_MNEMONIC_WORD_COUNT * WAMBLE_CLIENT_MNEMONIC_WORD_MAX) +     \
   (WAMBLE_CLIENT_MNEMONIC_WORD_COUNT - 1) + 1)
#define WAMBLE_CLIENT_PUBLIC_KEY_HEX_LENGTH (WAMBLE_PUBLIC_KEY_LENGTH * 2)

typedef struct {
  wamble_socket_t sock;
  int kind;
  struct sockaddr_in peer;
  uint32_t seq;
  uint8_t ws_rx_buf[WAMBLE_CLIENT_WS_FRAME_MAX];
  size_t ws_rx_len;
  size_t ws_rx_offset;
} wamble_client_t;

typedef enum {
  WAMBLE_CLIENT_STATUS_OK = 0,
  WAMBLE_CLIENT_STATUS_TIMEOUT,
  WAMBLE_CLIENT_STATUS_UNSUPPORTED,
  WAMBLE_CLIENT_STATUS_INVALID_ARGUMENT,
  WAMBLE_CLIENT_STATUS_NETWORK,
  WAMBLE_CLIENT_STATUS_PROTOCOL,
  WAMBLE_CLIENT_STATUS_CLOSED,
  WAMBLE_CLIENT_STATUS_RESOLVE
} WambleClientStatusCode;

typedef struct {
  WambleClientStatusCode code;
  int detail;
} WambleClientStatus;

typedef enum {
  WAMBLE_CLIENT_TEXT_CREATE_SESSION = 0,
  WAMBLE_CLIENT_TEXT_ATTACH,
  WAMBLE_CLIENT_TEXT_BACK,
  WAMBLE_CLIENT_TEXT_SESSION_REQUIRED,
  WAMBLE_CLIENT_TEXT_SESSION_READY,
  WAMBLE_CLIENT_TEXT_IDENTITY_READY,
  WAMBLE_CLIENT_TEXT_MNEMONIC_LABEL,
  WAMBLE_CLIENT_TEXT_PUBLIC_KEY_LABEL,
  WAMBLE_CLIENT_TEXT_CONNECTED_TO,
  WAMBLE_CLIENT_TEXT_DISCONNECTED,
  WAMBLE_CLIENT_TEXT_CONNECTING,
  WAMBLE_CLIENT_TEXT_ANONYMOUS,
  WAMBLE_CLIENT_TEXT_CREATE_IDENTITY,
  WAMBLE_CLIENT_TEXT_RESTORE,
  WAMBLE_CLIENT_TEXT_LOGOUT,
  WAMBLE_CLIENT_TEXT_SAVE_MNEMONIC,
  WAMBLE_CLIENT_TEXT_ENTER_MNEMONIC,
  WAMBLE_CLIENT_TEXT_INVALID_MNEMONIC,
  WAMBLE_CLIENT_TEXT_SAVE_PROGRESS,
  WAMBLE_CLIENT_TEXT_WHITE_TO_MOVE,
  WAMBLE_CLIENT_TEXT_BLACK_TO_MOVE,
  WAMBLE_CLIENT_TEXT_ILLEGAL_MOVE,
  WAMBLE_CLIENT_TEXT_BOARD,
  WAMBLE_CLIENT_TEXT_LEADERBOARD,
  WAMBLE_CLIENT_TEXT_STATS,
  WAMBLE_CLIENT_TEXT_SPECTATE,
  WAMBLE_CLIENT_TEXT_SPECTATING,
  WAMBLE_CLIENT_TEXT_LEAVE,
  WAMBLE_CLIENT_TEXT_PREDICTIONS,
  WAMBLE_CLIENT_TEXT_SUBMIT,
  WAMBLE_CLIENT_TEXT_SERVER_LABEL,
  WAMBLE_CLIENT_TEXT_NO_PROFILES,
  WAMBLE_CLIENT_TEXT_COULD_NOT_REACH,
  WAMBLE_CLIENT_TEXT_RETRY,
  WAMBLE_CLIENT_TEXT_DONE,
  WAMBLE_CLIENT_TEXT_DISMISS,
  WAMBLE_CLIENT_TEXT_JOIN,
  WAMBLE_CLIENT_TEXT_SCORE,
  WAMBLE_CLIENT_TEXT_GAMES,
  WAMBLE_CLIENT_TEXT_CHESS960,
  WAMBLE_CLIENT_TEXT_PLAYER,
  WAMBLE_CLIENT_TEXT_THEME,
  WAMBLE_CLIENT_TEXT_RATING,
  WAMBLE_CLIENT_TEXT_TERMS,
  WAMBLE_CLIENT_TEXT_TERMS_OF_SERVICE,
  WAMBLE_CLIENT_TEXT_CLOSE,
  WAMBLE_CLIENT_TEXT_CLEAR_PARENT,
  WAMBLE_CLIENT_TEXT_ALL,
  WAMBLE_CLIENT_TEXT_STANDARD,
  WAMBLE_CLIENT_TEXT_AVAILABLE_PROFILES,
  WAMBLE_CLIENT_TEXT_IDENTITY_NOT_STORED,
  WAMBLE_CLIENT_TEXT_IDENTITY_STORED,
  WAMBLE_CLIENT_TEXT_REPLYING_ROOT,
  WAMBLE_CLIENT_TEXT_REPLYING_TO,
  WAMBLE_CLIENT_TEXT_TERMS_UNAVAILABLE,
  WAMBLE_CLIENT_TEXT_TERMS_TOO_LARGE,
  WAMBLE_CLIENT_TEXT_DEPLOYMENT_HOST_UNAVAILABLE,
  WAMBLE_CLIENT_TEXT_ATTACH_IDENTITY_FAILED,
  WAMBLE_CLIENT_TEXT_LOADING_GAMES,
  WAMBLE_CLIENT_TEXT_NO_GAMES_FOR_FILTER,
  WAMBLE_CLIENT_TEXT_LOADING,
  WAMBLE_CLIENT_TEXT_NO_ENTRIES_YET,
  WAMBLE_CLIENT_TEXT_SELF_RANK,
  WAMBLE_CLIENT_TEXT_PREDICTION_STATUS_PENDING,
  WAMBLE_CLIENT_TEXT_PREDICTION_STATUS_CORRECT,
  WAMBLE_CLIENT_TEXT_PREDICTION_STATUS_INCORRECT,
  WAMBLE_CLIENT_TEXT_PREDICTION_STATUS_EXPIRED,
  WAMBLE_CLIENT_TEXT_PREDICTION_STATUS_UNKNOWN,
  WAMBLE_CLIENT_TEXT_NO_PREDICTIONS,
  WAMBLE_CLIENT_TEXT_PROFILE_CHECKING,
  WAMBLE_CLIENT_TEXT_PROFILE_UNAVAILABLE,
  WAMBLE_CLIENT_TEXT_LOADING_TERMS,
  WAMBLE_CLIENT_TEXT_NEXT_HALFMOVE,
  WAMBLE_CLIENT_TEXT_CURRENT_POSITION,
  WAMBLE_CLIENT_TEXT_CLEAR_SELECTION,
  WAMBLE_CLIENT_TEXT_PREDICTION_PREVIEWING,
  WAMBLE_CLIENT_TEXT_PREDICTION_SELECTED_HALFMOVE,
  WAMBLE_CLIENT_TEXT_PREDICTION_CHOOSE_PROMOTION,
  WAMBLE_CLIENT_TEXT_QUEEN,
  WAMBLE_CLIENT_TEXT_ROOK,
  WAMBLE_CLIENT_TEXT_BISHOP,
  WAMBLE_CLIENT_TEXT_KNIGHT,
  WAMBLE_CLIENT_TEXT_PREDICTION_EXAMPLE_MOVE,
  WAMBLE_CLIENT_TEXT_PREDICTION_SELECTED_UCI,
  WAMBLE_CLIENT_TEXT_PREDICTION_CUSTOM_UCI,
  WAMBLE_CLIENT_TEXT_PREDICTION_CUSTOM_UCI_HINT,
  WAMBLE_CLIENT_TEXT_PREDICTION_CUSTOM_UCI_PLACEHOLDER,
  WAMBLE_CLIENT_TEXT_PREDICTION_USE_CUSTOM_UCI,
  WAMBLE_CLIENT_TEXT_INVALID_UCI,
  WAMBLE_CLIENT_TEXT_LOADING_PREDICTIONS,
  WAMBLE_CLIENT_TEXT_REQUEST_FAILED,
  WAMBLE_CLIENT_TEXT_BAD_FRAGMENT_HASH,
  WAMBLE_CLIENT_TEXT_BAD_FRAGMENT_DECODE,
  WAMBLE_CLIENT_TEXT_LEGACY_IDENTITY_LOADED,
  WAMBLE_CLIENT_TEXT_INVALID_STORED_MNEMONIC_REMOVED,
  WAMBLE_CLIENT_TEXT_BROWSER_ENTROPY_FAILED,
  WAMBLE_CLIENT_TEXT_IDENTITY_GENERATION_FAILED,
  WAMBLE_CLIENT_TEXT_MNEMONIC_PLACEHOLDER,
  WAMBLE_CLIENT_TEXT_LIVE_BOARD,
  WAMBLE_CLIENT_TEXT_LIVE_BOARD_HINT_MOVE,
  WAMBLE_CLIENT_TEXT_LIVE_BOARD_HINT_VIEW,
  WAMBLE_CLIENT_TEXT_PREDICTION_BOARD,
  WAMBLE_CLIENT_TEXT_PREDICTION_BOARD_HINT_SUBMIT,
  WAMBLE_CLIENT_TEXT_PREDICTION_BOARD_HINT_VIEW,
  WAMBLE_CLIENT_TEXT_COUNT
} WambleClientTextId;

WambleClientStatus wamble_client_ws_send_handshake(wamble_socket_t sock,
                                                   const char *path,
                                                   const char *host_header,
                                                   const char *key,
                                                   const char *version);
WambleClientStatus wamble_client_ws_recv_http(wamble_socket_t sock, char *out,
                                              size_t cap);
WambleClientStatus wamble_client_ws_send_frame_ex(wamble_socket_t sock,
                                                  uint8_t fin, uint8_t opcode,
                                                  const uint8_t *payload,
                                                  size_t len, int force_ext126);
WambleClientStatus wamble_client_ws_send_frame(wamble_socket_t sock,
                                               uint8_t opcode,
                                               const uint8_t *payload,
                                               size_t len, int force_ext126);
WambleClientStatus wamble_client_ws_recv_frame(wamble_socket_t sock,
                                               uint8_t *out_opcode,
                                               uint8_t *payload,
                                               size_t payload_cap,
                                               size_t *out_len);
WambleClientStatus wamble_client_ws_send_handshake_with_first_frame(
    wamble_socket_t sock, const char *path, const char *host_header,
    const char *key, const char *version, const uint8_t *payload,
    size_t payload_len);
WambleClientStatus wamble_client_upgrade_ws(wamble_client_t *c,
                                            wamble_socket_t sock,
                                            const char *path,
                                            const char *host_header);
WambleClientStatus wamble_client_init_ws(wamble_client_t *c,
                                         wamble_socket_t sock);
WambleClientStatus wamble_client_init_udp(wamble_client_t *c,
                                          const struct sockaddr_in *server);
WambleClientStatus wamble_client_connect_udp(wamble_client_t *c,
                                             const char *host, uint16_t port);
WambleClientStatus wamble_client_connect_web(wamble_client_t *c,
                                             const char *url);
int wamble_client_connected(const wamble_client_t *c);
int wamble_client_closed(const wamble_client_t *c);
WambleClientStatus wamble_client_send(wamble_client_t *c,
                                      struct WambleMsg *msg);
WambleClientStatus wamble_client_recv(wamble_client_t *c, struct WambleMsg *out,
                                      int timeout_ms);
void wamble_client_close(wamble_client_t *c);

void wamble_client_keygen(const uint8_t seed[32],
                          uint8_t public_key[WAMBLE_PUBLIC_KEY_LENGTH],
                          uint8_t secret_key[64]);
void wamble_client_mnemonic_seed_to_key_seed(
    const uint8_t mnemonic_seed[WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH],
    uint8_t seed[32]);
int wamble_client_keygen_from_mnemonic_seed(
    const uint8_t mnemonic_seed[WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH],
    uint8_t public_key[WAMBLE_PUBLIC_KEY_LENGTH], uint8_t secret_key[64]);
int wamble_client_keygen_from_mnemonic(
    const char *mnemonic, uint8_t public_key[WAMBLE_PUBLIC_KEY_LENGTH],
    uint8_t secret_key[64]);
int wamble_client_sign_challenge(
    const uint8_t secret_key[64], const uint8_t token[TOKEN_LENGTH],
    const uint8_t public_key[WAMBLE_PUBLIC_KEY_LENGTH],
    const uint8_t challenge[WAMBLE_LOGIN_CHALLENGE_LENGTH],
    uint8_t signature[WAMBLE_LOGIN_SIGNATURE_LENGTH]);
int wamble_client_public_key_to_hex(
    const uint8_t public_key[WAMBLE_PUBLIC_KEY_LENGTH],
    char out[WAMBLE_CLIENT_PUBLIC_KEY_HEX_LENGTH + 1]);
int wamble_client_public_key_from_hex(
    const char *hex, uint8_t public_key[WAMBLE_PUBLIC_KEY_LENGTH]);
int wamble_client_mnemonic_word_at(
    uint16_t index, char out[WAMBLE_CLIENT_MNEMONIC_WORD_MAX + 1]);
int wamble_client_mnemonic_word_index(const char *word, uint16_t *out_index);
int wamble_client_mnemonic_seed_to_text(
    const uint8_t mnemonic_seed[WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH],
    char out[WAMBLE_CLIENT_MNEMONIC_TEXT_MAX]);
int wamble_client_mnemonic_text_to_seed(
    const char *mnemonic,
    uint8_t mnemonic_seed[WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH]);
int wamble_client_generate_mnemonic_seed(
    const uint8_t entropy[WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH],
    char out_mnemonic[WAMBLE_CLIENT_MNEMONIC_TEXT_MAX],
    uint8_t out_public_key[WAMBLE_PUBLIC_KEY_LENGTH],
    uint8_t out_secret_key[64]);

const char *wamble_client_locale_text(const char *locale,
                                      WambleClientTextId id);
int wamble_client_locale_write(const char *locale, WambleClientTextId id,
                               char *out, size_t out_size);
int wamble_client_locale_format(const char *locale, WambleClientTextId id,
                                char *out, size_t out_size, ...);

#endif
