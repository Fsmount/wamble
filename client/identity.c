#include "wamble/wamble_client.h"

#include <ctype.h>

void crypto_blake2b(uint8_t *hash, size_t hash_size, const uint8_t *msg,
                    size_t msg_size);
void crypto_eddsa_key_pair(uint8_t secret_key[64], uint8_t public_key[32],
                           uint8_t seed[32]);
void crypto_eddsa_sign(uint8_t signature[64], const uint8_t secret_key[64],
                       const uint8_t *message, size_t message_size);
int crypto_eddsa_check(const uint8_t signature[WAMBLE_LOGIN_SIGNATURE_LENGTH],
                       const uint8_t public_key[WAMBLE_PUBLIC_KEY_LENGTH],
                       const uint8_t *message, size_t message_size);

#include "mnemonic_words.inc"

#define WAMBLE_CLIENT_MNEMONIC_TOTAL_BITS                                      \
  (WAMBLE_CLIENT_MNEMONIC_WORD_COUNT * WAMBLE_CLIENT_MNEMONIC_BITS_PER_WORD)
#define WAMBLE_CLIENT_MNEMONIC_TOTAL_BYTES                                     \
  ((WAMBLE_CLIENT_MNEMONIC_TOTAL_BITS + 7) / 8)

static int hex_nibble(int c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return 10 + (c - 'a');
  if (c >= 'A' && c <= 'F')
    return 10 + (c - 'A');
  return -1;
}

static uint8_t mnemonic_checksum(
    const uint8_t mnemonic_seed[WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH]) {
  static const uint8_t domain[] = "wamble-client-mnemonic-checksum-v1";
  uint8_t hash[32];
  uint8_t input[sizeof(domain) - 1 + WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH];
  memcpy(input, domain, sizeof(domain) - 1);
  memcpy(input + sizeof(domain) - 1, mnemonic_seed,
         WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH);
  crypto_blake2b(hash, sizeof(hash), input, sizeof(input));
  return (uint8_t)(hash[0] >> (8 - WAMBLE_CLIENT_MNEMONIC_CHECKSUM_BITS));
}

static int mnemonic_word_index_internal(const char *word, uint16_t *out_index) {
  size_t len;
  if (!word || !out_index)
    return -1;
  len = strlen(word);
  if (len < WAMBLE_CLIENT_MNEMONIC_WORD_MIN ||
      len > WAMBLE_CLIENT_MNEMONIC_WORD_MAX) {
    return -1;
  }
  for (uint16_t i = 0; i < WAMBLE_CLIENT_MNEMONIC_WORDLIST_COUNT; i++) {
    if (strcmp(word, mnemonic_words[i]) == 0) {
      *out_index = i;
      return 0;
    }
  }
  return -1;
}

static int
mnemonic_word_at_internal(uint16_t index,
                          char out[WAMBLE_CLIENT_MNEMONIC_WORD_MAX + 1]) {
  size_t len;
  if (!out || index >= WAMBLE_CLIENT_MNEMONIC_WORDLIST_COUNT)
    return -1;
  len = strlen(mnemonic_words[index]);
  memcpy(out, mnemonic_words[index], len + 1);
  return 0;
}

static int
mnemonic_text_next_word(const char **cursor,
                        char out[WAMBLE_CLIENT_MNEMONIC_WORD_MAX + 1]) {
  const char *p = cursor ? *cursor : NULL;
  size_t len = 0;
  if (!p || !out)
    return -1;
  while (*p && isspace((unsigned char)*p))
    p++;
  if (!*p)
    return -1;
  while (*p && !isspace((unsigned char)*p)) {
    if (len >= WAMBLE_CLIENT_MNEMONIC_WORD_MAX)
      return -1;
    if (!isalpha((unsigned char)*p))
      return -1;
    out[len++] = (char)tolower((unsigned char)*p++);
  }
  if (len < WAMBLE_CLIENT_MNEMONIC_WORD_MIN ||
      len > WAMBLE_CLIENT_MNEMONIC_WORD_MAX) {
    return -1;
  }
  out[len] = '\0';
  *cursor = p;
  return 0;
}

static uint16_t mnemonic_bits_read_index(const uint8_t *bits,
                                         size_t word_index) {
  size_t bit_offset = word_index * WAMBLE_CLIENT_MNEMONIC_BITS_PER_WORD;
  uint16_t value = 0;
  for (size_t bit = 0; bit < WAMBLE_CLIENT_MNEMONIC_BITS_PER_WORD; bit++) {
    size_t absolute_bit = bit_offset + bit;
    uint8_t byte = bits[absolute_bit / 8];
    uint8_t mask = (uint8_t)(0x80u >> (absolute_bit % 8));
    value = (uint16_t)((value << 1) | ((byte & mask) != 0 ? 1u : 0u));
  }
  return value;
}

static void mnemonic_bits_write_index(uint8_t *bits, size_t word_index,
                                      uint16_t value) {
  size_t bit_offset = word_index * WAMBLE_CLIENT_MNEMONIC_BITS_PER_WORD;
  for (size_t bit = 0; bit < WAMBLE_CLIENT_MNEMONIC_BITS_PER_WORD; bit++) {
    size_t absolute_bit = bit_offset + bit;
    size_t shift = WAMBLE_CLIENT_MNEMONIC_BITS_PER_WORD - bit - 1;
    uint8_t bit_value = (uint8_t)((value >> shift) & 1u);
    uint8_t *byte = &bits[absolute_bit / 8];
    uint8_t mask = (uint8_t)(0x80u >> (absolute_bit % 8));
    if (bit_value)
      *byte = (uint8_t)(*byte | mask);
    else
      *byte = (uint8_t)(*byte & (uint8_t)~mask);
  }
}

static void mnemonic_seed_pack(
    const uint8_t mnemonic_seed[WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH],
    uint8_t packed[WAMBLE_CLIENT_MNEMONIC_TOTAL_BYTES]) {
  memset(packed, 0, WAMBLE_CLIENT_MNEMONIC_TOTAL_BYTES);
  memcpy(packed, mnemonic_seed, WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH);
  packed[WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH] =
      (uint8_t)(mnemonic_checksum(mnemonic_seed)
                << (8 - WAMBLE_CLIENT_MNEMONIC_CHECKSUM_BITS));
}

static int mnemonic_seed_unpack(
    const uint8_t packed[WAMBLE_CLIENT_MNEMONIC_TOTAL_BYTES],
    uint8_t mnemonic_seed[WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH]) {
  uint8_t expected;
  if (!packed || !mnemonic_seed)
    return -1;
  memcpy(mnemonic_seed, packed, WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH);
  expected = mnemonic_checksum(mnemonic_seed);
  return expected == (uint8_t)(packed[WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH] >>
                               (8 - WAMBLE_CLIENT_MNEMONIC_CHECKSUM_BITS))
             ? 0
             : -1;
}

void wamble_client_keygen(const uint8_t seed[32],
                          uint8_t public_key[WAMBLE_PUBLIC_KEY_LENGTH],
                          uint8_t secret_key[64]) {
  if (!seed || !public_key || !secret_key)
    return;
  crypto_eddsa_key_pair(secret_key, public_key, (uint8_t *)seed);
}

void wamble_client_mnemonic_seed_to_key_seed(
    const uint8_t mnemonic_seed[WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH],
    uint8_t seed[32]) {
  static const uint8_t domain[] = "wamble-client-mnemonic-v1";
  uint8_t input[sizeof(domain) - 1 + WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH];
  if (!mnemonic_seed || !seed)
    return;
  memcpy(input, domain, sizeof(domain) - 1);
  memcpy(input + sizeof(domain) - 1, mnemonic_seed,
         WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH);
  crypto_blake2b(seed, 32, input, sizeof(input));
}

int wamble_client_keygen_from_mnemonic_seed(
    const uint8_t mnemonic_seed[WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH],
    uint8_t public_key[WAMBLE_PUBLIC_KEY_LENGTH], uint8_t secret_key[64]) {
  uint8_t seed[32];
  if (!mnemonic_seed || !public_key || !secret_key)
    return -1;
  wamble_client_mnemonic_seed_to_key_seed(mnemonic_seed, seed);
  wamble_client_keygen(seed, public_key, secret_key);
  return 0;
}

int wamble_client_keygen_from_mnemonic(
    const char *mnemonic, uint8_t public_key[WAMBLE_PUBLIC_KEY_LENGTH],
    uint8_t secret_key[64]) {
  uint8_t mnemonic_seed[WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH];
  if (wamble_client_mnemonic_text_to_seed(mnemonic, mnemonic_seed) != 0)
    return -1;
  return wamble_client_keygen_from_mnemonic_seed(mnemonic_seed, public_key,
                                                 secret_key);
}

int wamble_client_sign_challenge(
    const uint8_t secret_key[64], const uint8_t token[TOKEN_LENGTH],
    const uint8_t public_key[WAMBLE_PUBLIC_KEY_LENGTH],
    const uint8_t challenge[WAMBLE_LOGIN_CHALLENGE_LENGTH],
    uint8_t signature[WAMBLE_LOGIN_SIGNATURE_LENGTH]) {
  if (!secret_key || !token || !public_key || !challenge || !signature)
    return -1;
  {
    uint8_t msg[256];
    size_t msg_len = wamble_build_login_signature_message(
        msg, sizeof(msg), token, public_key, challenge);
    if (msg_len == 0)
      return -1;
    crypto_eddsa_sign(signature, secret_key, msg, msg_len);
  }
  return 0;
}

int wamble_client_public_key_to_hex(
    const uint8_t public_key[WAMBLE_PUBLIC_KEY_LENGTH],
    char out[WAMBLE_CLIENT_PUBLIC_KEY_HEX_LENGTH + 1]) {
  static const char hex[] = "0123456789abcdef";
  if (!public_key || !out)
    return -1;
  for (int i = 0; i < WAMBLE_PUBLIC_KEY_LENGTH; i++) {
    out[i * 2] = hex[(public_key[i] >> 4) & 0x0F];
    out[i * 2 + 1] = hex[public_key[i] & 0x0F];
  }
  out[WAMBLE_CLIENT_PUBLIC_KEY_HEX_LENGTH] = '\0';
  return 0;
}

int wamble_client_public_key_from_hex(
    const char *hex, uint8_t public_key[WAMBLE_PUBLIC_KEY_LENGTH]) {
  if (!hex || !public_key ||
      strlen(hex) != (size_t)WAMBLE_CLIENT_PUBLIC_KEY_HEX_LENGTH) {
    return -1;
  }
  for (int i = 0; i < WAMBLE_PUBLIC_KEY_LENGTH; i++) {
    int hi = hex_nibble((unsigned char)hex[i * 2]);
    int lo = hex_nibble((unsigned char)hex[i * 2 + 1]);
    if (hi < 0 || lo < 0)
      return -1;
    public_key[i] = (uint8_t)((hi << 4) | lo);
  }
  return 0;
}

int wamble_client_mnemonic_word_at(
    uint16_t index, char out[WAMBLE_CLIENT_MNEMONIC_WORD_MAX + 1]) {
  return mnemonic_word_at_internal(index, out);
}

int wamble_client_mnemonic_word_index(const char *word, uint16_t *out_index) {
  return mnemonic_word_index_internal(word, out_index);
}

int wamble_client_mnemonic_seed_to_text(
    const uint8_t mnemonic_seed[WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH],
    char out[WAMBLE_CLIENT_MNEMONIC_TEXT_MAX]) {
  uint8_t packed[WAMBLE_CLIENT_MNEMONIC_TOTAL_BYTES];
  size_t written = 0;
  if (!mnemonic_seed || !out)
    return -1;
  mnemonic_seed_pack(mnemonic_seed, packed);
  for (int i = 0; i < WAMBLE_CLIENT_MNEMONIC_WORD_COUNT; i++) {
    char word[WAMBLE_CLIENT_MNEMONIC_WORD_MAX + 1];
    size_t len;
    uint16_t index = mnemonic_bits_read_index(packed, (size_t)i);
    if (mnemonic_word_at_internal(index, word) != 0)
      return -1;
    len = strlen(word);
    if (written + len + (i > 0 ? 1u : 0u) >= WAMBLE_CLIENT_MNEMONIC_TEXT_MAX)
      return -1;
    if (i > 0)
      out[written++] = ' ';
    memcpy(out + written, word, len);
    written += len;
  }
  out[written] = '\0';
  return 0;
}

int wamble_client_mnemonic_text_to_seed(
    const char *mnemonic,
    uint8_t mnemonic_seed[WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH]) {
  const char *cursor = mnemonic;
  uint8_t packed[WAMBLE_CLIENT_MNEMONIC_TOTAL_BYTES];
  if (!mnemonic || !mnemonic_seed)
    return -1;
  memset(packed, 0, sizeof(packed));
  for (int i = 0; i < WAMBLE_CLIENT_MNEMONIC_WORD_COUNT; i++) {
    char word[WAMBLE_CLIENT_MNEMONIC_WORD_MAX + 1];
    uint16_t index = 0;
    if (mnemonic_text_next_word(&cursor, word) != 0 ||
        mnemonic_word_index_internal(word, &index) != 0) {
      return -1;
    }
    mnemonic_bits_write_index(packed, (size_t)i, index);
  }
  while (*cursor && isspace((unsigned char)*cursor))
    cursor++;
  if (*cursor)
    return -1;
  return mnemonic_seed_unpack(packed, mnemonic_seed);
}

int wamble_client_generate_mnemonic_seed(
    const uint8_t entropy[WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH],
    char out_mnemonic[WAMBLE_CLIENT_MNEMONIC_TEXT_MAX],
    uint8_t out_public_key[WAMBLE_PUBLIC_KEY_LENGTH],
    uint8_t out_secret_key[64]) {
  if (!entropy || !out_mnemonic || !out_public_key || !out_secret_key)
    return -1;
  if (wamble_client_mnemonic_seed_to_text(entropy, out_mnemonic) != 0)
    return -1;
  return wamble_client_keygen_from_mnemonic_seed(entropy, out_public_key,
                                                 out_secret_key);
}
