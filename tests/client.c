#include "common/wamble_test.h"
#include "wamble/wamble_client.h"

static int overwrite_last_word(char *out, size_t out_size, const char *mnemonic,
                               const char *replacement) {
  const char *last_space = strrchr(mnemonic, ' ');
  size_t prefix_len = last_space ? (size_t)(last_space - mnemonic + 1) : 0;
  if (prefix_len == 0)
    return -1;
  return snprintf(out, out_size, "%.*s%s", (int)prefix_len, mnemonic,
                  replacement) > 0
             ? 0
             : -1;
}

WAMBLE_TEST(client_mnemonic_wordlist_shape) {
  char words[WAMBLE_CLIENT_MNEMONIC_WORDLIST_COUNT]
            [WAMBLE_CLIENT_MNEMONIC_WORD_MAX + 1];
  for (uint16_t i = 0; i < WAMBLE_CLIENT_MNEMONIC_WORDLIST_COUNT; i++) {
    T_ASSERT_STATUS_OK(wamble_client_mnemonic_word_at(i, words[i]));
    T_ASSERT(strlen(words[i]) >= WAMBLE_CLIENT_MNEMONIC_WORD_MIN);
    T_ASSERT(strlen(words[i]) <= WAMBLE_CLIENT_MNEMONIC_WORD_MAX);
    for (size_t j = 0; words[i][j]; j++) {
      T_ASSERT(words[i][j] >= 'a' && words[i][j] <= 'z');
    }
    {
      uint16_t idx = UINT16_MAX;
      T_ASSERT_STATUS_OK(wamble_client_mnemonic_word_index(words[i], &idx));
      T_ASSERT_EQ_INT((int)idx, (int)i);
    }
  }
  for (uint16_t i = 0; i < WAMBLE_CLIENT_MNEMONIC_WORDLIST_COUNT; i++) {
    for (uint16_t j = (uint16_t)(i + 1);
         j < WAMBLE_CLIENT_MNEMONIC_WORDLIST_COUNT; j++) {
      T_ASSERT(strcmp(words[i], words[j]) != 0);
    }
  }
  {
    char word[WAMBLE_CLIENT_MNEMONIC_WORD_MAX + 1];
    T_ASSERT_STATUS_OK(wamble_client_mnemonic_word_at(0, word));
    T_ASSERT_STREQ(word, "the");
    T_ASSERT_STATUS_OK(wamble_client_mnemonic_word_at(1, word));
    T_ASSERT_STREQ(word, "to");
    T_ASSERT_STATUS_OK(wamble_client_mnemonic_word_at(2, word));
    T_ASSERT_STREQ(word, "and");
    T_ASSERT_STATUS_OK(wamble_client_mnemonic_word_at(
        WAMBLE_CLIENT_MNEMONIC_WORDLIST_COUNT - 1, word));
    T_ASSERT_STREQ(word, "cams");
    T_ASSERT(wamble_client_mnemonic_word_at(
                 WAMBLE_CLIENT_MNEMONIC_WORDLIST_COUNT, word) != 0);
  }
  return 0;
}

WAMBLE_TEST(client_mnemonic_roundtrip) {
  uint8_t seed[WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH];
  uint8_t decoded[WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH];
  char text[WAMBLE_CLIENT_MNEMONIC_TEXT_MAX];
  for (int i = 0; i < WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH; i++)
    seed[i] = (uint8_t)(0x10 + i * 9);
  T_ASSERT_STATUS_OK(wamble_client_mnemonic_seed_to_text(seed, text));
  T_ASSERT(strlen(text) < WAMBLE_CLIENT_MNEMONIC_TEXT_MAX);
  {
    int spaces = 0;
    for (size_t i = 0; text[i]; i++) {
      if (text[i] == ' ') {
        spaces++;
        continue;
      }
      T_ASSERT(text[i] >= 'a' && text[i] <= 'z');
    }
    T_ASSERT_EQ_INT(spaces, WAMBLE_CLIENT_MNEMONIC_WORD_COUNT - 1);
  }
  T_ASSERT_STATUS_OK(wamble_client_mnemonic_text_to_seed(text, decoded));
  T_ASSERT(memcmp(seed, decoded, sizeof(seed)) == 0);
  {
    char mixed[WAMBLE_CLIENT_MNEMONIC_TEXT_MAX + 24];
    size_t out = 0;
    mixed[out++] = ' ';
    mixed[out++] = ' ';
    for (size_t i = 0; text[i]; i++) {
      if (text[i] == ' ') {
        mixed[out++] = (i & 1u) ? '\n' : '\t';
        continue;
      }
      mixed[out++] = (char)toupper((unsigned char)text[i]);
    }
    mixed[out++] = ' ';
    mixed[out++] = ' ';
    mixed[out] = '\0';
    T_ASSERT_STATUS_OK(wamble_client_mnemonic_text_to_seed(mixed, decoded));
    T_ASSERT(memcmp(seed, decoded, sizeof(seed)) == 0);
  }
  return 0;
}

WAMBLE_TEST(client_mnemonic_rejects_bad_input) {
  uint8_t seed[WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH];
  uint8_t decoded[WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH];
  char mnemonic[WAMBLE_CLIENT_MNEMONIC_TEXT_MAX];
  char bad[WAMBLE_CLIENT_MNEMONIC_TEXT_MAX];
  char replacement[WAMBLE_CLIENT_MNEMONIC_WORD_MAX + 1];
  for (int i = 0; i < WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH; i++)
    seed[i] = (uint8_t)(0x70 + i * 5);
  T_ASSERT_STATUS_OK(wamble_client_mnemonic_seed_to_text(seed, mnemonic));
  T_ASSERT(wamble_client_mnemonic_text_to_seed(
               "the to and of in is for that you it on", decoded) != 0);
  T_ASSERT(wamble_client_mnemonic_text_to_seed(
               "the to and of in is for that you it on with extra", decoded) !=
           0);
  for (uint16_t i = 0; i < WAMBLE_CLIENT_MNEMONIC_WORDLIST_COUNT; i++) {
    T_ASSERT_STATUS_OK(wamble_client_mnemonic_word_at(i, replacement));
    T_ASSERT_STATUS_OK(
        overwrite_last_word(bad, sizeof(bad), mnemonic, replacement));
    if (strcmp(bad, mnemonic) == 0)
      continue;
    if (wamble_client_mnemonic_text_to_seed(bad, decoded) != 0)
      return 0;
  }
  T_ASSERT(!"expected checksum mismatch");
  return 0;
}

WAMBLE_TEST(client_identity_helpers_are_deterministic) {
  uint8_t mnemonic_seed[WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH];
  uint8_t key_seed[32];
  uint8_t key_seed_again[32];
  char mnemonic[WAMBLE_CLIENT_MNEMONIC_TEXT_MAX];
  uint8_t public_key_1[WAMBLE_PUBLIC_KEY_LENGTH];
  uint8_t secret_key_1[64];
  uint8_t public_key_2[WAMBLE_PUBLIC_KEY_LENGTH];
  uint8_t secret_key_2[64];
  uint8_t public_key_3[WAMBLE_PUBLIC_KEY_LENGTH];
  uint8_t secret_key_3[64];
  uint8_t token[TOKEN_LENGTH];
  uint8_t challenge[WAMBLE_LOGIN_CHALLENGE_LENGTH];
  uint8_t signature[WAMBLE_LOGIN_SIGNATURE_LENGTH];
  uint8_t hex_roundtrip[WAMBLE_PUBLIC_KEY_LENGTH];
  char public_key_hex[WAMBLE_CLIENT_PUBLIC_KEY_HEX_LENGTH + 1];
  for (int i = 0; i < WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH; i++)
    mnemonic_seed[i] = (uint8_t)(0x20 + i * 7);
  T_ASSERT_STATUS_OK(
      wamble_client_mnemonic_seed_to_text(mnemonic_seed, mnemonic));
  wamble_client_mnemonic_seed_to_key_seed(mnemonic_seed, key_seed);
  wamble_client_mnemonic_seed_to_key_seed(mnemonic_seed, key_seed_again);
  T_ASSERT(memcmp(key_seed, key_seed_again, sizeof(key_seed)) == 0);
  for (int i = 0; i < TOKEN_LENGTH; i++)
    token[i] = (uint8_t)(0x40 + i);
  for (int i = 0; i < WAMBLE_LOGIN_CHALLENGE_LENGTH; i++)
    challenge[i] = (uint8_t)(0x80 + i);
  T_ASSERT_STATUS_OK(wamble_client_keygen_from_mnemonic_seed(
      mnemonic_seed, public_key_1, secret_key_1));
  T_ASSERT_STATUS_OK(
      wamble_client_keygen_from_mnemonic(mnemonic, public_key_2, secret_key_2));
  T_ASSERT_STATUS_OK(
      wamble_client_keygen_from_mnemonic(mnemonic, public_key_3, secret_key_3));
  T_ASSERT(memcmp(public_key_1, public_key_2, sizeof(public_key_1)) == 0);
  T_ASSERT(memcmp(secret_key_1, secret_key_2, sizeof(secret_key_1)) == 0);
  T_ASSERT(memcmp(public_key_2, public_key_3, sizeof(public_key_2)) == 0);
  T_ASSERT(memcmp(secret_key_2, secret_key_3, sizeof(secret_key_2)) == 0);
  T_ASSERT_STATUS_OK(wamble_client_sign_challenge(
      secret_key_1, token, public_key_1, challenge, signature));
  {
    static const uint8_t golden[WAMBLE_LOGIN_SIGNATURE_LENGTH] = {
        0x32, 0x65, 0x18, 0xb4, 0xc8, 0xa0, 0x5f, 0x19, 0x0b, 0x96, 0x11,
        0x7d, 0x5b, 0x42, 0x37, 0x55, 0x2b, 0x79, 0xec, 0x3c, 0xd0, 0x0b,
        0x43, 0x6d, 0x8e, 0x0b, 0x47, 0x3a, 0x87, 0xbf, 0x02, 0x13, 0x53,
        0xc5, 0x73, 0xb2, 0xe4, 0x1a, 0xf9, 0x35, 0xd4, 0x58, 0x19, 0xb9,
        0xf9, 0x5c, 0xf6, 0x61, 0x9c, 0x1f, 0x21, 0x95, 0x14, 0x5f, 0x81,
        0xc3, 0x35, 0x4f, 0x49, 0x24, 0xb5, 0x8d, 0x33, 0x02};
    T_ASSERT(memcmp(signature, golden, sizeof(golden)) == 0);
  }
  T_ASSERT_STATUS_OK(
      wamble_client_public_key_to_hex(public_key_1, public_key_hex));
  T_ASSERT_EQ_INT((int)strlen(public_key_hex),
                  WAMBLE_CLIENT_PUBLIC_KEY_HEX_LENGTH);
  T_ASSERT_STATUS_OK(
      wamble_client_public_key_from_hex(public_key_hex, hex_roundtrip));
  T_ASSERT(memcmp(public_key_1, hex_roundtrip, sizeof(public_key_1)) == 0);
  T_ASSERT(wamble_client_public_key_from_hex("bad", hex_roundtrip) != 0);
  return 0;
}

WAMBLE_TEST(client_locale_scaffold_works) {
  char out[64];
  T_ASSERT_STREQ(
      wamble_client_locale_text(NULL, WAMBLE_CLIENT_TEXT_CREATE_SESSION),
      "Create Session");
  T_ASSERT_STREQ(
      wamble_client_locale_text("en-US", WAMBLE_CLIENT_TEXT_SESSION_READY),
      "session ready");
  T_ASSERT_STREQ(
      wamble_client_locale_text("fr", WAMBLE_CLIENT_TEXT_PUBLIC_KEY_LABEL),
      "Public Key");
  T_ASSERT_STATUS_OK(wamble_client_locale_write(
      "en", WAMBLE_CLIENT_TEXT_MNEMONIC_LABEL, out, sizeof(out)));
  T_ASSERT_STREQ(out, "Mnemonic");
  T_ASSERT_STATUS_OK(wamble_client_locale_format(
      "en", WAMBLE_CLIENT_TEXT_CONNECTED_TO, out, sizeof(out), "loopback"));
  T_ASSERT_STREQ(out, "connected to loopback");
  T_ASSERT(wamble_client_locale_write("en", WAMBLE_CLIENT_TEXT_CREATE_SESSION,
                                      out, 4) != 0);
  return 0;
}

WAMBLE_TEST(client_generate_mnemonic_seed) {
  uint8_t entropy[WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH];
  char mnemonic[WAMBLE_CLIENT_MNEMONIC_TEXT_MAX];
  char mnemonic2[WAMBLE_CLIENT_MNEMONIC_TEXT_MAX];
  uint8_t public_key[WAMBLE_PUBLIC_KEY_LENGTH];
  uint8_t secret_key[64];
  uint8_t public_key2[WAMBLE_PUBLIC_KEY_LENGTH];
  uint8_t secret_key2[64];
  uint8_t recovered_seed[WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH];
  for (int i = 0; i < WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH; i++)
    entropy[i] = (uint8_t)(0xA0 + i * 3);
  T_ASSERT_STATUS_OK(wamble_client_generate_mnemonic_seed(
      entropy, mnemonic, public_key, secret_key));
  T_ASSERT(strlen(mnemonic) > 0);
  T_ASSERT(strlen(mnemonic) < WAMBLE_CLIENT_MNEMONIC_TEXT_MAX);
  T_ASSERT_STATUS_OK(wamble_client_generate_mnemonic_seed(
      entropy, mnemonic2, public_key2, secret_key2));
  T_ASSERT_STREQ(mnemonic, mnemonic2);
  T_ASSERT(memcmp(public_key, public_key2, sizeof(public_key)) == 0);
  T_ASSERT(memcmp(secret_key, secret_key2, sizeof(secret_key)) == 0);
  T_ASSERT_STATUS_OK(
      wamble_client_mnemonic_text_to_seed(mnemonic, recovered_seed));
  T_ASSERT(
      memcmp(recovered_seed, entropy, WAMBLE_CLIENT_MNEMONIC_SEED_LENGTH) == 0);
  T_ASSERT_STATUS_OK(
      wamble_client_keygen_from_mnemonic(mnemonic, public_key2, secret_key2));
  T_ASSERT(memcmp(public_key, public_key2, sizeof(public_key)) == 0);
  T_ASSERT(memcmp(secret_key, secret_key2, sizeof(secret_key)) == 0);
  return 0;
}

WAMBLE_TEST(client_udp_connect_and_state_helpers) {
  wamble_client_t client;
  memset(&client, 0, sizeof(client));

  T_ASSERT(wamble_client_closed(NULL));
  T_ASSERT(!wamble_client_connected(NULL));

  T_ASSERT_CLIENT_STATUS_OK(
      wamble_client_connect_udp(&client, "127.0.0.1", 4242));
  T_ASSERT(wamble_client_connected(&client));
  T_ASSERT(!wamble_client_closed(&client));
  T_ASSERT_EQ_INT(client.kind, WAMBLE_TRANSPORT_UDP);
  T_ASSERT(client.sock != WAMBLE_INVALID_SOCKET);
  T_ASSERT_EQ_INT(ntohs(client.peer.sin_port), 4242);
  T_ASSERT_EQ_INT(client.seq, 1);
  T_ASSERT(wamble_client_connect_udp(&client, "", 4242).code !=
           WAMBLE_CLIENT_STATUS_OK);

  wamble_client_close(&client);
  T_ASSERT(!wamble_client_connected(&client));
  T_ASSERT(wamble_client_closed(&client));

  return 0;
}

WAMBLE_TESTS_BEGIN_NAMED(wamble_register_tests_client)
WAMBLE_TESTS_ADD_FM(client_mnemonic_wordlist_shape, "client");
WAMBLE_TESTS_ADD_FM(client_mnemonic_roundtrip, "client");
WAMBLE_TESTS_ADD_FM(client_mnemonic_rejects_bad_input, "client");
WAMBLE_TESTS_ADD_FM(client_identity_helpers_are_deterministic, "client");
WAMBLE_TESTS_ADD_FM(client_generate_mnemonic_seed, "client");
WAMBLE_TESTS_ADD_FM(client_udp_connect_and_state_helpers, "client");
WAMBLE_TESTS_ADD_FM(client_locale_scaffold_works, "client");
WAMBLE_TESTS_END()
