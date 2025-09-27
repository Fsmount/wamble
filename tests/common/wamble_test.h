#ifndef WAMBLE_TEST_H
#define WAMBLE_TEST_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*wamble_test_fn)(void);
typedef void (*wamble_hook_fn)(void);
typedef int (*wamble_param_test_fn)(const void *case_data);

typedef struct {
  const char *name;
  const char *tags;
  wamble_test_fn fn;
  wamble_hook_fn setup;
  wamble_hook_fn teardown;
  int timeout_ms;
  const void *param_data;
  wamble_param_test_fn param_fn;
} wamble_test_case;

void wamble_test_register_ex(const char *name, const char *tags,
                             wamble_test_fn fn, wamble_hook_fn setup,
                             wamble_hook_fn teardown, int timeout_ms);
int wamble_test_main(int argc, char **argv);

void wamble_register_tests(void);

void wamble_param_register(const char *base_name, const char *tags,
                           wamble_param_test_fn fn, const void *cases,
                           size_t case_size, int count, int timeout_ms,
                           wamble_hook_fn setup, wamble_hook_fn teardown);

#define WAMBLE_TEST(name) static int name(void)

#define WAMBLE_TESTS_BEGIN() void wamble_register_tests(void) {
#define WAMBLE_TESTS_ADD(name)                                                 \
  wamble_test_register_ex(#name, NULL, name, NULL, NULL, 0)
#define WAMBLE_TESTS_ADD_EX(name, tags, setup, teardown, timeout_ms)           \
  wamble_test_register_ex(#name, tags, name, setup, teardown, timeout_ms)
#define WAMBLE_TESTS_END() }

#define WAMBLE_PARAM_TEST(type, name) static int name(const type *tc)
#define WAMBLE_PARAM_REGISTER(type, fn, base_name, tags, arr, timeout_ms)      \
  wamble_param_register(base_name, tags, (wamble_param_test_fn)(fn),           \
                        (const void *)(arr), sizeof(type),                     \
                        (int)(sizeof(arr) / sizeof((arr)[0])), timeout_ms,     \
                        NULL, NULL)

#define T_FAIL(fmt, ...)                                                       \
  do {                                                                         \
    fprintf(stderr, "FAIL %s:%d: " fmt "\n", __FILE__, __LINE__,               \
            ##__VA_ARGS__);                                                    \
    return 1;                                                                  \
  } while (0)

#define T_ASSERT(cond)                                                         \
  do {                                                                         \
    if (!(cond))                                                               \
      T_FAIL("Assertion failed: %s", #cond);                                   \
  } while (0)

#define T_ASSERT_EQ_INT(a, b)                                                  \
  do {                                                                         \
    long _aa = (long)(a), _bb = (long)(b);                                     \
    if (_aa != _bb)                                                            \
      T_FAIL("Expected %ld == %ld", _aa, _bb);                                 \
  } while (0)

#define T_ASSERT_STREQ(a, b)                                                   \
  do {                                                                         \
    const char *_aa = (a), *_bb = (b);                                         \
    if (!_aa || !_bb || strcmp(_aa, _bb) != 0)                                 \
      T_FAIL("Expected strings equal");                                        \
  } while (0)

#ifdef __cplusplus
}
#endif

#endif
