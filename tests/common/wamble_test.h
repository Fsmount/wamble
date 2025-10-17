#ifndef WAMBLE_TEST_H
#define WAMBLE_TEST_H

#include "wamble/wamble.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "wamble_test_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) || defined(__clang__)
#define WAMBLE_TEST_THREAD_LOCAL __thread
#elif defined(_MSC_VER)
#define WAMBLE_TEST_THREAD_LOCAL __declspec(thread)
#else
#define WAMBLE_TEST_THREAD_LOCAL
#endif

extern WAMBLE_TEST_THREAD_LOCAL char g_wamble_test_fail_msg[1024];
extern WAMBLE_TEST_THREAD_LOCAL const char *g_wamble_test_fail_file;
extern WAMBLE_TEST_THREAD_LOCAL int g_wamble_test_fail_line;

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
#define WAMBLE_TESTS_BEGIN_NAMED(fnname) void fnname(void) {
#define WAMBLE_TESTS_ADD(name)                                                 \
  wamble_test_register_ex(#name, NULL, name, NULL, NULL, 0)
#define WAMBLE_TESTS_ADD_EX(name, tags, setup, teardown, timeout_ms)           \
  wamble_test_register_ex(#name, tags, name, setup, teardown, timeout_ms)
#define WAMBLE_TESTS_END() }

#define WAMBLE_TESTS_BEGIN_DB()                                                \
  void wamble_register_tests(void) {                                           \
    if (wamble_should_skip_db_tests())                                         \
      return;

#define WAMBLE_PARAM_TEST(type, name) static int name(const type *tc)
#define WAMBLE_PARAM_REGISTER(type, fn, base_name, tags, arr, timeout_ms)      \
  wamble_param_register(base_name, tags, (wamble_param_test_fn)(fn),           \
                        (const void *)(arr), sizeof(type),                     \
                        (int)(sizeof(arr) / sizeof((arr)[0])), timeout_ms,     \
                        NULL, NULL)

#define WAMBLE_MK_TAGS(suite_lit, module_lit)                                  \
  "suite=" suite_lit " module=" module_lit

#define WAMBLE_TESTS_ADD_SM(name, suite_lit, module_lit)                       \
  wamble_test_register_ex(#name, WAMBLE_MK_TAGS(suite_lit, module_lit), name,  \
                          NULL, NULL, 0)

#define WAMBLE_TESTS_ADD_EX_SM(name, suite_lit, module_lit, setup, teardown,   \
                               timeout_ms)                                     \
  wamble_test_register_ex(#name, WAMBLE_MK_TAGS(suite_lit, module_lit), name,  \
                          setup, teardown, timeout_ms)

#define WAMBLE_PARAM_REGISTER_SM(type, fn, base_name, suite_lit, module_lit,   \
                                 arr, timeout_ms)                              \
  wamble_param_register(base_name, WAMBLE_MK_TAGS(suite_lit, module_lit),      \
                        (wamble_param_test_fn)(fn), (const void *)(arr),       \
                        sizeof(type), (int)(sizeof(arr) / sizeof((arr)[0])),   \
                        timeout_ms, NULL, NULL)

#define WAMBLE_SUITE_FUNCTIONAL "functional"
#define WAMBLE_SUITE_PERFORMANCE "performance"
#define WAMBLE_SUITE_SPEED "speed"
#define WAMBLE_SUITE_STRESS "stress"

#define WAMBLE_TESTS_ADD_FM(name, module_lit)                                  \
  WAMBLE_TESTS_ADD_SM(name, WAMBLE_SUITE_FUNCTIONAL, module_lit)

#define WAMBLE_TESTS_ADD_EX_FM(name, module_lit, setup, teardown, timeout_ms)  \
  WAMBLE_TESTS_ADD_EX_SM(name, WAMBLE_SUITE_FUNCTIONAL, module_lit, setup,     \
                         teardown, timeout_ms)

#define T_FAIL(fmt, ...)                                                       \
  do {                                                                         \
    g_wamble_test_fail_file = __FILE__;                                        \
    g_wamble_test_fail_line = __LINE__;                                        \
    snprintf(g_wamble_test_fail_msg, sizeof(g_wamble_test_fail_msg), fmt,      \
             ##__VA_ARGS__);                                                   \
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

#define T_ASSERT_STATUS_OK(status)                                             \
  do {                                                                         \
    int _s = (int)(status);                                                    \
    if (_s != 0)                                                               \
      T_FAIL("Expected status OK (0), but got %d for %s (errno=%d %s)", _s,    \
             #status, wamble_last_error(),                                     \
             wamble_strerror(wamble_last_error()));                            \
  } while (0)

#define T_ASSERT_STATUS(status, expected)                                      \
  do {                                                                         \
    int _s = (int)(status);                                                    \
    int _e = (int)(expected);                                                  \
    if (_s != _e)                                                              \
      T_FAIL("Expected status %d, but got %d for %s", _e, _s, #status);        \
  } while (0)

#ifdef __cplusplus
}
#endif

#endif
