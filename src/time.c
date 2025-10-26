#include "../include/wamble/wamble.h"

uint64_t wamble_now_mono_millis(void) {
#if defined(WAMBLE_PLATFORM_WINDOWS)
  LARGE_INTEGER freq, counter;
  if (QueryPerformanceFrequency(&freq) && QueryPerformanceCounter(&counter)) {
    return (uint64_t)((counter.QuadPart * 1000ULL) / (uint64_t)freq.QuadPart);
  }
  return (uint64_t)GetTickCount64();
#else
  struct timespec ts;
#ifdef CLOCK_MONOTONIC
  if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
#endif
  if (clock_gettime(CLOCK_REALTIME, &ts) == 0)
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
  return (uint64_t)time(NULL) * 1000ULL;
#endif
}

time_t wamble_now_wall(void) { return time(NULL); }

uint64_t wamble_now_nanos(void) {
#if defined(WAMBLE_PLATFORM_WINDOWS)
  LARGE_INTEGER freq, counter;
  if (QueryPerformanceFrequency(&freq) && QueryPerformanceCounter(&counter)) {
    uint64_t f = (uint64_t)freq.QuadPart;
    uint64_t c = (uint64_t)counter.QuadPart;
    uint64_t sec = c / f;
    uint64_t rem = c % f;
    uint64_t nanos = sec * 1000000000ULL + (rem * 1000000000ULL) / f;
    return nanos;
  }
  return (uint64_t)GetTickCount64() * 1000000ULL;
#elif defined(WAMBLE_PLATFORM_POSIX)
  struct timespec ts;
#ifdef CLOCK_MONOTONIC
  if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
  if (clock_gettime(CLOCK_REALTIME, &ts) == 0)
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
  return (uint64_t)time(NULL) * 1000000000ULL;
#else
  return (uint64_t)time(NULL) * 1000000000ULL;
#endif
}

int gmtime_w(struct tm *out_tm, const time_t *timer) {
#if defined(WAMBLE_PLATFORM_WINDOWS)
  return (gmtime_s(out_tm, timer) == 0) ? 1 : 0;
#elif defined(WAMBLE_PLATFORM_POSIX)
#if defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L
  return (gmtime_r(timer, out_tm) != NULL) ? 1 : 0;
#else
  struct tm *tmp = gmtime(timer);
  if (!tmp)
    return 0;
  *out_tm = *tmp;
  return 1;
#endif
#else
  (void)out_tm;
  (void)timer;
  return 0;
#endif
}
