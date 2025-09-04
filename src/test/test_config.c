#ifdef TEST_CONFIG
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../../include/wamble/wamble.h"

static const char *conf_path = "build/test_config.conf";

static void write_config_file(void) {
  const char *cfg = "(def log-level 3)\n"
                    "(def log-level-network 4)\n"
                    "(defn add2 (a b) (+ a b))\n"
                    "(def timeout-ms (add2 40 2))\n"
                    "(defmacro inc (x) (do (+ x 1)))\n"
                    "(def max-retries (inc 3))\n"
                    "(defprofile base ((def port 8888) (def advertise 1) (def "
                    "visibility 1)))\n"
                    "(defprofile canary :inherits base ((def port 8891) (def "
                    "visibility 2)))\n";
  FILE *f = fopen(conf_path, "w");
  assert(f);
  fwrite(cfg, 1, strlen(cfg), f);
  fclose(f);
}

int main(void) {
  write_config_file();
  config_load(conf_path, NULL, NULL, 0);

  assert(get_config()->timeout_ms == 42);
  assert(get_config()->max_retries == 4);

  assert(get_config()->log_level == 3);
  assert(get_config()->log_level_network == 4);

  int n = config_profile_count();
  assert(n >= 2);
  const WambleProfile *base = config_find_profile("base");
  const WambleProfile *canary = config_find_profile("canary");
  assert(base && canary);
  assert(base->advertise == 1);
  assert(base->visibility == 1);
  assert(base->config.port == 8888);
  assert(canary->config.port == 8891);
  assert(canary->visibility == 2);

  assert(canary->advertise == 1);

  printf("config basic eval PASSED\n");
  return 0;
}
#endif
