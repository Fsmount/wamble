#include "common/wamble_test.h"
#include "wamble/wamble.h"
#include <math.h>
#include <string.h>

WAMBLE_TEST(prediction_config_loads_prediction_options) {
  const char *cfg_path = "build/test_prediction_config.conf";
  FILE *f = fopen(cfg_path, "wb");
  T_ASSERT(f != NULL);
  fputs("(def prediction-mode 2)\n"
        "(def prediction-base-points 1.5)\n"
        "(def prediction-streak-multiplier 3.0)\n"
        "(def prediction-streak-cap 7)\n"
        "(def prediction-gated-percent 42)\n"
        "(def prediction-penalty-incorrect 0.25)\n"
        "(def prediction-match-policy \"from-to-only\")\n"
        "(def prediction-view-depth-limit 4)\n"
        "(def prediction-max-pending 9)\n",
        f);
  fclose(f);

  T_ASSERT_STATUS(config_load(cfg_path, NULL, NULL, 0), CONFIG_LOAD_OK);
  const WambleConfig *cfg = get_config();
  T_ASSERT(cfg != NULL);
  T_ASSERT_EQ_INT(cfg->prediction_mode, 2);
  T_ASSERT(fabs(cfg->prediction_base_points - 1.5) < 0.001);
  T_ASSERT(fabs(cfg->prediction_streak_multiplier - 3.0) < 0.001);
  T_ASSERT_EQ_INT(cfg->prediction_streak_cap, 7);
  T_ASSERT_EQ_INT(cfg->prediction_gated_percent, 42);
  T_ASSERT(fabs(cfg->prediction_penalty_incorrect - 0.25) < 0.001);
  T_ASSERT(strcmp(cfg->prediction_match_policy, "from-to-only") == 0);
  T_ASSERT_EQ_INT(cfg->prediction_view_depth_limit, 4);
  T_ASSERT_EQ_INT(cfg->prediction_max_pending, 9);
  return 0;
}

WAMBLE_TESTS_BEGIN_NAMED(prediction_tests) {
  WAMBLE_TESTS_ADD_FM(prediction_config_loads_prediction_options, "prediction");
}
WAMBLE_TESTS_END()
