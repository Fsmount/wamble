#include "../include/wamble/wamble.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>

static WAMBLE_THREAD_LOCAL WambleBoard *board_cached;
static WAMBLE_THREAD_LOCAL int num_cached_boards = 0;
static WAMBLE_THREAD_LOCAL int total_boards = 0;
static WAMBLE_THREAD_LOCAL time_t last_count_update = 0;
static WAMBLE_THREAD_LOCAL uint64_t next_board_id = 1;
static WAMBLE_THREAD_LOCAL wamble_mutex_t next_board_id_mutex;
static WAMBLE_THREAD_LOCAL int next_board_id_initialized = 0;
static WAMBLE_THREAD_LOCAL int next_board_id_mutex_initialized = 0;
static WAMBLE_THREAD_LOCAL wamble_mutex_t board_mutex;
static WAMBLE_THREAD_LOCAL int board_mutex_initialized = 0;

#define BOARD_MAP_SIZE (get_config()->max_boards * 2)
static WAMBLE_THREAD_LOCAL int *board_index_map;
#define INITIAL_BOARD_FEN                                                      \
  "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1"
#define INITIAL_BOARD_STATUS "DORMANT"
#define NO_CHESS960_POSITION (-1)

static int board_should_be_chess960(uint64_t board_id) {
  int interval = get_config()->chess960_interval;
  if (interval < 0)
    return 0;
  if (interval == 0)
    return 1;
  return (board_id % (uint64_t)interval) == 0;
}

static int board_get_chess960_position(uint64_t board_id) {
  return (int)(board_id % 960);
}

static inline uint64_t mix64_hash(uint64_t x) {
  x ^= x >> 33;
  x *= 0xff51afd7ed558ccdULL;
  x ^= x >> 33;
  x *= 0xc4ceb9fe1a85ec53ULL;
  x ^= x >> 33;
  return x;
}

static int board_manager_ready(void) {
  return board_mutex_initialized && board_cached && board_index_map &&
         get_config()->max_boards > 0;
}

static int board_map_capacity(void) {
  int cap = BOARD_MAP_SIZE;
  return cap > 0 ? cap : 0;
}

static int board_map_next(int idx, int cap) {
  idx++;
  if (idx >= cap)
    idx = 0;
  return idx;
}

static void ensure_board_id_mutex(void) {
  if (!next_board_id_mutex_initialized) {
    wamble_mutex_init(&next_board_id_mutex);
    next_board_id_mutex_initialized = 1;
  }
}

static uint64_t alloc_board_id(void) {
  ensure_board_id_mutex();
  wamble_mutex_lock(&next_board_id_mutex);
  if (!next_board_id_initialized) {
    if (next_board_id == 0)
      next_board_id = 1;
    next_board_id_initialized = 1;
  }
  uint64_t id = next_board_id++;
  wamble_mutex_unlock(&next_board_id_mutex);
  return id;
}

static void board_map_put(uint64_t id, int index) {
  int cap = board_map_capacity();
  if (!board_index_map || cap <= 0)
    return;
  uint64_t h = mix64_hash(id);
  int i = (int)(h % (uint64_t)cap);
  for (int probe = 0; probe < cap; probe++) {
    if (board_index_map[i] == -1) {
      board_index_map[i] = index;
      return;
    }
    i = board_map_next(i, cap);
  }
}

static int board_map_get(uint64_t id) {
  int cap = board_map_capacity();
  if (!board_index_map || !board_cached || cap <= 0)
    return -1;
  uint64_t h = mix64_hash(id);
  int i = (int)(h % (uint64_t)cap);
  for (int probe = 0; probe < cap; probe++) {
    int idx = board_index_map[i];
    if (idx == -1)
      return -1;
    if (idx >= 0 && board_cached[idx].id == id)
      return idx;
    i = board_map_next(i, cap);
  }
  return -1;
}

static BoardState board_state_from_string(const char *s) {
  if (!s)
    return BOARD_STATE_DORMANT;
  if (strcmp(s, "RESERVED") == 0)
    return BOARD_STATE_RESERVED;
  if (strcmp(s, "ACTIVE") == 0)
    return BOARD_STATE_ACTIVE;
  if (strcmp(s, "ARCHIVED") == 0)
    return BOARD_STATE_ARCHIVED;
  return BOARD_STATE_DORMANT;
}

static void remove_board_from_cache(int cache_index);
static void transition_reserved_to_dormant(WambleBoard *board);
static int find_cache_slot_for_board(void);

static int token_is_zero(const uint8_t *token) {
  if (!token)
    return 1;
  for (int i = 0; i < TOKEN_LENGTH; i++) {
    if (token[i] != 0)
      return 0;
  }
  return 1;
}

void board_manager_tick() {
  if (!board_manager_ready())
    return;
  time_t now = wamble_now_wall();
  int refresh_board_supply = 0;

  wamble_mutex_lock(&board_mutex);

  for (int i = num_cached_boards - 1; i >= 0; i--) {
    WambleBoard *board = &board_cached[i];

    if (board->state == BOARD_STATE_RESERVED) {
      if (token_is_zero(board->reservation_player_token)) {
        transition_reserved_to_dormant(board);
        continue;
      }
      time_t reservation_age = now - board->reservation_time;
      if (reservation_age >= get_config()->reservation_timeout) {
        WamblePlayer *player =
            get_player_by_token(board->reservation_player_token);
        if (!player || !player->has_persistent_identity) {
          transition_reserved_to_dormant(board);
        }
      }
    }

    if (board->state == BOARD_STATE_ACTIVE) {
      time_t inactive_time = now - board->last_move_time;
      if (inactive_time >= get_config()->inactivity_timeout) {
        board->state = BOARD_STATE_DORMANT;
        wamble_emit_update_board(board->id, board->fen, "DORMANT");
      }
    }
  }

  if (now - last_count_update >= 60)
    refresh_board_supply = 1;

  wamble_mutex_unlock(&board_mutex);

  if (!refresh_board_supply)
    return;

  DbBoardIdList dormant = wamble_query_list_boards_by_status("DORMANT");
  DbBoardIdList active = wamble_query_list_boards_by_status("ACTIVE");
  DbBoardIdList reserved = wamble_query_list_boards_by_status("RESERVED");
  bool lists_ok = (dormant.status == DB_OK && active.status == DB_OK &&
                   reserved.status == DB_OK);
  if (!lists_ok)
    return;

  int observed_total_boards = dormant.count + active.count + reserved.count;
  int longest_game = 0;
  int players = 0;
  (void)wamble_query_get_longest_game_moves(&longest_game);
  (void)wamble_query_get_active_session_count(&players);
  int target_boards = longest_game * players;
  if (target_boards < get_config()->min_boards)
    target_boards = get_config()->min_boards;
  if (target_boards > get_config()->max_boards)
    target_boards = get_config()->max_boards;

  int boards_to_create = target_boards - observed_total_boards;
  int created_count = 0;
  for (int i = 0; i < boards_to_create; i++) {
    if (observed_total_boards + created_count >= get_config()->max_boards)
      break;
    uint64_t new_board_id = alloc_board_id();
    int c960_pos = NO_CHESS960_POSITION;
    const char *fen_to_use = INITIAL_BOARD_FEN;
    char c960_fen[FEN_MAX_LENGTH];
    if (board_should_be_chess960(new_board_id)) {
      c960_pos = board_get_chess960_position(new_board_id);
      chess960_gen_fen(c960_pos, c960_fen, sizeof(c960_fen));
      fen_to_use = c960_fen;
    }
    wamble_emit_create_board(new_board_id, fen_to_use, INITIAL_BOARD_STATUS,
                             c960_pos);
    created_count++;
  }

  wamble_mutex_lock(&board_mutex);
  total_boards = observed_total_boards + created_count;
  last_count_update = now;
  wamble_mutex_unlock(&board_mutex);
}

void board_manager_init(void) {
  if (board_cached || board_index_map) {
    free(board_cached);
    free(board_index_map);
    board_cached = NULL;
    board_index_map = NULL;
  }
  if (board_mutex_initialized) {
    wamble_mutex_destroy(&board_mutex);
    board_mutex_initialized = 0;
  }
  num_cached_boards = 0;
  total_boards = 0;
  last_count_update = 0;
  next_board_id = 1;
  next_board_id_initialized = 0;
  wamble_mutex_init(&board_mutex);
  board_mutex_initialized = 1;
  if (get_config()->max_boards <= 0)
    return;
  board_cached = malloc(sizeof(WambleBoard) * (size_t)get_config()->max_boards);
  board_index_map =
      malloc(sizeof(int) * (size_t)(get_config()->max_boards * 2));
  if (!board_cached || !board_index_map) {
    free(board_cached);
    free(board_index_map);
    board_cached = NULL;
    board_index_map = NULL;
    return;
  }
  memset(board_cached, 0,
         sizeof(WambleBoard) * (size_t)get_config()->max_boards);
  rng_init();
  for (int i = 0; i < BOARD_MAP_SIZE; i++)
    board_index_map[i] = -1;

  DbBoardIdList dormant = wamble_query_list_boards_by_status("DORMANT");
  DbBoardIdList active = wamble_query_list_boards_by_status("ACTIVE");
  DbBoardIdList reserved = wamble_query_list_boards_by_status("RESERVED");
  ensure_board_id_mutex();
  uint64_t max_id = 0;
  DbStatus st = wamble_query_get_max_board_id(&max_id);
  wamble_mutex_lock(&next_board_id_mutex);
  if (!next_board_id_initialized) {
    next_board_id = (st == DB_OK && max_id > 0) ? (max_id + 1) : 1;
    next_board_id_initialized = 1;
  }
  wamble_mutex_unlock(&next_board_id_mutex);
  bool lists_ok = (dormant.status == DB_OK && active.status == DB_OK &&
                   reserved.status == DB_OK);

  if (lists_ok) {
    total_boards = dormant.count + active.count + reserved.count;

    int boards_to_create = get_config()->min_boards - total_boards;
    if (boards_to_create > 0) {
      for (int i = 0; i < boards_to_create; i++) {
        int slot = find_cache_slot_for_board();
        if (slot < 0)
          break;
        uint64_t new_board_id = alloc_board_id();
        WambleBoard *b = &board_cached[slot];
        memset(b, 0, sizeof(*b));
        b->id = new_board_id;
        b->mode_params.chess960_position_id = NO_CHESS960_POSITION;
        int c960_pos_init = NO_CHESS960_POSITION;
        if (board_should_be_chess960(new_board_id)) {
          c960_pos_init = board_get_chess960_position(new_board_id);
          char c960_fen[FEN_MAX_LENGTH];
          chess960_gen_fen(c960_pos_init, c960_fen, sizeof(c960_fen));
          strcpy(b->fen, c960_fen);
          b->mode_params.chess960_position_id = c960_pos_init;
        } else {
          strcpy(b->fen, INITIAL_BOARD_FEN);
        }
        parse_fen_to_bitboard(b->fen, &b->board);
        b->state = BOARD_STATE_DORMANT;
        b->result = GAME_RESULT_IN_PROGRESS;
        b->creation_time = wamble_now_wall();
        b->last_move_time = 0;
        b->last_assignment_time = 0;
        board_map_put(b->id, slot);
        if (slot >= num_cached_boards)
          num_cached_boards = slot + 1;
        wamble_emit_create_board(new_board_id, b->fen, INITIAL_BOARD_STATUS,
                                 b->mode_params.chess960_position_id);
        total_boards++;
      }
    }
  }
}

static void transition_to_archived(WambleBoard *board, GameResult result) {
  time_t now = wamble_now_wall();
  board->state = BOARD_STATE_ARCHIVED;
  board->result = result;

  wamble_emit_update_board(board->id, board->fen, "ARCHIVED");

  char winning_side = 'd';
  if (result == GAME_RESULT_WHITE_WINS) {
    winning_side = 'w';
  } else if (result == GAME_RESULT_BLACK_WINS) {
    winning_side = 'b';
  }
  int move_count = (board->board.fullmove_number - 1) * 2;
  if (board->board.turn == 'b')
    move_count += 1;
  if (move_count < 0)
    move_count = 0;
  int duration_seconds = 0;
  if (board->creation_time > 0 && now > board->creation_time) {
    duration_seconds = (int)(now - board->creation_time);
  }
  const char *termination_reason = "unknown";
  if (result == GAME_RESULT_DRAW) {
    termination_reason = "draw";
  } else if (result == GAME_RESULT_WHITE_WINS ||
             result == GAME_RESULT_BLACK_WINS) {
    termination_reason = "win";
  }
  wamble_emit_record_game_result(board->id, winning_side, move_count,
                                 duration_seconds, termination_reason);

  total_boards--;
}

static bool is_board_eligible_for_assignment(const WambleBoard *board) {
  return (board->state == BOARD_STATE_DORMANT ||
          board->state == BOARD_STATE_ACTIVE) &&
         board->result == GAME_RESULT_IN_PROGRESS;
}

static int board_pairing_allowed_for_player(const WambleBoard *board,
                                            const WamblePlayer *player) {
  if (!board || !player)
    return 0;
  if (!get_config()->experiment_enabled)
    return 1;

  char current_group[128] = {0};
  WambleTreatmentAssignment assignment = {0};
  if (network_get_session_treatment_group(player->token, current_group,
                                          sizeof(current_group)) != 0 &&
      wamble_query_get_session_treatment_assignment(player->token,
                                                    &assignment) == DB_OK) {
    snprintf(current_group, sizeof(current_group), "%s", assignment.group_key);
  }
  if (!board->last_mover_treatment_group[0] || !current_group[0])
    return 1;
  return wamble_query_treatment_edge_allows(wamble_runtime_profile_key(),
                                            current_group,
                                            board->last_mover_treatment_group);
}

static int board_assignment_apply_treatment(const WambleBoard *board,
                                            const WamblePlayer *player,
                                            double *score) {
  if (!board || !player || !score)
    return 0;
  WambleFact facts[7];
  int fact_count = 0;
  memset(facts, 0, sizeof(facts));

  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "board.id");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_INT;
  facts[fact_count].int_value = (int64_t)board->id;
  fact_count++;

  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "board.move_count");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_INT;
  facts[fact_count].int_value = board->board.fullmove_number;
  fact_count++;

  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "player.games_played");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_INT;
  facts[fact_count].int_value = player->games_played;
  fact_count++;

  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "player.rating");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_DOUBLE;
  facts[fact_count].double_value = player->rating;
  fact_count++;

  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "board.is_chess960");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_BOOL;
  facts[fact_count].bool_value =
      (board->board.game_mode == GAME_MODE_CHESS960) ? 1 : 0;
  fact_count++;

  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "board.chess960_position_id");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_INT;
  facts[fact_count].int_value =
      (int64_t)board->mode_params.chess960_position_id;
  fact_count++;

  snprintf(facts[fact_count].key, sizeof(facts[fact_count].key), "%s",
           "player.chess960_games_played");
  facts[fact_count].value_type = WAMBLE_TREATMENT_VALUE_INT;
  facts[fact_count].int_value = player->chess960_games_played;
  fact_count++;

  WambleTreatmentAction actions[16];
  int action_count = 0;
  if (wamble_query_resolve_treatment_actions(
          player->token, "", "board.assignment",
          board->last_mover_treatment_group, facts, fact_count, actions, 16,
          &action_count) != DB_OK) {
    return 0;
  }

  int board_is_960 = (board->board.game_mode == GAME_MODE_CHESS960);
  for (int i = 0; i < action_count; i++) {
    const WambleTreatmentAction *action = &actions[i];
    if (strcmp(action->output_kind, "feature") == 0 &&
        action->value_type == WAMBLE_TREATMENT_VALUE_BOOL &&
        action->bool_value) {
      if (strcmp(action->output_key, "board.assignment.disable") == 0) {
        *score = 0.0;
        return -1;
      }
      if (strcmp(action->output_key, "board.chess960.disable") == 0 &&
          board_is_960) {
        *score = 0.0;
        return -1;
      }
      if (strcmp(action->output_key, "board.chess960.only") == 0 &&
          !board_is_960) {
        *score = 0.0;
        return -1;
      }
    }
    if (strcmp(action->output_kind, "behavior") != 0)
      continue;
    int ok = 0;
    double value = wamble_treatment_action_number(action, &ok);
    if (!ok)
      continue;
    if (strcmp(action->output_key, "board.score.multiplier") == 0) {
      *score *= value;
    } else if (strcmp(action->output_key, "board.score.bonus") == 0) {
      *score += value;
    }
  }
  if (*score < 0.0)
    *score = 0.0;
  return 0;
}

static double calculate_board_attractiveness(const WambleBoard *board,
                                             const WamblePlayer *player) {
  time_t now = wamble_now_wall();
  double score = 1.0;

  GamePhase phase;
  int fullmove_number = board->board.fullmove_number;
  if (fullmove_number < GAME_PHASE_EARLY_THRESHOLD) {
    phase = GAME_PHASE_EARLY;
  } else if (fullmove_number < GAME_PHASE_MID_THRESHOLD) {
    phase = GAME_PHASE_MID;
  } else {
    phase = GAME_PHASE_END;
  }

  int relevant_games = (board->board.game_mode == GAME_MODE_CHESS960)
                           ? player->chess960_games_played
                           : player->games_played;
  bool is_new_player = (relevant_games < NEW_PLAYER_GAMES_THRESHOLD);

  double multiplier;
  switch (phase) {
  case GAME_PHASE_EARLY:
    multiplier = is_new_player
                     ? get_config()->new_player_early_phase_mult
                     : get_config()->experienced_player_early_phase_mult;
    break;
  case GAME_PHASE_MID:
    multiplier = is_new_player
                     ? get_config()->new_player_mid_phase_mult
                     : get_config()->experienced_player_mid_phase_mult;
    break;
  case GAME_PHASE_END:
    multiplier = is_new_player
                     ? get_config()->new_player_end_phase_mult
                     : get_config()->experienced_player_end_phase_mult;
    break;
  }
  score *= multiplier;

  time_t time_since_assignment = now - board->last_assignment_time;
  if (time_since_assignment <= 0) {
    time_since_assignment = 1;
  }
  double recency_factor = log((double)time_since_assignment);
  score *= recency_factor;

  if (board_assignment_apply_treatment(board, player, &score) < 0)
    return 0.0;

  return score;
}

static void apply_reservation_to_board(WambleBoard *board,
                                       WamblePlayer *player) {
  time_t now = wamble_now_wall();

  board->state = BOARD_STATE_RESERVED;
  board->reservation_time = now;
  board->last_assignment_time = now;
  memcpy(board->reservation_player_token, player->token, TOKEN_LENGTH);
  board->reserved_for_white = (board->board.turn == 'w');

  wamble_emit_update_board(board->id, board->fen, "RESERVED");
  wamble_emit_update_board_assignment_time(board->id);
  wamble_emit_update_board_reservation_meta(board->id, now,
                                            board->reserved_for_white);

  if (player->has_persistent_identity) {
    wamble_emit_create_reservation(board->id, player->token,
                                   get_config()->reservation_timeout,
                                   board->reserved_for_white);
  }
}

static WambleBoard *load_board_into_cache(uint64_t board_id) {
  int cache_slot = find_cache_slot_for_board();
  if (cache_slot < 0) {
    return NULL;
  }

  DbBoardResult br = wamble_query_get_board(board_id);
  if (br.status != DB_OK) {
    return NULL;
  }

  WambleBoard *board = &board_cached[cache_slot];
  board->id = board_id;
  {
    size_t __len = strnlen(br.fen, FEN_MAX_LENGTH - 1);
    memcpy(board->fen, br.fen, __len);
    board->fen[__len] = '\0';
  }
  parse_fen_to_bitboard(board->fen, &board->board);
  board->state = board_state_from_string(br.status_text);
  board->result = GAME_RESULT_IN_PROGRESS;
  board->last_move_time = 0;
  board->creation_time =
      (br.created_at > 0) ? br.created_at : wamble_now_wall();
  board->last_assignment_time = br.last_assignment_time;
  board->last_move_time = br.last_move_time;
  snprintf(board->last_mover_treatment_group,
           sizeof(board->last_mover_treatment_group), "%s",
           br.last_mover_treatment_group);
  memset(board->reservation_player_token, 0, TOKEN_LENGTH);
  board->reservation_time = br.reservation_time;
  board->reserved_for_white = br.reserved_for_white;
  board->board.game_mode =
      (br.mode_variant_id >= 0) ? GAME_MODE_CHESS960 : GAME_MODE_STANDARD;
  board->mode_params.chess960_position_id = br.mode_variant_id;

  board_map_put(board_id, cache_slot);
  if (cache_slot >= num_cached_boards) {
    num_cached_boards = cache_slot + 1;
  }

  return board;
}

static void remove_board_from_cache(int cache_index) {
  if (cache_index < 0 || cache_index >= num_cached_boards) {
    return;
  }
  int cap = board_map_capacity();
  if (!board_index_map || cap <= 0)
    return;

  uint64_t board_id_to_remove = board_cached[cache_index].id;

  uint64_t h_remove = mix64_hash(board_id_to_remove);
  int i_remove = (int)(h_remove % (uint64_t)cap);
  for (int probe = 0; probe < cap; probe++) {
    if (board_index_map[i_remove] == cache_index) {
      board_index_map[i_remove] = -1;
      break;
    }
    i_remove = board_map_next(i_remove, cap);
  }

  num_cached_boards--;

  if (cache_index < num_cached_boards) {
    board_cached[cache_index] = board_cached[num_cached_boards];
    uint64_t moved_board_id = board_cached[cache_index].id;

    uint64_t h_moved = mix64_hash(moved_board_id);
    int i_moved = (int)(h_moved % (uint64_t)cap);
    for (int probe = 0; probe < cap; probe++) {
      if (board_index_map[i_moved] == num_cached_boards) {
        board_index_map[i_moved] = cache_index;
        break;
      }
      i_moved = board_map_next(i_moved, cap);
    }
  }

  memset(&board_cached[num_cached_boards], 0, sizeof(WambleBoard));
}

static int find_cache_slot_for_board(void) {
  for (int i = 0; i < get_config()->max_boards; i++) {
    if (board_cached[i].id == 0) {
      return i;
    }
  }

  for (int i = 0; i < num_cached_boards; i++) {
    if (board_cached[i].state != BOARD_STATE_RESERVED) {
      remove_board_from_cache(i);
      return i;
    }
  }

  return -1;
}

void board_move_played(uint64_t board_id) {
  if (!board_manager_ready())
    return;
  wamble_mutex_lock(&board_mutex);

  int idx = board_map_get(board_id);
  if (idx >= 0) {
    WambleBoard *board = &board_cached[idx];

    if (board->state == BOARD_STATE_RESERVED) {
      WambleTreatmentAssignment assignment = {0};
      board->last_mover_treatment_group[0] = '\0';
      if (wamble_query_get_session_treatment_assignment(
              board->reservation_player_token, &assignment) == DB_OK) {
        snprintf(board->last_mover_treatment_group,
                 sizeof(board->last_mover_treatment_group), "%s",
                 assignment.group_key);
      }
      board->state = BOARD_STATE_ACTIVE;
      board->last_move_time = wamble_now_wall();

      wamble_emit_update_board(board->id, board->fen, "ACTIVE");
      wamble_emit_update_board_move_meta(board->id,
                                         board->last_mover_treatment_group);
      wamble_emit_remove_reservation(board->id);
      wamble_emit_update_board_reservation_meta(board->id, 0, false);

      memset(board->reservation_player_token, 0, TOKEN_LENGTH);
      board->reservation_time = 0;
      board->reserved_for_white = false;
    } else if (board->state == BOARD_STATE_ACTIVE) {
      board->last_move_time = wamble_now_wall();
      wamble_emit_update_board_move_meta(board->id,
                                         board->last_mover_treatment_group);
    }
  }

  wamble_mutex_unlock(&board_mutex);
}

void board_game_completed(uint64_t board_id, GameResult result) {
  if (!board_manager_ready())
    return;
  wamble_mutex_lock(&board_mutex);
  int idx = board_map_get(board_id);
  if (idx >= 0) {
    WambleBoard *board = &board_cached[idx];
    board->result = result;
    update_player_ratings(board);
  }
  wamble_mutex_unlock(&board_mutex);

  calculate_and_distribute_pot(board_id);

  wamble_mutex_lock(&board_mutex);
  idx = board_map_get(board_id);
  if (idx >= 0) {
    WambleBoard *board = &board_cached[idx];
    transition_to_archived(board, result);
  }
  wamble_mutex_unlock(&board_mutex);
  prediction_expire_board(board_id);
}

bool board_is_reserved_for_player(uint64_t board_id,
                                  const uint8_t *player_token) {
  if (!board_manager_ready())
    return false;
  wamble_mutex_lock(&board_mutex);

  int idx = board_map_get(board_id);
  if (idx >= 0) {
    WambleBoard *board = &board_cached[idx];
    bool is_reserved = (board->state == BOARD_STATE_RESERVED) &&
                       (memcmp(board->reservation_player_token, player_token,
                               TOKEN_LENGTH) == 0);
    wamble_mutex_unlock(&board_mutex);
    return is_reserved;
  }

  wamble_mutex_unlock(&board_mutex);
  return false;
}

static void transition_reserved_to_dormant(WambleBoard *board) {
  board->state = BOARD_STATE_DORMANT;

  memset(board->reservation_player_token, 0, TOKEN_LENGTH);
  board->reservation_time = 0;
  board->reserved_for_white = false;

  wamble_emit_update_board(board->id, board->fen, "DORMANT");
  wamble_emit_remove_reservation(board->id);
  wamble_emit_update_board_reservation_meta(board->id, 0, false);
}

void board_release_reservation(uint64_t board_id) {
  if (!board_manager_ready())
    return;
  wamble_mutex_lock(&board_mutex);

  int idx = board_map_get(board_id);
  if (idx >= 0) {
    WambleBoard *board = &board_cached[idx];
    if (board->state == BOARD_STATE_RESERVED) {
      transition_reserved_to_dormant(board);
    }
  }

  wamble_mutex_unlock(&board_mutex);
}

int board_manager_export(WambleBoard *out, int max, int *out_count,
                         uint64_t *out_next_id) {
  if (!out_count || max < 0)
    return -1;
  if (!board_mutex_initialized || !board_cached || !board_index_map) {
    *out_count = 0;
    if (out_next_id) {
      ensure_board_id_mutex();
      wamble_mutex_lock(&next_board_id_mutex);
      *out_next_id = next_board_id;
      wamble_mutex_unlock(&next_board_id_mutex);
    }
    return 0;
  }
  wamble_mutex_lock(&board_mutex);
  int n = num_cached_boards;
  if (n > max)
    n = max;
  for (int i = 0; i < n; i++) {
    out[i] = board_cached[i];
  }
  if (out_count)
    *out_count = n;
  if (out_next_id) {
    ensure_board_id_mutex();
    wamble_mutex_lock(&next_board_id_mutex);
    *out_next_id = next_board_id;
    wamble_mutex_unlock(&next_board_id_mutex);
  }
  wamble_mutex_unlock(&board_mutex);
  return 0;
}

int board_manager_import(const WambleBoard *in, int count, uint64_t next_id) {
  if ((count > 0 && !in) || count < 0)
    return -1;
  if (!board_manager_ready())
    return -1;
  int capacity = get_config()->max_boards;
  if (count > capacity)
    count = capacity;

  wamble_mutex_lock(&board_mutex);

  memset(board_cached, 0, sizeof(WambleBoard) * (size_t)capacity);
  for (int i = 0; i < BOARD_MAP_SIZE; i++)
    board_index_map[i] = -1;
  for (int i = 0; i < count; i++) {
    board_cached[i] = in[i];
    board_map_put(board_cached[i].id, i);
  }
  num_cached_boards = count;
  ensure_board_id_mutex();
  wamble_mutex_lock(&next_board_id_mutex);
  next_board_id = (next_id > 0) ? next_id : (uint64_t)(count + 1);
  next_board_id_initialized = 1;
  wamble_mutex_unlock(&next_board_id_mutex);
  wamble_mutex_unlock(&board_mutex);
  return 0;
}

static int create_new_board_for_player(WamblePlayer *player);

typedef struct {
  WambleBoard *board;
  double score;
  bool is_cached;
  uint64_t board_id;
} ScoredBoard;

static int collect_cached_eligible_boards(WamblePlayer *player,
                                          ScoredBoard *eligible_boards,
                                          int eligible_capacity,
                                          double *out_total_score) {
  int eligible_count = 0;
  if (out_total_score)
    *out_total_score = 0.0;
  if (!player || !eligible_boards || eligible_capacity <= 0 || !out_total_score)
    return 0;

  for (int i = 0; i < num_cached_boards && eligible_count < eligible_capacity;
       i++) {
    WambleBoard *board = &board_cached[i];
    if (!is_board_eligible_for_assignment(board))
      continue;
    if (!board_pairing_allowed_for_player(board, player))
      continue;

    double score = calculate_board_attractiveness(board, player);
    eligible_boards[eligible_count].board = board;
    eligible_boards[eligible_count].score = score;
    eligible_boards[eligible_count].is_cached = true;
    eligible_boards[eligible_count].board_id = board->id;
    *out_total_score += score;
    eligible_count++;
  }
  return eligible_count;
}

static int append_dormant_eligible_boards(WamblePlayer *player,
                                          ScoredBoard *eligible_boards,
                                          int eligible_count,
                                          int eligible_capacity,
                                          double *inout_total_score) {
  if (!player || !eligible_boards || eligible_capacity <= 0 ||
      !inout_total_score) {
    return eligible_count;
  }

  DbBoardIdList dormant = wamble_query_list_boards_by_status("DORMANT");
  if (dormant.status != DB_OK || !dormant.ids)
    return eligible_count;

  for (int i = 0; i < dormant.count && eligible_count < eligible_capacity;
       i++) {
    uint64_t board_id = dormant.ids[i];
    if (board_map_get(board_id) >= 0)
      continue;

    DbBoardResult br = wamble_query_get_board(board_id);
    if (br.status != DB_OK)
      continue;

    WambleBoard temp_board = (WambleBoard){0};
    temp_board.id = board_id;
    {
      size_t __len = strnlen(br.fen, FEN_MAX_LENGTH - 1);
      memcpy(temp_board.fen, br.fen, __len);
      temp_board.fen[__len] = '\0';
    }
    parse_fen_to_bitboard(temp_board.fen, &temp_board.board);
    temp_board.state = BOARD_STATE_DORMANT;
    temp_board.result = GAME_RESULT_IN_PROGRESS;
    temp_board.last_assignment_time = br.last_assignment_time;
    temp_board.board.game_mode =
        (br.mode_variant_id >= 0) ? GAME_MODE_CHESS960 : GAME_MODE_STANDARD;
    temp_board.mode_params.chess960_position_id = br.mode_variant_id;
    snprintf(temp_board.last_mover_treatment_group,
             sizeof(temp_board.last_mover_treatment_group), "%s",
             br.last_mover_treatment_group);
    if (!board_pairing_allowed_for_player(&temp_board, player))
      continue;

    double score = calculate_board_attractiveness(&temp_board, player);
    eligible_boards[eligible_count].board = NULL;
    eligible_boards[eligible_count].score = score;
    eligible_boards[eligible_count].is_cached = false;
    eligible_boards[eligible_count].board_id = board_id;
    *inout_total_score += score;
    eligible_count++;
  }

  return eligible_count;
}

static WambleBoard *select_scored_board(const ScoredBoard *eligible_boards,
                                        int eligible_count,
                                        double total_score) {
  if (!eligible_boards || eligible_count <= 0 || total_score <= 0.0)
    return NULL;

  double random_value = rng_double() * total_score;
  for (int i = 0; i < eligible_count; i++) {
    random_value -= eligible_boards[i].score;
    if (random_value > 0)
      continue;
    if (eligible_boards[i].is_cached)
      return eligible_boards[i].board;
    return load_board_into_cache(eligible_boards[i].board_id);
  }
  return NULL;
}

WambleBoard *find_board_for_player(WamblePlayer *player) {
  if (!player || !board_manager_ready()) {
    return NULL;
  }

  wamble_mutex_lock(&board_mutex);

  int eligible_capacity = get_config()->max_boards * 2;
  if (eligible_capacity <= 0) {
    wamble_mutex_unlock(&board_mutex);
    return NULL;
  }
  ScoredBoard *eligible_boards =
      calloc((size_t)eligible_capacity, sizeof(*eligible_boards));
  if (!eligible_boards) {
    wamble_mutex_unlock(&board_mutex);
    return NULL;
  }
  double total_score = 0.0;
  int eligible_count = collect_cached_eligible_boards(
      player, eligible_boards, eligible_capacity, &total_score);
  eligible_count = append_dormant_eligible_boards(
      player, eligible_boards, eligible_count, eligible_capacity, &total_score);
  WambleBoard *selected_board =
      select_scored_board(eligible_boards, eligible_count, total_score);

  if (selected_board) {
    apply_reservation_to_board(selected_board, player);
    free(eligible_boards);
    wamble_mutex_unlock(&board_mutex);
    return selected_board;
  }

  if (total_boards < get_config()->max_boards) {
    int new_board_index = create_new_board_for_player(player);
    if (new_board_index >= 0) {
      selected_board = &board_cached[new_board_index];
      free(eligible_boards);
      wamble_mutex_unlock(&board_mutex);
      return selected_board;
    }
  }

  free(eligible_boards);
  wamble_mutex_unlock(&board_mutex);
  return NULL;
}

static int create_new_board_for_player(WamblePlayer *player) {
  time_t now = wamble_now_wall();

  int longest_game = 0;
  int players = 0;
  (void)wamble_query_get_longest_game_moves(&longest_game);
  (void)wamble_query_get_active_session_count(&players);
  int target_boards = longest_game * players;
  if (target_boards < get_config()->min_boards) {
    target_boards = get_config()->min_boards;
  }

  if (total_boards >= get_config()->max_boards ||
      total_boards >= target_boards) {
    return -1;
  }

  int cache_slot = find_cache_slot_for_board();
  if (cache_slot < 0) {
    return -1;
  }

  WambleBoard *board = &board_cached[cache_slot];
  board->id = alloc_board_id();
  board->mode_params.chess960_position_id = NO_CHESS960_POSITION;
  if (board_should_be_chess960(board->id)) {
    board->mode_params.chess960_position_id =
        board_get_chess960_position(board->id);
    char c960_fen[FEN_MAX_LENGTH];
    chess960_gen_fen(board->mode_params.chess960_position_id, c960_fen,
                     sizeof(c960_fen));
    strcpy(board->fen, c960_fen);
  } else {
    strcpy(board->fen, INITIAL_BOARD_FEN);
  }
  wamble_emit_create_board(board->id, board->fen, INITIAL_BOARD_STATUS,
                           board->mode_params.chess960_position_id);

  board->result = GAME_RESULT_IN_PROGRESS;
  parse_fen_to_bitboard(board->fen, &board->board);
  board->last_move_time = now;
  board->creation_time = now;
  board->last_mover_treatment_group[0] = '\0';

  apply_reservation_to_board(board, player);

  board_map_put(board->id, cache_slot);
  if (cache_slot >= num_cached_boards) {
    num_cached_boards = cache_slot + 1;
  }

  total_boards++;

  return cache_slot;
}

WambleBoard *get_board_by_id(uint64_t board_id) {
  if (!board_manager_ready())
    return NULL;
  wamble_mutex_lock(&board_mutex);
  int idx = board_map_get(board_id);
  if (idx >= 0) {
    WambleBoard *b = &board_cached[idx];
    wamble_mutex_unlock(&board_mutex);
    return b;
  }

  WambleBoard *loaded_board = load_board_into_cache(board_id);
  wamble_mutex_unlock(&board_mutex);
  return loaded_board;
}
