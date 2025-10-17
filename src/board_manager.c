#include "../include/wamble/wamble.h"
#include <math.h>
#include <string.h>

static WAMBLE_THREAD_LOCAL WambleBoard *board_cached;
static WAMBLE_THREAD_LOCAL int num_cached_boards = 0;
static WAMBLE_THREAD_LOCAL int total_boards = 0;
static WAMBLE_THREAD_LOCAL uint64_t next_board_id = 1;
static WAMBLE_THREAD_LOCAL wamble_mutex_t board_mutex;

#define BOARD_MAP_SIZE (get_config()->max_boards * 2)
static WAMBLE_THREAD_LOCAL int *board_index_map;

static inline uint64_t mix64_hash(uint64_t x) {
  x ^= x >> 33;
  x *= 0xff51afd7ed558ccdULL;
  x ^= x >> 33;
  x *= 0xc4ceb9fe1a85ec53ULL;
  x ^= x >> 33;
  return x;
}

static void board_map_put(uint64_t id, int index) {
  uint64_t h = mix64_hash(id);
  int mask = BOARD_MAP_SIZE - 1;
  int i = (int)(h & (uint64_t)mask);
  for (int probe = 0; probe < BOARD_MAP_SIZE; probe++) {
    if (board_index_map[i] == -1) {
      board_index_map[i] = index;
      return;
    }
    i = (i + 1) & mask;
  }
}

static int board_map_get(uint64_t id) {
  uint64_t h = mix64_hash(id);
  int mask = BOARD_MAP_SIZE - 1;
  int i = (int)(h & (uint64_t)mask);
  for (int probe = 0; probe < BOARD_MAP_SIZE; probe++) {
    int idx = board_index_map[i];
    if (idx == -1)
      return -1;
    if (idx >= 0 && board_cached[idx].id == id)
      return idx;
    i = (i + 1) & mask;
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

void board_manager_tick() {
  wamble_mutex_lock(&board_mutex);

  time_t now = wamble_now_wall();
  static time_t last_count_update = 0;

  for (int i = num_cached_boards - 1; i >= 0; i--) {
    WambleBoard *board = &board_cached[i];

    if (board->state == BOARD_STATE_RESERVED) {
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
        db_async_update_board(board->id, board->fen, "DORMANT");
      }
    }
  }

  if (now - last_count_update >= 60) {
    DbBoardIdList dormant = db_list_boards_by_status("DORMANT");
    DbBoardIdList active = db_list_boards_by_status("ACTIVE");
    DbBoardIdList reserved = db_list_boards_by_status("RESERVED");
    bool lists_ok = (dormant.status == DB_OK && active.status == DB_OK &&
                     reserved.status == DB_OK);

    if (lists_ok) {
      total_boards = dormant.count + active.count + reserved.count;
      last_count_update = now;

      int longest_game = db_get_longest_game_moves();
      int players = db_get_active_session_count();
      int target_boards = longest_game * players;
      if (target_boards < get_config()->min_boards) {
        target_boards = get_config()->min_boards;
      }
      if (target_boards > get_config()->max_boards) {
        target_boards = get_config()->max_boards;
      }

      int boards_to_create = target_boards - total_boards;
      if (boards_to_create > 0) {
        for (int i = 0; i < boards_to_create; i++) {
          if (total_boards >= get_config()->max_boards) {
            break;
          }
          uint64_t new_board_id = db_create_board(
              "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1");
          if (new_board_id > 0) {
            total_boards++;
            if (new_board_id >= next_board_id) {
              next_board_id = new_board_id + 1;
            }
          }
        }
      }
    }
  }

  wamble_mutex_unlock(&board_mutex);
}

void board_manager_init(void) {
  if (board_cached) {
    free(board_cached);
    free(board_index_map);
    wamble_mutex_destroy(&board_mutex);
  }
  board_cached = malloc(sizeof(WambleBoard) * (size_t)get_config()->max_boards);
  board_index_map =
      malloc(sizeof(int) * (size_t)(get_config()->max_boards * 2));
  memset(board_cached, 0,
         sizeof(WambleBoard) * (size_t)get_config()->max_boards);
  num_cached_boards = 0;
  total_boards = 0;
  next_board_id = 1;
  wamble_mutex_init(&board_mutex);
  rng_init();
  for (int i = 0; i < BOARD_MAP_SIZE; i++)
    board_index_map[i] = -1;

  DbBoardIdList dormant = db_list_boards_by_status("DORMANT");
  DbBoardIdList active = db_list_boards_by_status("ACTIVE");
  DbBoardIdList reserved = db_list_boards_by_status("RESERVED");
  bool lists_ok = (dormant.status == DB_OK && active.status == DB_OK &&
                   reserved.status == DB_OK);

  if (lists_ok) {
    total_boards = dormant.count + active.count + reserved.count;

    int boards_to_create = get_config()->min_boards - total_boards;
    if (boards_to_create > 0) {
      for (int i = 0; i < boards_to_create; i++) {
        uint64_t new_board_id = db_create_board(
            "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1");
        if (new_board_id >= next_board_id) {
          next_board_id = new_board_id + 1;
        }
        total_boards++;
      }
    }
  }
}

static void transition_to_archived(WambleBoard *board, GameResult result) {
  board->state = BOARD_STATE_ARCHIVED;
  board->result = result;

  db_async_update_board(board->id, board->fen, "ARCHIVED");

  char winning_side = 'd';
  if (result == GAME_RESULT_WHITE_WINS) {
    winning_side = 'w';
  } else if (result == GAME_RESULT_BLACK_WINS) {
    winning_side = 'b';
  }
  db_async_record_game_result(board->id, winning_side);

  total_boards--;
}

static bool is_board_eligible_for_assignment(const WambleBoard *board) {
  return (board->state == BOARD_STATE_DORMANT ||
          board->state == BOARD_STATE_ACTIVE) &&
         board->result == GAME_RESULT_IN_PROGRESS;
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

  bool is_new_player = (player->games_played < NEW_PLAYER_GAMES_THRESHOLD);

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

  db_async_update_board(board->id, board->fen, "RESERVED");
  db_async_update_board_assignment_time(board->id);

  if (player->has_persistent_identity) {
    uint64_t session_id = db_get_session_by_token(player->token);
    if (session_id > 0) {
      db_async_create_reservation(board->id, session_id,
                                  get_config()->reservation_timeout);
    }
  }
}

static int find_cache_slot_for_board(void);
static WambleBoard *load_board_into_cache(uint64_t board_id) {
  int cache_slot = find_cache_slot_for_board();
  if (cache_slot < 0) {
    return NULL;
  }

  DbBoardResult br = db_get_board(board_id);
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
  board->creation_time = wamble_now_wall();
  board->last_assignment_time = br.last_assignment_time;
  memset(board->reservation_player_token, 0, TOKEN_LENGTH);
  board->reservation_time = 0;
  board->reserved_for_white = false;

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

  uint64_t board_id_to_remove = board_cached[cache_index].id;

  uint64_t h_remove = mix64_hash(board_id_to_remove);
  int mask = BOARD_MAP_SIZE - 1;
  int i_remove = (int)(h_remove & (uint64_t)mask);
  for (int probe = 0; probe < BOARD_MAP_SIZE; probe++) {
    if (board_index_map[i_remove] == cache_index) {
      board_index_map[i_remove] = -1;
      break;
    }
    i_remove = (i_remove + 1) & mask;
  }

  num_cached_boards--;

  if (cache_index < num_cached_boards) {
    board_cached[cache_index] = board_cached[num_cached_boards];
    uint64_t moved_board_id = board_cached[cache_index].id;

    uint64_t h_moved = mix64_hash(moved_board_id);
    int i_moved = (int)(h_moved & (uint64_t)mask);
    for (int probe = 0; probe < BOARD_MAP_SIZE; probe++) {
      if (board_index_map[i_moved] == num_cached_boards) {
        board_index_map[i_moved] = cache_index;
        break;
      }
      i_moved = (i_moved + 1) & mask;
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
  wamble_mutex_lock(&board_mutex);

  int idx = board_map_get(board_id);
  if (idx >= 0) {
    WambleBoard *board = &board_cached[idx];

    if (board->state == BOARD_STATE_RESERVED) {
      board->state = BOARD_STATE_ACTIVE;
      board->last_move_time = wamble_now_wall();

      db_async_update_board(board->id, board->fen, "ACTIVE");
      db_async_remove_reservation(board->id);

      memset(board->reservation_player_token, 0, TOKEN_LENGTH);
      board->reservation_time = 0;
      board->reserved_for_white = false;
    } else if (board->state == BOARD_STATE_ACTIVE) {
      board->last_move_time = wamble_now_wall();
    }
  }

  wamble_mutex_unlock(&board_mutex);
}

void board_game_completed(uint64_t board_id, GameResult result) {
  wamble_mutex_lock(&board_mutex);

  int idx = board_map_get(board_id);
  if (idx >= 0) {
    WambleBoard *board = &board_cached[idx];
    board->result = result;

    update_player_ratings(board);

    calculate_and_distribute_pot(board_id);

    transition_to_archived(board, result);
  }

  wamble_mutex_unlock(&board_mutex);
}

bool board_is_reserved_for_player(uint64_t board_id,
                                  const uint8_t *player_token) {
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

  db_async_update_board(board->id, board->fen, "DORMANT");
  db_async_remove_reservation(board->id);
}

void board_release_reservation(uint64_t board_id) {
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

void board_archive(uint64_t board_id) {
  wamble_mutex_lock(&board_mutex);

  int idx = board_map_get(board_id);
  if (idx >= 0) {
    WambleBoard *board = &board_cached[idx];
    if (board->state != BOARD_STATE_ARCHIVED) {
      transition_to_archived(board, board->result);
    }
  }

  wamble_mutex_unlock(&board_mutex);
}

int board_manager_export(WambleBoard *out, int max, int *out_count,
                         uint64_t *out_next_id) {
  if (!out_count || max < 0)
    return -1;
  wamble_mutex_lock(&board_mutex);
  int n = num_cached_boards;
  if (n > max)
    n = max;
  for (int i = 0; i < n; i++) {
    out[i] = board_cached[i];
  }
  if (out_count)
    *out_count = n;
  if (out_next_id)
    *out_next_id = next_board_id;
  wamble_mutex_unlock(&board_mutex);
  return 0;
}

int board_manager_import(const WambleBoard *in, int count, uint64_t next_id) {
  if ((count > 0 && !in) || count < 0)
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
  next_board_id = (next_id > 0) ? next_id : (uint64_t)(count + 1);
  wamble_mutex_unlock(&board_mutex);
  return 0;
}

static int create_new_board_for_player(WamblePlayer *player);

WambleBoard *find_board_for_player(WamblePlayer *player) {
  if (!player) {
    return NULL;
  }

  wamble_mutex_lock(&board_mutex);

  typedef struct {
    WambleBoard *board;
    double score;
    bool is_cached;
    uint64_t board_id;
  } ScoredBoard;

  ScoredBoard eligible_boards[get_config()->max_boards * 2];
  int eligible_count = 0;
  double total_score = 0.0;

  for (int i = 0; i < num_cached_boards; i++) {
    WambleBoard *board = &board_cached[i];

    if (!is_board_eligible_for_assignment(board)) {
      continue;
    }

    double score = calculate_board_attractiveness(board, player);

    eligible_boards[eligible_count].board = board;
    eligible_boards[eligible_count].score = score;
    eligible_boards[eligible_count].is_cached = true;
    eligible_boards[eligible_count].board_id = board->id;
    total_score += score;
    eligible_count++;
  }

  DbBoardIdList dormant = db_list_boards_by_status("DORMANT");
  if (dormant.status == DB_OK && dormant.ids) {
    for (int i = 0;
         i < dormant.count && eligible_count < get_config()->max_boards * 2;
         i++) {
      uint64_t board_id = dormant.ids[i];

      if (board_map_get(board_id) >= 0) {
        continue;
      }

      DbBoardResult br = db_get_board(board_id);
      if (br.status != DB_OK) {
        continue;
      }

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

      double score = calculate_board_attractiveness(&temp_board, player);

      eligible_boards[eligible_count].board = NULL;
      eligible_boards[eligible_count].score = score;
      eligible_boards[eligible_count].is_cached = false;
      eligible_boards[eligible_count].board_id = board_id;
      total_score += score;
      eligible_count++;
    }
  }

  WambleBoard *selected_board = NULL;

  if (eligible_count > 0 && total_score > 0) {
    double random_value = rng_double() * total_score;
    for (int i = 0; i < eligible_count; i++) {
      random_value -= eligible_boards[i].score;
      if (random_value <= 0) {
        if (eligible_boards[i].is_cached) {
          selected_board = eligible_boards[i].board;
        } else {
          selected_board = load_board_into_cache(eligible_boards[i].board_id);
        }
        break;
      }
    }
  }

  if (selected_board) {
    apply_reservation_to_board(selected_board, player);
    wamble_mutex_unlock(&board_mutex);
    return selected_board;
  }

  if (total_boards < get_config()->max_boards) {
    int new_board_index = create_new_board_for_player(player);
    if (new_board_index >= 0) {
      selected_board = &board_cached[new_board_index];
      wamble_mutex_unlock(&board_mutex);
      return selected_board;
    }
  }

  wamble_mutex_unlock(&board_mutex);
  return NULL;
}

static int create_new_board_for_player(WamblePlayer *player) {
  time_t now = wamble_now_wall();

  int longest_game = db_get_longest_game_moves();
  int players = db_get_active_session_count();
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
  strcpy(board->fen,
         "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1");

  board->id = db_create_board(board->fen);
  if (board->id == 0) {
    board->id = next_board_id++;
  } else {
    if (board->id >= next_board_id) {
      next_board_id = board->id + 1;
    }
  }

  board->result = GAME_RESULT_IN_PROGRESS;
  parse_fen_to_bitboard(board->fen, &board->board);
  board->last_move_time = now;
  board->creation_time = now;

  apply_reservation_to_board(board, player);

  board_map_put(board->id, cache_slot);
  if (cache_slot >= num_cached_boards) {
    num_cached_boards = cache_slot + 1;
  }

  total_boards++;

  return cache_slot;
}

WambleBoard *get_board_by_id(uint64_t board_id) {
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

int get_total_board_count_public(void) {
  wamble_mutex_lock(&board_mutex);
  int count = total_boards;
  wamble_mutex_unlock(&board_mutex);
  return count;
}
