#include "../include/wamble/wamble.h"
#include <string.h>
#if defined(WAMBLE_PLATFORM_POSIX)
#include <unistd.h>
#endif

#define WAMBLE_STATE_MAGIC "WMBLST01"
#define WAMBLE_STATE_FORMAT_REVISION 3u
#define WAMBLE_STATE_MIN_LOADABLE_REVISION 1u
#define WAMBLE_STATE_SPECTATOR_REVISION 2u
#define WAMBLE_STATE_FIXED_SPECTATOR_REVISION 3u

static int state_revision_loadable(uint32_t revision) {
  return revision >= WAMBLE_STATE_MIN_LOADABLE_REVISION &&
         revision <= WAMBLE_STATE_FORMAT_REVISION;
}

typedef struct StateHeader {
  char magic[8];
  uint32_t version;
  uint32_t count;
  uint64_t next_id;
  uint32_t spectator_count;
  uint32_t reserved;
} StateHeader;

int wamble_runtime_state_path(char *out, size_t out_size, const char *name) {
  if (!out || out_size == 0)
    return -1;
  out[0] = '\0';
  const char *base = ".";
  const WambleConfig *cfg = get_config();
  if (cfg && cfg->state_dir && cfg->state_dir[0]) {
    base = cfg->state_dir;
#ifdef WAMBLE_PLATFORM_POSIX
  } else {
    base = "/tmp";
#else
  } else {
    const char *tmp = getenv("TEMP");
    if (tmp && tmp[0])
      base = tmp;
#endif
  }
  char sep = '/';
#ifdef WAMBLE_PLATFORM_WINDOWS
  sep = '\\';
#endif
  size_t base_len = strlen(base);
  int need_sep =
      (base_len > 0 && base[base_len - 1] != '/' && base[base_len - 1] != '\\');
  snprintf(out, out_size, "%s%s%s", base, need_sep ? (char[2]){sep, '\0'} : "",
           name ? name : "");
  return 0;
}

static int state_write_all(FILE *f, const void *data, size_t len) {
  if (!f || !data)
    return -1;
  return (fwrite(data, 1, len, f) == len) ? 0 : -1;
}

static int state_read_all(FILE *f, void *data, size_t len) {
  if (!f || !data)
    return -1;
  return (fread(data, 1, len, f) == len) ? 0 : -1;
}

int board_manager_export(WambleBoard *out, int max, int *out_count,
                         uint64_t *out_next_id);
int board_manager_import(const WambleBoard *in, int count, uint64_t next_id);
int spectator_manager_export(void *out, int max, int *out_count);
size_t spectator_manager_state_record_size(void);
size_t spectator_manager_legacy_state_record_size(void);
int spectator_manager_export_state_records(uint8_t *out, size_t record_size,
                                           int max, int *out_count);
int spectator_manager_import_state_records(const uint8_t *in,
                                           size_t record_size, int count);
int spectator_manager_import_legacy_state_records(const uint8_t *in,
                                                  size_t record_size,
                                                  int count);

int state_save_to_file(const char *path) {
  if (!path)
    return -1;
  FILE *f = fopen(path, "wb");
  if (!f)
    return -1;

  int cap = get_config()->max_boards;
  if (cap <= 0)
    cap = 1;
  WambleBoard *tmp = (WambleBoard *)malloc(sizeof(WambleBoard) * (size_t)cap);
  if (!tmp) {
    fclose(f);
    return -1;
  }
  int count = 0;
  uint64_t next_id = 0;
  if (board_manager_export(tmp, cap, &count, &next_id) != 0) {
    free(tmp);
    fclose(f);
    return -1;
  }

  int spectator_count = 0;
  if (spectator_manager_export(NULL, 0, &spectator_count) != 0) {
    free(tmp);
    fclose(f);
    return -1;
  }
  uint8_t *spectators = NULL;
  size_t spectator_record_size = spectator_manager_state_record_size();
  if (spectator_count > 0) {
    if (spectator_record_size == 0) {
      free(tmp);
      fclose(f);
      return -1;
    }
    spectators =
        (uint8_t *)calloc((size_t)spectator_count, spectator_record_size);
    if (!spectators) {
      free(tmp);
      fclose(f);
      return -1;
    }
    if (spectator_manager_export_state_records(
            spectators, spectator_record_size, spectator_count,
            &spectator_count) != 0) {
      free(spectators);
      free(tmp);
      fclose(f);
      return -1;
    }
  }

  StateHeader hdr;
  memset(&hdr, 0, sizeof(hdr));
  memcpy(hdr.magic, WAMBLE_STATE_MAGIC, sizeof(hdr.magic));
  hdr.version = WAMBLE_STATE_FORMAT_REVISION;
  hdr.count = (uint32_t)((count < 0) ? 0 : count);
  hdr.next_id = next_id;
  hdr.spectator_count = (uint32_t)((spectator_count < 0) ? 0 : spectator_count);

  if (state_write_all(f, &hdr, sizeof(hdr)) != 0) {
    free(spectators);
    free(tmp);
    fclose(f);
    return -1;
  }
  if (count > 0) {
    size_t need = sizeof(WambleBoard) * (size_t)count;
    if (state_write_all(f, tmp, need) != 0) {
      free(spectators);
      free(tmp);
      fclose(f);
      return -1;
    }
  }
  if (spectator_count > 0) {
    size_t need = spectator_record_size * (size_t)spectator_count;
    if (state_write_all(f, spectators, need) != 0) {
      free(spectators);
      free(tmp);
      fclose(f);
      return -1;
    }
  }
  free(spectators);
  free(tmp);
  fclose(f);
  return 0;
}

int state_load_from_file(const char *path) {
  if (!path)
    return -1;
  FILE *f = fopen(path, "rb");
  if (!f)
    return -1;

  StateHeader hdr;
  memset(&hdr, 0, sizeof(hdr));
  if (state_read_all(f, &hdr.magic, sizeof(hdr.magic)) != 0 ||
      state_read_all(f, &hdr.version, sizeof(hdr.version)) != 0 ||
      state_read_all(f, &hdr.count, sizeof(hdr.count)) != 0 ||
      state_read_all(f, &hdr.next_id, sizeof(hdr.next_id)) != 0)
    return fclose(f), -1;
  if (memcmp(hdr.magic, WAMBLE_STATE_MAGIC, sizeof(hdr.magic)) != 0 ||
      !state_revision_loadable(hdr.version))
    return fclose(f), -1;
  if (hdr.version >= WAMBLE_STATE_SPECTATOR_REVISION) {
    if (state_read_all(f, &hdr.spectator_count, sizeof(hdr.spectator_count)) !=
            0 ||
        state_read_all(f, &hdr.reserved, sizeof(hdr.reserved)) != 0)
      return fclose(f), -1;
  }
  int count = (int)hdr.count;
  if (count < 0)
    count = 0;
  WambleBoard *tmp = NULL;
  if (count > 0) {
    tmp = (WambleBoard *)malloc(sizeof(WambleBoard) * (size_t)count);
    if (!tmp)
      return fclose(f), -1;
    size_t need = sizeof(WambleBoard) * (size_t)count;
    if (state_read_all(f, tmp, need) != 0) {
      free(tmp);
      fclose(f);
      return -1;
    }
  }
  uint8_t *spectators = NULL;
  int spectator_count = 0;
  if (hdr.version >= WAMBLE_STATE_SPECTATOR_REVISION) {
    spectator_count = (int)hdr.spectator_count;
    if (spectator_count < 0)
      spectator_count = 0;
    if (spectator_count > 0) {
      size_t record_size = hdr.version >= WAMBLE_STATE_FIXED_SPECTATOR_REVISION
                               ? spectator_manager_state_record_size()
                               : spectator_manager_legacy_state_record_size();
      if (record_size == 0) {
        free(tmp);
        fclose(f);
        return -1;
      }
      spectators = (uint8_t *)malloc(record_size * (size_t)spectator_count);
      if (!spectators) {
        free(tmp);
        fclose(f);
        return -1;
      }
      size_t need = record_size * (size_t)spectator_count;
      if (state_read_all(f, spectators, need) != 0) {
        free(spectators);
        free(tmp);
        fclose(f);
        return -1;
      }
    }
  }
  int rc = board_manager_import(tmp, count, hdr.next_id);
  if (rc == 0 && hdr.version >= WAMBLE_STATE_SPECTATOR_REVISION) {
    if (hdr.version >= WAMBLE_STATE_FIXED_SPECTATOR_REVISION) {
      rc = spectator_manager_import_state_records(
          spectators, spectator_manager_state_record_size(), spectator_count);
    } else {
      rc = spectator_manager_import_legacy_state_records(
          spectators, spectator_manager_legacy_state_record_size(),
          spectator_count);
    }
  }
  free(spectators);
  free(tmp);
  fclose(f);
  return rc;
}
