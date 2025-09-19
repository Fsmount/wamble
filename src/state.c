#include "../include/wamble/wamble.h"
#include <string.h>
#if defined(WAMBLE_PLATFORM_POSIX)
#include <unistd.h>
#endif

typedef struct StateHeader {
  char magic[8];
  uint32_t version;
  uint32_t count;
  uint64_t next_id;
} StateHeader;

int board_manager_export(WambleBoard *out, int max, int *out_count,
                         uint64_t *out_next_id);
int board_manager_import(const WambleBoard *in, int count, uint64_t next_id);

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

  StateHeader hdr;
  memset(&hdr, 0, sizeof(hdr));
  memcpy(hdr.magic, "WMBLST01", 8);
  hdr.version = 1u;
  hdr.count = (uint32_t)((count < 0) ? 0 : count);
  hdr.next_id = next_id;

  size_t w = fwrite(&hdr, 1, sizeof(hdr), f);
  if (w != sizeof(hdr)) {
    free(tmp);
    fclose(f);
    return -1;
  }
  if (count > 0) {
    size_t need = sizeof(WambleBoard) * (size_t)count;
    w = fwrite(tmp, 1, need, f);
    if (w != need) {
      free(tmp);
      fclose(f);
      return -1;
    }
  }
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
  size_t r = fread(&hdr, 1, sizeof(hdr), f);
  if (r != sizeof(hdr)) {
    fclose(f);
    return -1;
  }
  if (memcmp(hdr.magic, "WMBLST01", 8) != 0 || hdr.version != 1u) {
    fclose(f);
    return -1;
  }
  int count = (int)hdr.count;
  if (count < 0)
    count = 0;
  WambleBoard *tmp = NULL;
  if (count > 0) {
    tmp = (WambleBoard *)malloc(sizeof(WambleBoard) * (size_t)count);
    if (!tmp) {
      fclose(f);
      return -1;
    }
    size_t need = sizeof(WambleBoard) * (size_t)count;
    r = fread(tmp, 1, need, f);
    if (r != need) {
      free(tmp);
      fclose(f);
      return -1;
    }
  }
  fclose(f);
  int rc = board_manager_import(tmp, count, hdr.next_id);
  if (tmp)
    free(tmp);
  return rc;
}
