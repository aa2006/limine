#include <fs/flat_fs.h>
#include <stdint.h>
#include <lib/libc.h>
#include <lib/blib.h>
#include <lib/print.h>
#include <drivers/disk.h>
#include <stdbool.h>
#include <mm/pmm.h>

static char *strchr(const char *s, int c) {
  while (*s != (char)(c)) if (!(*s++)) return NULL;
  return (char *)(s);
}

int flatfs_check_signature(struct volume *part) {
  flatfs_t fs;
  if (!volume_read(part, &fs, 0, 1)) return 0;

  return (fs.flat_sig == FLAT_SIGNATURE);
}

bool flatfs_get_guid(struct guid *guid, struct volume *part) {
  flatfs_t fs;
  if (!volume_read(part, &fs, 0, 1)) return 0;

  memcpy(guid, fs.guid, sizeof(struct guid));

  return 1;
}

static flatfs_header_t flatfs_get_header(struct volume *part, uint64_t header_ptr) {
  flatfs_header_t header;
  if (!volume_read(part, &header, header_ptr, 1)) header.type = FLAT_TYPE_NULL;

  return header;
}

static uint64_t flatfs_find(struct volume *part, uint64_t dir, const char *name) {
  flatfs_header_t dir_header = flatfs_get_header(part, dir);
  if (dir_header.type == FLAT_TYPE_NULL) return 0;

  uint64_t entry_cnt = (dir_header.block_cnt << 9) / sizeof(uint64_t);

  // Load all the entries from this block
  uint64_t entries[entry_cnt];
  if (!volume_read(part, &entries, (dir + 1), dir_header.block_cnt)) return 0;

  flatfs_header_t header;

  // Compare each of the loaded entries
  for (uint64_t i = 0; i < entry_cnt; i++) {
    header = flatfs_get_header(part, entries[i]);
    if (header.type == FLAT_TYPE_NULL) return 0;

    if (!(header.type & FLAT_TYPE_MASK) && !strcmp(header.data.name, name)) return entries[i];
  }

  // Ok, we didn't find it on this block, let's check the next one
  if (dir_header.next_ptr) return flatfs_find(part, dir_header.next_ptr, name);

  // No entry found with that name, abort
  return 0;
}

int flatfs_open(struct flatfs_file_handle *ret, struct volume *part, const char *filename) {
  if (!filename) return -1;
  else if (!(*filename)) return -1;
  else if (*filename == '/') return flatfs_open(ret, part, filename + 1);

  ret->part = part;

  if (!flatfs_check_signature(part)) {
    print("flat_fs: signature invalid\n");
    return -1;
  }

  uint64_t header_ptr = 1; // Root dir.

  while (filename) {
    char name[256] = {0}; // Temp. buffer

    const char *ptr = strchr(filename, '/');
    if (ptr) {
      memcpy(name, filename, ptr - filename);
      filename += (ptr - filename) + 1;
    } else {
      strcpy(name, filename);
      filename = NULL;
    }

    if (!(header_ptr = flatfs_find(part, header_ptr, name))) return -1;
  }

  ret->header_ptr = header_ptr;

  flatfs_header_t header;
  header = flatfs_get_header(part, header_ptr);

  ret->size = header.data.size;

  return 0;
}

int flatfs_read(struct flatfs_file_handle *file, void *buf, uint64_t loc, uint64_t count) {
  flatfs_header_t header;
  uint64_t header_ptr = file->header_ptr;

  while (header_ptr && count) {
    // Load current header
    header = flatfs_get_header(file->part, header_ptr);
    if (header.type == FLAT_TYPE_NULL) return -1;

    // Read the blocks
    if (loc < header.block_cnt) {
      uint64_t read_cnt = header.block_cnt < count ? header.block_cnt : count;

      if (!volume_read(file->part, buf, (header_ptr + 1), read_cnt)) return 0;
      count -= read_cnt;

      buf += header.block_cnt << 9;
    } else loc -= header.block_cnt;

    // Prepare to load next block
    header_ptr = header.next_ptr;
  }

  return 0;
}
