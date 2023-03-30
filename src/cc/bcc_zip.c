/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "bcc_zip.h"

#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// Specification of ZIP file format can be found here:
// https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
// For a high level overview of the structure of a ZIP file see
// sections 4.3.1 - 4.3.6.

// Data structures appearing in ZIP files do not contain any
// padding and they might be misaligned. To allow us to safely
// operate on pointers to such structures and their members, without
// worrying of platform specific alignment issues, we define
// unaligned_uint16_t and unaligned_uint32_t types with no alignment
// requirements.
typedef struct {
  uint8_t raw[2];
} unaligned_uint16_t;

static uint16_t unaligned_uint16_read(unaligned_uint16_t value) {
  uint16_t return_value;
  memcpy(&return_value, value.raw, sizeof(return_value));
  return return_value;
}

typedef struct {
  uint8_t raw[4];
} unaligned_uint32_t;

static uint32_t unaligned_uint32_read(unaligned_uint32_t value) {
  uint32_t return_value;
  memcpy(&return_value, value.raw, sizeof(return_value));
  return return_value;
}

#define END_OF_CD_RECORD_MAGIC 0x06054b50

// See section 4.3.16 of the spec.
struct end_of_central_directory_record {
  // Magic value equal to END_OF_CD_RECORD_MAGIC
  unaligned_uint32_t magic;

  // Number of the file containing this structure or 0xFFFF if ZIP64 archive.
  // Zip archive might span multiple files (disks).
  unaligned_uint16_t this_disk;

  // Number of the file containing the beginning of the central directory or
  // 0xFFFF if ZIP64 archive.
  unaligned_uint16_t cd_disk;

  // Number of central directory records on this disk or 0xFFFF if ZIP64
  // archive.
  unaligned_uint16_t cd_records;

  // Number of central directory records on all disks or 0xFFFF if ZIP64
  // archive.
  unaligned_uint16_t cd_records_total;

  // Size of the central directory recrod or 0xFFFFFFFF if ZIP64 archive.
  unaligned_uint32_t cd_size;

  // Offset of the central directory from the beginning of the archive or
  // 0xFFFFFFFF if ZIP64 archive.
  unaligned_uint32_t cd_offset;

  // Length of comment data following end of central driectory record.
  unaligned_uint16_t comment_length;

  // Up to 64k of arbitrary bytes.
  // uint8_t comment[comment_length]
};

#define CD_FILE_HEADER_MAGIC 0x02014b50
#define FLAG_ENCRYPTED (1 << 0)
#define FLAG_HAS_DATA_DESCRIPTOR (1 << 3)

// See section 4.3.12 of the spec.
struct central_directory_file_header {
  // Magic value equal to CD_FILE_HEADER_MAGIC.
  unaligned_uint32_t magic;
  unaligned_uint16_t version;
  // Minimum zip version needed to extract the file.
  unaligned_uint16_t min_version;
  unaligned_uint16_t flags;
  unaligned_uint16_t compression;
  unaligned_uint16_t last_modified_time;
  unaligned_uint16_t last_modified_date;
  unaligned_uint32_t crc;
  unaligned_uint32_t compressed_size;
  unaligned_uint32_t uncompressed_size;
  unaligned_uint16_t file_name_length;
  unaligned_uint16_t extra_field_length;
  unaligned_uint16_t file_comment_length;
  // Number of the disk where the file starts or 0xFFFF if ZIP64 archive.
  unaligned_uint16_t disk;
  unaligned_uint16_t internal_attributes;
  unaligned_uint32_t external_attributes;
  // Offset from the start of the disk containing the local file header to the
  // start of the local file header.
  unaligned_uint32_t offset;
};

#define LOCAL_FILE_HEADER_MAGIC 0x04034b50

// See section 4.3.7 of the spec.
struct local_file_header {
  // Magic value equal to LOCAL_FILE_HEADER_MAGIC.
  unaligned_uint32_t magic;
  // Minimum zip version needed to extract the file.
  unaligned_uint16_t min_version;
  unaligned_uint16_t flags;
  unaligned_uint16_t compression;
  unaligned_uint16_t last_modified_time;
  unaligned_uint16_t last_modified_date;
  unaligned_uint32_t crc;
  unaligned_uint32_t compressed_size;
  unaligned_uint32_t uncompressed_size;
  unaligned_uint16_t file_name_length;
  unaligned_uint16_t extra_field_length;
};

struct bcc_zip_archive {
  void* data;
  uint32_t size;
  uint32_t cd_offset;
  uint32_t cd_records;
};

static void* check_access(struct bcc_zip_archive* archive, uint32_t offset,
                          uint32_t size) {
  if (offset + size > archive->size || offset > offset + size) {
    return NULL;
  }
  return archive->data + offset;
}

// Returns 0 on success, -1 on error and -2 if the eocd indicates
// the archive uses features which are not supported.
static int try_parse_end_of_central_directory(struct bcc_zip_archive* archive,
                                              uint32_t offset) {
  struct end_of_central_directory_record* eocd = check_access(
      archive, offset, sizeof(struct end_of_central_directory_record));
  if (eocd == NULL ||
      unaligned_uint32_read(eocd->magic) != END_OF_CD_RECORD_MAGIC) {
    return -1;
  }

  uint16_t comment_length = unaligned_uint16_read(eocd->comment_length);
  if (offset + sizeof(struct end_of_central_directory_record) +
          comment_length !=
      archive->size) {
    return -1;
  }

  uint16_t cd_records = unaligned_uint16_read(eocd->cd_records);
  if (unaligned_uint16_read(eocd->this_disk) != 0 ||
      unaligned_uint16_read(eocd->cd_disk) != 0 ||
      unaligned_uint16_read(eocd->cd_records_total) != cd_records) {
    // This is a valid eocd, but we only support single-file non-ZIP64 archives.
    return -2;
  }

  uint32_t cd_offset = unaligned_uint32_read(eocd->cd_offset);
  uint32_t cd_size = unaligned_uint32_read(eocd->cd_size);
  if (check_access(archive, cd_offset, cd_size) == NULL) {
    return -1;
  }

  archive->cd_offset = cd_offset;
  archive->cd_records = cd_records;
  return 0;
}

static int find_central_directory(struct bcc_zip_archive* archive) {
  if (archive->size <= sizeof(struct end_of_central_directory_record)) {
    return -1;
  }

  int rc = -1;
  // Because the end of central directory ends with a variable length array of
  // up to 0xFFFF bytes we can't know exactly where it starts and need to
  // search for it at the end of the file, scanning the (limit, offset] range.
  int64_t offset =
      (int64_t)archive->size - sizeof(struct end_of_central_directory_record);
  int64_t limit = offset - (1 << 16);
  for (; offset >= 0 && offset > limit && rc == -1; offset--) {
    rc = try_parse_end_of_central_directory(archive, offset);
  }

  return rc;
}

struct bcc_zip_archive* bcc_zip_archive_open(const char* path) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    return NULL;
  }

  off_t size = lseek(fd, 0, SEEK_END);
  if (size == (off_t)-1 || size > UINT32_MAX) {
    close(fd);
    return NULL;
  }

  void* data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);

  if (data == MAP_FAILED) {
    return NULL;
  }

  struct bcc_zip_archive* archive = malloc(sizeof(struct bcc_zip_archive));
  if (archive == NULL) {
    munmap(data, size);
    return NULL;
  };

  archive->data = data;
  archive->size = size;
  if (find_central_directory(archive)) {
    munmap(data, size);
    free(archive);
    archive = NULL;
  }

  return archive;
}

void bcc_zip_archive_close(struct bcc_zip_archive* archive) {
  munmap(archive->data, archive->size);
  free(archive);
}

static struct local_file_header* local_file_header_at_offset(
    struct bcc_zip_archive* archive, uint32_t offset) {
  struct local_file_header* lfh =
      check_access(archive, offset, sizeof(struct local_file_header));
  if (lfh == NULL ||
      unaligned_uint32_read(lfh->magic) != LOCAL_FILE_HEADER_MAGIC) {
    return NULL;
  }
  return lfh;
}

static int get_entry_at_offset(struct bcc_zip_archive* archive, uint32_t offset,
                               struct bcc_zip_entry* out) {
  struct local_file_header* lfh = local_file_header_at_offset(archive, offset);
  offset += sizeof(struct local_file_header);
  if (lfh == NULL) {
    return -1;
  };

  uint16_t flags = unaligned_uint16_read(lfh->flags);
  if ((flags & FLAG_ENCRYPTED) || (flags & FLAG_HAS_DATA_DESCRIPTOR)) {
    return -1;
  }

  uint16_t name_length = unaligned_uint16_read(lfh->file_name_length);
  const char* name = check_access(archive, offset, name_length);
  offset += name_length;
  if (name == NULL) {
    return -1;
  }

  uint16_t extra_field_length = unaligned_uint16_read(lfh->extra_field_length);
  if (check_access(archive, offset, extra_field_length) == NULL) {
    return -1;
  }
  offset += extra_field_length;

  uint32_t compressed_size = unaligned_uint32_read(lfh->compressed_size);
  void* data = check_access(archive, offset, compressed_size);
  if (data == NULL) {
    return -1;
  }

  out->compression = unaligned_uint16_read(lfh->compression);
  out->name_length = name_length;
  out->name = name;
  out->data = data;
  out->data_length = compressed_size;
  out->data_offset = offset;

  return 0;
}

static struct central_directory_file_header* cd_file_header_at_offset(
    struct bcc_zip_archive* archive, uint32_t offset) {
  struct central_directory_file_header* cdfh = check_access(
      archive, offset, sizeof(struct central_directory_file_header));
  if (cdfh == NULL ||
      unaligned_uint32_read(cdfh->magic) != CD_FILE_HEADER_MAGIC) {
    return NULL;
  }
  return cdfh;
}

int bcc_zip_archive_find_entry(struct bcc_zip_archive* archive,
                               const char* file_name,
                               struct bcc_zip_entry* out) {
  size_t file_name_length = strlen(file_name);

  uint32_t offset = archive->cd_offset;
  for (uint32_t i = 0; i < archive->cd_records; ++i) {
    struct central_directory_file_header* cdfh =
        cd_file_header_at_offset(archive, offset);
    offset += sizeof(struct central_directory_file_header);
    if (cdfh == NULL) {
      return -1;
    }

    uint16_t cdfh_name_length = unaligned_uint16_read(cdfh->file_name_length);
    const char* cdfh_name = check_access(archive, offset, cdfh_name_length);
    if (cdfh_name == NULL) {
      return -1;
    }

    uint16_t cdfh_flags = unaligned_uint16_read(cdfh->flags);
    if ((cdfh_flags & FLAG_ENCRYPTED) == 0 &&
        (cdfh_flags & FLAG_HAS_DATA_DESCRIPTOR) == 0 &&
        file_name_length == cdfh_name_length &&
        memcmp(file_name, archive->data + offset, file_name_length) == 0) {
      return get_entry_at_offset(archive, unaligned_uint32_read(cdfh->offset),
                                 out);
    }

    offset += cdfh_name_length;
    offset += unaligned_uint16_read(cdfh->extra_field_length);
    offset += unaligned_uint16_read(cdfh->file_comment_length);
  }

  return -1;
}

int bcc_zip_archive_find_entry_at_offset(struct bcc_zip_archive* archive,
                                         uint32_t target,
                                         struct bcc_zip_entry* out) {
  uint32_t offset = archive->cd_offset;
  for (uint32_t i = 0; i < archive->cd_records; ++i) {
    struct central_directory_file_header* cdfh =
        cd_file_header_at_offset(archive, offset);
    offset += sizeof(struct central_directory_file_header);
    if (cdfh == NULL) {
      return -1;
    }

    uint16_t cdfh_flags = unaligned_uint16_read(cdfh->flags);
    if ((cdfh_flags & FLAG_ENCRYPTED) == 0 &&
        (cdfh_flags & FLAG_HAS_DATA_DESCRIPTOR) == 0) {
      if (get_entry_at_offset(archive, unaligned_uint32_read(cdfh->offset),
                              out)) {
        return -1;
      }

      if (out->data <= archive->data + target &&
          archive->data + target < out->data + out->data_length) {
        return 0;
      }
    }

    offset += unaligned_uint16_read(cdfh->file_name_length);
    offset += unaligned_uint16_read(cdfh->extra_field_length);
    offset += unaligned_uint16_read(cdfh->file_comment_length);
  }

  return -1;
}

struct bcc_zip_archive* bcc_zip_archive_open_and_find(
    const char* path, struct bcc_zip_entry* out) {
  struct bcc_zip_archive* archive = NULL;
  const char* separator = strstr(path, "!/");
  if (separator == NULL || separator - path >= PATH_MAX) {
    return NULL;
  }

  char archive_path[PATH_MAX];
  strncpy(archive_path, path, separator - path);
  archive_path[separator - path] = 0;
  archive = bcc_zip_archive_open(archive_path);
  if (archive == NULL) {
    return NULL;
  }

  if (bcc_zip_archive_find_entry(archive, separator + 2, out)) {
    bcc_zip_archive_close(archive);
    return NULL;
  }

  return archive;
}
