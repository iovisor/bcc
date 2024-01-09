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

#ifndef LIBBCC_ZIP_H
#define LIBBCC_ZIP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Represents an opened zip archive.
// Only basic ZIP files are supported, in particular the following are not
// supported:
// - encryption
// - streaming
// - multi-part ZIP files
// - ZIP64
struct bcc_zip_archive;

// Carries information on name, compression method and data corresponding to
// a file in a zip archive.
struct bcc_zip_entry {
  // Compression method as defined in pkzip spec. 0 means data is uncompressed.
  uint16_t compression;

  // Non-null terminated name of the file.
  const char* name;
  // Length of the file name.
  uint16_t name_length;

  // Pointer to the file data.
  const void* data;
  // Length of the file data.
  uint32_t data_length;
  // Offset of the file data within the archive.
  uint32_t data_offset;
};

// Opens a zip archive. Returns NULL in case of an error.
struct bcc_zip_archive* bcc_zip_archive_open(const char* path);

// Closes a zip archive and releases resources.
void bcc_zip_archive_close(struct bcc_zip_archive* archive);

// Looks up data corresponding to a file in given zip archive.
int bcc_zip_archive_find_entry(struct bcc_zip_archive* archive,
                               const char* name, struct bcc_zip_entry* out);

int bcc_zip_archive_find_entry_at_offset(struct bcc_zip_archive* archive,
                                         uint32_t offset,
                                         struct bcc_zip_entry* out);

// Opens a zip archives and looks up entry within the archive.
// Provided path is interpreted as archive path followed by "!/"
// characters and name of the zip entry. This convention is used
// by Android tools.
struct bcc_zip_archive* bcc_zip_archive_open_and_find(
    const char* path, struct bcc_zip_entry* out);

#ifdef __cplusplus
}
#endif
#endif
