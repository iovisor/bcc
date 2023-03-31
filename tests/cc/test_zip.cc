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

#include <cstring>

#include "bcc_zip.h"
#include "catch.hpp"

#define LIB_ENTRY_NAME "libdebuginfo_test_lib.so"
#define ENTRY_IN_SUBDIR_NAME "zip_subdir/file.txt"
#define NOT_AN_ARCHIVE_PATH CMAKE_CURRENT_BINARY_DIR "/dummy_proc_map.txt"
#define TEST_ARCHIVE_PATH CMAKE_CURRENT_BINARY_DIR "/archive.zip"

namespace {

void require_entry_name_is(const bcc_zip_entry& entry, const char* name) {
  REQUIRE(entry.name_length == strlen(name));
  REQUIRE(memcmp(entry.name, name, strlen(name)) == 0);
}

bcc_zip_entry get_required_entry(bcc_zip_archive* archive,
                                 const char* asset_name) {
  bcc_zip_entry out;
  REQUIRE(bcc_zip_archive_find_entry(archive, asset_name, &out) == 0);
  require_entry_name_is(out, asset_name);
  return out;
}

const void* get_uncompressed_data(const bcc_zip_entry& entry) {
  REQUIRE(entry.compression == 0);
  REQUIRE(entry.data_offset > 0);
  REQUIRE(entry.data != nullptr);
  return entry.data;
}

}  // namespace

TEST_CASE("returns error for non-zip files", "[zip]") {
  bcc_zip_archive* archive = bcc_zip_archive_open(NOT_AN_ARCHIVE_PATH);
  REQUIRE(archive == nullptr);
}

TEST_CASE("finds entries in a zip archive by name", "[zip]") {
  bcc_zip_archive* archive = bcc_zip_archive_open(TEST_ARCHIVE_PATH);
  REQUIRE(archive != nullptr);

  bcc_zip_entry entry = get_required_entry(archive, LIB_ENTRY_NAME);
  REQUIRE(memcmp(get_uncompressed_data(entry),
                 "\x7f"
                 "ELF",
                 4) == 0);

  entry = get_required_entry(archive, ENTRY_IN_SUBDIR_NAME);
  REQUIRE(memcmp(get_uncompressed_data(entry), "This is a text file\n", 20) ==
          0);

  REQUIRE(bcc_zip_archive_find_entry(archive, "missing", &entry) == -1);

  bcc_zip_archive_close(archive);
}

TEST_CASE("finds entries in a zip archive by offset", "[zip]") {
  bcc_zip_archive* archive = bcc_zip_archive_open(TEST_ARCHIVE_PATH);
  REQUIRE(archive != nullptr);

  bcc_zip_entry entry;
  REQUIRE(bcc_zip_archive_find_entry_at_offset(archive, 100, &entry) == 0);
  require_entry_name_is(entry, LIB_ENTRY_NAME);
  REQUIRE(memcmp(get_uncompressed_data(entry),
                 "\x7f"
                 "ELF",
                 4) == 0);

  REQUIRE(bcc_zip_archive_find_entry_at_offset(archive, 100000, &entry) == -1);

  bcc_zip_archive_close(archive);
}

TEST_CASE("open zip archive and finds an entry", "[zip]") {
  bcc_zip_entry entry;
  bcc_zip_archive* archive = bcc_zip_archive_open_and_find(
      TEST_ARCHIVE_PATH "!/" LIB_ENTRY_NAME, &entry);
  REQUIRE(archive != nullptr);
  require_entry_name_is(entry, LIB_ENTRY_NAME);
  REQUIRE(memcmp(get_uncompressed_data(entry),
                 "\x7f"
                 "ELF",
                 4) == 0);
  bcc_zip_archive_close(archive);

  archive = bcc_zip_archive_open_and_find(
      TEST_ARCHIVE_PATH "!/" ENTRY_IN_SUBDIR_NAME, &entry);
  REQUIRE(archive != nullptr);
  require_entry_name_is(entry, ENTRY_IN_SUBDIR_NAME);
  REQUIRE(memcmp(get_uncompressed_data(entry), "This is a text file\n", 20) ==
          0);
  bcc_zip_archive_close(archive);

  archive =
      bcc_zip_archive_open_and_find(TEST_ARCHIVE_PATH "!/NOT_FOUND", &entry);
  REQUIRE(archive == nullptr);
}
