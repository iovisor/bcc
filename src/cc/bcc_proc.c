/*
 * Copyright (c) 2016 GitHub, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "bcc_proc.h"

#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bcc_elf.h"
#include "bcc_perf_map.h"
#include "bcc_zip.h"

#ifdef __x86_64__
// https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
const unsigned long long kernelAddrSpace = 0x00ffffffffffffff;
#else
const unsigned long long kernelAddrSpace = 0x0;
#endif

char *bcc_procutils_which(const char *binpath) {
  char buffer[4096];
  const char *PATH;

  if (strchr(binpath, '/'))
    return bcc_elf_is_exe(binpath) ? strdup(binpath) : 0;

  if (!(PATH = getenv("PATH")))
    return 0;

  while (PATH) {
    const char *next = strchr(PATH, ':') ?: strchr(PATH, '\0');
    const size_t path_len = next - PATH;

    if (path_len) {
      int ret = snprintf(buffer, sizeof(buffer), "%.*s/%s",
	                  (int)path_len, PATH, binpath);
      if (ret < 0 || ret >= sizeof(buffer))
        return 0;

      if (bcc_elf_is_exe(buffer))
        return strdup(buffer);
    }

    PATH = *next ? (next + 1) : 0;
  }

  return 0;
}

#define STARTS_WITH(mapname, prefix) (!strncmp(mapname, prefix, sizeof(prefix)-1))

int bcc_mapping_is_file_backed(const char *mapname) {
  return mapname[0] && !(
    STARTS_WITH(mapname, "//anon") ||
    STARTS_WITH(mapname, "/dev/zero") ||
    STARTS_WITH(mapname, "/anon_hugepage") ||
    STARTS_WITH(mapname, "[stack") ||
    STARTS_WITH(mapname, "/SYSV") ||
    STARTS_WITH(mapname, "[heap]") ||
    STARTS_WITH(mapname, "[vsyscall]"));
}

/*
Finds a file descriptor for a given inode if it's a memory-backed fd.
*/
static char *_procutils_memfd_path(const int pid, const uint64_t inum) {
  char path_buffer[PATH_MAX + 1];
  char *path = NULL;
  char *dirstr;
  DIR *dirstream;
  struct stat sb;
  struct dirent *dent;

  snprintf(path_buffer, (PATH_MAX + 1), "/proc/%d/fd", pid);
  dirstr = malloc(strlen(path_buffer) + 1);
  strcpy(dirstr, path_buffer);
  dirstream = opendir(dirstr);

  if (dirstream == NULL) {
    free(dirstr);
    return NULL;
  }

  while (path == NULL && (dent = readdir(dirstream)) != NULL) {
    snprintf(path_buffer, (PATH_MAX + 1), "%s/%s", dirstr, dent->d_name);
    if (stat(path_buffer, &sb) == -1)
      continue;

    if (sb.st_ino == inum) {
      char *pid_fd_path = malloc(strlen(path_buffer) + 1);
      strcpy(pid_fd_path, path_buffer);
      path = pid_fd_path;
    }
  }
  closedir(dirstream);
  free(dirstr);

  return path;
}

static int _procfs_might_be_zip_path(const char *path) {
  return strstr(path, ".zip") || strstr(path, ".apk");
}

static char *_procfs_find_zip_entry(const char *path, int pid,
                                    uint32_t *offset) {
  char ns_relative_path[PATH_MAX];
  int rc = snprintf(ns_relative_path, sizeof(ns_relative_path),
                    "/proc/%d/root%s", pid, path);
  if (rc < 0 || rc >= sizeof(ns_relative_path)) {
    return NULL;
  }

  struct bcc_zip_archive *archive = bcc_zip_archive_open(ns_relative_path);
  if (archive == NULL) {
    return NULL;
  }

  struct bcc_zip_entry entry;
  if (bcc_zip_archive_find_entry_at_offset(archive, *offset, &entry) ||
      entry.compression) {
    bcc_zip_archive_close(archive);
    return NULL;
  }

  char *result = malloc(strlen(path) + entry.name_length + 3);
  if (result == NULL) {
    bcc_zip_archive_close(archive);
    return NULL;
  }

  sprintf(result, "%s!/%.*s", path, entry.name_length, entry.name);
  *offset -= entry.data_offset;
  bcc_zip_archive_close(archive);
  return result;
}

// return: 0 -> callback returned < 0, stopped iterating
//        -1 -> callback never indicated to stop
int _procfs_maps_each_module(FILE *procmap, int pid,
                             bcc_procutils_modulecb callback, void *payload) {
  char buf[PATH_MAX + 1], perm[5];
  char *name, *resolved_name;
  mod_info mod;
  uint8_t enter_ns;
  while (true) {
    enter_ns = 1;
    buf[0] = '\0';
    // From fs/proc/task_mmu.c:show_map_vma
    if (fscanf(procmap, "%lx-%lx %4s %llx %lx:%lx %lu%[^\n]",
          &mod.start_addr, &mod.end_addr, perm, &mod.file_offset,
          &mod.dev_major, &mod.dev_minor, &mod.inode, buf) != 8)
      break;

    if (perm[2] != 'x')
      continue;

    name = buf;
    while (isspace(*name))
      name++;
    mod.name = name;
    if (!bcc_mapping_is_file_backed(name))
      continue;

    resolved_name = NULL;
    if (strstr(name, "/memfd:")) {
      resolved_name = _procutils_memfd_path(pid, mod.inode);
      if (resolved_name != NULL) {
        enter_ns = 0;
      }
    } else if (_procfs_might_be_zip_path(mod.name)) {
      uint32_t zip_entry_offset = mod.file_offset;
      resolved_name = _procfs_find_zip_entry(mod.name, pid, &zip_entry_offset);
      if (resolved_name != NULL) {
        mod.file_offset = zip_entry_offset;
      }
    }

    if (resolved_name != NULL) {
      strncpy(buf, resolved_name, PATH_MAX);
      buf[PATH_MAX] = 0;
      free(resolved_name);
      mod.name = buf;
    }

    if (callback(&mod, enter_ns, payload) < 0)
      return 0;
  }

  return -1;
}

int bcc_procutils_each_module(int pid, bcc_procutils_modulecb callback,
                              void *payload) {
  char procmap_filename[128];
  FILE *procmap;
  snprintf(procmap_filename, sizeof(procmap_filename), "/proc/%ld/maps",
           (long)pid);
  procmap = fopen(procmap_filename, "r");
  if (!procmap)
    return -1;

  _procfs_maps_each_module(procmap, pid, callback, payload);

  // Address mapping for the entire address space maybe in /tmp/perf-<PID>.map
  // This will be used if symbols aren't resolved in an earlier mapping.
  char map_path[4096];
  // Try perf-<PID>.map path with process's mount namespace, chroot and NSPID,
  // in case it is generated by the process itself.
  mod_info mod;
  memset(&mod, 0, sizeof(mod_info));
  if (bcc_perf_map_path(map_path, sizeof(map_path), pid)) {
    mod.name = map_path;
    mod.end_addr = -1;
    if (callback(&mod, 1, payload) < 0)
      goto done;
  }
  // Try perf-<PID>.map path with global root and PID, in case it is generated
  // by other Process. Avoid checking mount namespace for this.
  memset(&mod, 0, sizeof(mod_info));
  int res = snprintf(map_path, 4096, "/tmp/perf-%d.map", pid);
  if (res > 0 && res < 4096) {
    mod.name = map_path;
    mod.end_addr = -1;
    if (callback(&mod, 0, payload) < 0)
      goto done;
  }

done:
  fclose(procmap);
  return 0;
}

int bcc_procutils_each_ksym(bcc_procutils_ksymcb callback, void *payload) {
  char line[2048];
  char *symname, *endsym, *modname, *endmod = NULL;
  FILE *kallsyms;
  unsigned long long addr;

  /* root is needed to list ksym addresses */
  if (geteuid() != 0)
    return -1;

  kallsyms = fopen("/proc/kallsyms", "r");
  if (!kallsyms)
    return -1;

  while (fgets(line, sizeof(line), kallsyms)) {
    addr = strtoull(line, &symname, 16);
    if (addr == 0 || addr == ULLONG_MAX)
      continue;
    if (addr < kernelAddrSpace)
      continue;

    symname++;
    // Ignore data symbols
    if (*symname == 'b' || *symname == 'B' || *symname == 'd' ||
        *symname == 'D' || *symname == 'r' || *symname =='R')
      continue;

    endsym = (symname = symname + 2);
    while (*endsym && !isspace(*endsym)) endsym++;
    *endsym = '\0';

    // Parse module name if it's available
    modname = endsym + 1;
    while (*modname && isspace(*endsym)) modname++;

    if (*modname && *modname == '[') {
      endmod = ++modname;
      while (*endmod && *endmod != ']') endmod++;
      if (*endmod)
        *(endmod) = '\0';
      else
        endmod = NULL;
    }

    if (!endmod)
      modname = "kernel";

    callback(symname, modname, addr, payload);
  }

  fclose(kallsyms);
  return 0;
}

#define CACHE1_HEADER "ld.so-1.7.0"
#define CACHE1_HEADER_LEN (sizeof(CACHE1_HEADER) - 1)

#define CACHE2_HEADER "glibc-ld.so.cache"
#define CACHE2_HEADER_LEN (sizeof(CACHE2_HEADER) - 1)
#define CACHE2_VERSION "1.1"

struct ld_cache1_entry {
  int32_t flags;
  uint32_t key;
  uint32_t value;
};

struct ld_cache1 {
  char header[CACHE1_HEADER_LEN];
  uint32_t entry_count;
  struct ld_cache1_entry entries[0];
};

struct ld_cache2_entry {
  int32_t flags;
  uint32_t key;
  uint32_t value;
  uint32_t pad1_;
  uint64_t pad2_;
};

struct ld_cache2 {
  char header[CACHE2_HEADER_LEN];
  char version[3];
  uint32_t entry_count;
  uint32_t string_table_len;
  uint32_t pad_[5];
  struct ld_cache2_entry entries[0];
};

static int lib_cache_count;
static struct ld_lib {
  char *libname;
  char *path;
  int flags;
} * lib_cache;

static int read_cache1(const char *ld_map) {
  struct ld_cache1 *ldcache = (struct ld_cache1 *)ld_map;
  const char *ldstrings =
      (const char *)(ldcache->entries + ldcache->entry_count);
  uint32_t i;

  lib_cache =
      (struct ld_lib *)malloc(ldcache->entry_count * sizeof(struct ld_lib));
  lib_cache_count = (int)ldcache->entry_count;

  for (i = 0; i < ldcache->entry_count; ++i) {
    const char *key = ldstrings + ldcache->entries[i].key;
    const char *val = ldstrings + ldcache->entries[i].value;
    const int flags = ldcache->entries[i].flags;

    lib_cache[i].libname = strdup(key);
    lib_cache[i].path = strdup(val);
    lib_cache[i].flags = flags;
  }
  return 0;
}

static int read_cache2(const char *ld_map) {
  struct ld_cache2 *ldcache = (struct ld_cache2 *)ld_map;
  uint32_t i;

  if (memcmp(ld_map, CACHE2_HEADER, CACHE2_HEADER_LEN))
    return -1;

  lib_cache =
      (struct ld_lib *)malloc(ldcache->entry_count * sizeof(struct ld_lib));
  lib_cache_count = (int)ldcache->entry_count;

  for (i = 0; i < ldcache->entry_count; ++i) {
    const char *key = ld_map + ldcache->entries[i].key;
    const char *val = ld_map + ldcache->entries[i].value;
    const int flags = ldcache->entries[i].flags;

    lib_cache[i].libname = strdup(key);
    lib_cache[i].path = strdup(val);
    lib_cache[i].flags = flags;
  }
  return 0;
}

static int load_ld_cache(const char *cache_path) {
  struct stat st;
  size_t ld_size;
  const char *ld_map;
  int ret, fd = open(cache_path, O_RDONLY);

  if (fd < 0)
    return -1;

  if (fstat(fd, &st) < 0 || st.st_size < sizeof(struct ld_cache1)) {
    close(fd);
    return -1;
  }

  ld_size = st.st_size;
  ld_map = (const char *)mmap(NULL, ld_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (ld_map == MAP_FAILED) {
    close(fd);
    return -1;
  }

  if (memcmp(ld_map, CACHE1_HEADER, CACHE1_HEADER_LEN) == 0) {
    const struct ld_cache1 *cache1 = (struct ld_cache1 *)ld_map;
    size_t cache1_len = sizeof(struct ld_cache1) +
                        (cache1->entry_count * sizeof(struct ld_cache1_entry));
    cache1_len = (cache1_len + 0x7) & ~0x7ULL;

    if (ld_size > (cache1_len + sizeof(struct ld_cache2)))
      ret = read_cache2(ld_map + cache1_len);
    else
      ret = read_cache1(ld_map);
  } else {
    ret = read_cache2(ld_map);
  }

  munmap((void *)ld_map, ld_size);
  close(fd);
  return ret;
}

#define LD_SO_CACHE "/etc/ld.so.cache"
#define FLAG_TYPE_MASK 0x00ff
#define TYPE_ELF_LIBC6 0x0003
#define FLAG_ABI_MASK 0xff00
#define ABI_SPARC_LIB64 0x0100
#define ABI_IA64_LIB64 0x0200
#define ABI_X8664_LIB64 0x0300
#define ABI_S390_LIB64 0x0400
#define ABI_POWERPC_LIB64 0x0500
#define ABI_AARCH64_LIB64 0x0a00

static bool match_so_flags(int flags) {
  if ((flags & FLAG_TYPE_MASK) != TYPE_ELF_LIBC6)
    return false;

  switch (flags & FLAG_ABI_MASK) {
  case ABI_SPARC_LIB64:
  case ABI_IA64_LIB64:
  case ABI_X8664_LIB64:
  case ABI_S390_LIB64:
  case ABI_POWERPC_LIB64:
  case ABI_AARCH64_LIB64:
    return (sizeof(void *) == 8);
  }

  return sizeof(void *) == 4;
}

static bool which_so_in_process(const char* libname, int pid, char* libpath) {
  int ret, found = false;
  char endline[4096], *mapname = NULL, *newline;
  char mappings_file[128];
  const size_t search_len = strlen(libname) + strlen("/lib.");
  char search1[search_len + 1];
  char search2[search_len + 1];

  snprintf(mappings_file, sizeof(mappings_file), "/proc/%ld/maps", (long)pid);
  FILE *fp = fopen(mappings_file, "r");
  if (!fp)
    return NULL;

  snprintf(search1, search_len + 1, "/lib%s.", libname);
  snprintf(search2, search_len + 1, "/lib%s-", libname);

  do {
    ret = fscanf(fp, "%*x-%*x %*s %*x %*s %*d");
    if (!fgets(endline, sizeof(endline), fp))
      break;

    mapname = endline;
    newline = strchr(endline, '\n');
    if (newline)
      newline[0] = '\0';

    while (isspace(mapname[0])) mapname++;

    if (strstr(mapname, ".so") && (strstr(mapname, search1) ||
                                   strstr(mapname, search2))) {
      found = true;
      memcpy(libpath, mapname, strlen(mapname) + 1);
      break;
    }
  } while (ret != EOF);

  fclose(fp);
  return found;
}

char *bcc_procutils_which_so(const char *libname, int pid) {
  const size_t soname_len = strlen(libname) + strlen("lib.so");
  char soname[soname_len + 1];
  char libpath[4096];
  int i;

  if (strchr(libname, '/'))
    return strdup(libname);

  if (pid && which_so_in_process(libname, pid, libpath))
    return strdup(libpath);

  if (lib_cache_count < 0)
    return NULL;

  if (!lib_cache_count && load_ld_cache(LD_SO_CACHE) < 0) {
    lib_cache_count = -1;
    return NULL;
  }

  snprintf(soname, soname_len + 1, "lib%s.so", libname);

  for (i = 0; i < lib_cache_count; ++i) {
    if (!strncmp(lib_cache[i].libname, soname, soname_len) &&
        match_so_flags(lib_cache[i].flags)) {
      return strdup(lib_cache[i].path);
    }
  }
  return NULL;
}

void bcc_procutils_free(const char *ptr) {
  free((void *)ptr);
}

/* Detects the following languages + C. */
const char *languages[] = {"java", "node", "perl", "php", "python", "ruby"};
const char *language_c = "c";
const int nb_languages = 6;

const char *bcc_procutils_language(int pid) {
  char procfilename[24], line[4096], pathname[32], *str;
  FILE *procfile;
  int i, ret;

  /* Look for clues in the absolute path to the executable. */
  snprintf(procfilename, sizeof(procfilename), "/proc/%ld/exe", (long)pid);
  if (realpath(procfilename, line)) {
    for (i = 0; i < nb_languages; i++)
      if (strstr(line, languages[i]))
        return languages[i];
  }


  snprintf(procfilename, sizeof(procfilename), "/proc/%ld/maps", (long)pid);
  procfile = fopen(procfilename, "r");
  if (!procfile)
    return NULL;

  /* Look for clues in memory mappings. */
  bool libc = false;
  do {
    char perm[8], dev[8];
    long long begin, end, size, inode;
    ret = fscanf(procfile, "%llx-%llx %s %llx %s %lld", &begin, &end, perm,
                 &size, dev, &inode);
    if (!fgets(line, sizeof(line), procfile))
      break;
    if (ret == 6) {
      char *mapname = line;
      char *newline = strchr(line, '\n');
      if (newline)
        newline[0] = '\0';
      while (isspace(mapname[0])) mapname++;
      for (i = 0; i < nb_languages; i++) {
        snprintf(pathname, sizeof(pathname), "/lib%s", languages[i]);
        if (strstr(mapname, pathname)) {
          fclose(procfile);
          return languages[i];
	}
        if ((str = strstr(mapname, "libc")) &&
            (str[4] == '-' || str[4] == '.'))
          libc = true;
      }
    }
  } while (ret && ret != EOF);

  fclose(procfile);

  /* Return C as the language if libc was found and nothing else. */
  return libc ? language_c : NULL;
}
