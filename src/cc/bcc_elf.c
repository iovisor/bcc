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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include <gelf.h>
#include "bcc_elf.h"
#include "bcc_proc.h"
#include "bcc_syms.h"

#define NT_STAPSDT 3
#define ELF_ST_TYPE(x) (((uint32_t) x) & 0xf)

static int openelf_fd(int fd, Elf **elf_out) {
  if (elf_version(EV_CURRENT) == EV_NONE)
    return -1;

  *elf_out = elf_begin(fd, ELF_C_READ, 0);
  if (*elf_out == NULL)
    return -1;

  return 0;
}

static int openelf(const char *path, Elf **elf_out, int *fd_out) {
  *fd_out = open(path, O_RDONLY);
  if (*fd_out < 0)
    return -1;

  if (openelf_fd(*fd_out, elf_out) == -1) {
    close(*fd_out);
    return -1;
  }

  return 0;
}

static const char *parse_stapsdt_note(struct bcc_elf_usdt *probe,
                                      const char *desc, int elf_class) {
  if (elf_class == ELFCLASS32) {
    probe->pc = *((uint32_t *)(desc));
    probe->base_addr = *((uint32_t *)(desc + 4));
    probe->semaphore = *((uint32_t *)(desc + 8));
    desc = desc + 12;
  } else {
    probe->pc = *((uint64_t *)(desc));
    probe->base_addr = *((uint64_t *)(desc + 8));
    probe->semaphore = *((uint64_t *)(desc + 16));
    desc = desc + 24;
  }

  probe->provider = desc;
  desc += strlen(desc) + 1;

  probe->name = desc;
  desc += strlen(desc) + 1;

  probe->arg_fmt = desc;
  desc += strlen(desc) + 1;

  return desc;
}

static int do_note_segment(Elf_Scn *section, int elf_class,
                           bcc_elf_probecb callback, const char *binpath,
                           uint64_t first_inst_offset, void *payload) {
  Elf_Data *data = NULL;

  while ((data = elf_getdata(section, data)) != 0) {
    size_t offset = 0;
    GElf_Nhdr hdr;
    size_t name_off, desc_off;

    while ((offset = gelf_getnote(data, offset, &hdr, &name_off, &desc_off)) !=
           0) {
      const char *desc, *desc_end;
      struct bcc_elf_usdt probe;

      if (hdr.n_type != NT_STAPSDT)
        continue;

      if (hdr.n_namesz != 8)
        continue;

      if (memcmp((const char *)data->d_buf + name_off, "stapsdt", 8) != 0)
        continue;

      desc = (const char *)data->d_buf + desc_off;
      desc_end = desc + hdr.n_descsz;

      if (parse_stapsdt_note(&probe, desc, elf_class) == desc_end) {
        if (probe.pc < first_inst_offset)
          fprintf(stderr,
                  "WARNING: invalid address 0x%lx for probe (%s,%s) in binary %s\n",
                  probe.pc, probe.provider, probe.name, binpath);
        else
          callback(binpath, &probe, payload);
      }
    }
  }
  return 0;
}

static int listprobes(Elf *e, bcc_elf_probecb callback, const char *binpath,
                      void *payload) {
  Elf_Scn *section = NULL;
  size_t stridx;
  int elf_class = gelf_getclass(e);
  uint64_t first_inst_offset = 0;

  if (elf_getshdrstrndx(e, &stridx) != 0)
    return -1;

  // Get the offset to the first instruction
  while ((section = elf_nextscn(e, section)) != 0) {
    GElf_Shdr header;

    if (!gelf_getshdr(section, &header))
      continue;

    // The elf file section layout is based on increasing virtual address,
    // getting the first section with SHF_EXECINSTR is enough.
    if (header.sh_flags & SHF_EXECINSTR) {
      first_inst_offset = header.sh_addr;
      break;
    }
  }

  while ((section = elf_nextscn(e, section)) != 0) {
    GElf_Shdr header;
    char *name;

    if (!gelf_getshdr(section, &header))
      continue;

    if (header.sh_type != SHT_NOTE)
      continue;

    name = elf_strptr(e, stridx, header.sh_name);
    if (name && !strcmp(name, ".note.stapsdt")) {
      if (do_note_segment(section, elf_class, callback, binpath,
                          first_inst_offset, payload) < 0)
        return -1;
    }
  }

  return 0;
}

int bcc_elf_foreach_usdt(const char *path, bcc_elf_probecb callback,
                         void *payload) {
  Elf *e;
  int fd, res;

  if (openelf(path, &e, &fd) < 0)
    return -1;

  res = listprobes(e, callback, path, payload);
  elf_end(e);
  close(fd);

  return res;
}

static int list_in_scn(Elf *e, Elf_Scn *section, size_t stridx, size_t symsize,
                       struct bcc_symbol_option *option,
                       bcc_elf_symcb callback, void *payload) {
  Elf_Data *data = NULL;

  while ((data = elf_getdata(section, data)) != 0) {
    size_t i, symcount = data->d_size / symsize;

    if (data->d_size % symsize)
      return -1;

    for (i = 0; i < symcount; ++i) {
      GElf_Sym sym;
      const char *name;

      if (!gelf_getsym(data, (int)i, &sym))
        continue;

      if ((name = elf_strptr(e, stridx, sym.st_name)) == NULL)
        continue;
      if (name[0] == 0)
        continue;

      if (sym.st_value == 0)
        continue;

      uint32_t st_type = ELF_ST_TYPE(sym.st_info);
      if (!(option->use_symbol_type & (1 << st_type)))
        continue;

      if (callback(name, sym.st_value, sym.st_size, payload) < 0)
        return 1;      // signal termination to caller
    }
  }

  return 0;
}

static int listsymbols(Elf *e, bcc_elf_symcb callback, void *payload,
                       struct bcc_symbol_option *option) {
  Elf_Scn *section = NULL;

  while ((section = elf_nextscn(e, section)) != 0) {
    GElf_Shdr header;

    if (!gelf_getshdr(section, &header))
      continue;

    if (header.sh_type != SHT_SYMTAB && header.sh_type != SHT_DYNSYM)
      continue;

    int rc = list_in_scn(e, section, header.sh_link, header.sh_entsize,
                         option, callback, payload);
    if (rc == 1)
      break;    // callback signaled termination

    if (rc < 0)
      return rc;
  }

  return 0;
}

static Elf_Data * get_section_elf_data(Elf *e, const char *section_name) {
  Elf_Scn *section = NULL;
  GElf_Shdr header;
  char *name;

  size_t stridx;
  if (elf_getshdrstrndx(e, &stridx) != 0)
    return NULL;

  while ((section = elf_nextscn(e, section)) != 0) {
    if (!gelf_getshdr(section, &header))
      continue;

    name = elf_strptr(e, stridx, header.sh_name);
    if (name && !strcmp(name, section_name)) {
      return elf_getdata(section, NULL);
    }
  }

  return NULL;
}

static int find_debuglink(Elf *e, char **debug_file, unsigned int *crc) {
  Elf_Data *data = NULL;

  *debug_file = NULL;
  *crc = 0;

  data = get_section_elf_data(e, ".gnu_debuglink");
  if (!data || data->d_size <= 5)
    return 0;

  *debug_file = (char *)data->d_buf;
  *crc = *(unsigned int*)((char *)data->d_buf + data->d_size - 4);

  return *debug_file ? 1 : 0;
}

static int find_buildid(Elf *e, char *buildid) {
  Elf_Data *data = get_section_elf_data(e, ".note.gnu.build-id");
  if (!data || data->d_size <= 16 || strcmp((char *)data->d_buf + 12, "GNU"))
    return 0;

  char *buf = (char *)data->d_buf + 16;
  size_t length = data->d_size - 16;
  size_t i = 0;
  for (i = 0; i < length; ++i) {
    sprintf(buildid + (i * 2), "%02hhx", buf[i]);
  }

  return 1;
}

// The CRC algorithm used by GNU debuglink. Taken from:
//    https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html
static unsigned int gnu_debuglink_crc32(unsigned int crc,
                                        char *buf, size_t len) {
  static const unsigned int crc32_table[256] =
  {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419,
    0x706af48f, 0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4,
    0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07,
    0x90bf1d91, 0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
    0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7, 0x136c9856,
    0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4,
    0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
    0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3,
    0x45df5c75, 0xdcd60dcf, 0xabd13d59, 0x26d930ac, 0x51de003a,
    0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599,
    0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190,
    0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f,
    0x9fbfe4a5, 0xe8b8d433, 0x7807c9a2, 0x0f00f934, 0x9609a88e,
    0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
    0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed,
    0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3,
    0xfbd44c65, 0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
    0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a,
    0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5,
    0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa, 0xbe0b1010,
    0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17,
    0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6,
    0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615,
    0x73dc1683, 0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
    0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1, 0xf00f9344,
    0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a,
    0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
    0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1,
    0xa6bc5767, 0x3fb506dd, 0x48b2364b, 0xd80d2bda, 0xaf0a1b4c,
    0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef,
    0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe,
    0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31,
    0x2cd99e8b, 0x5bdeae1d, 0x9b64c2b0, 0xec63f226, 0x756aa39c,
    0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
    0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b,
    0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1,
    0x18b74777, 0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
    0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45, 0xa00ae278,
    0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7,
    0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc, 0x40df0b66,
    0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605,
    0xcdd70693, 0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8,
    0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b,
    0x2d02ef8d
  };
  char *end;

  crc = ~crc & 0xffffffff;
  for (end = buf + len; buf < end; ++buf)
    crc = crc32_table[(crc ^ *buf) & 0xff] ^ (crc >> 8);
  return ~crc & 0xffffffff;
}

static int verify_checksum(const char *file, unsigned int crc) {
  struct stat st;
  int fd;
  void *buf;
  unsigned int actual;

  fd = open(file, O_RDONLY);
  if (fd < 0)
    return 0;

  if (fstat(fd, &st) < 0)
    return 0;

  buf = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (!buf) {
    close(fd);
    return 0;
  }

  actual = gnu_debuglink_crc32(0, buf, st.st_size);

  munmap(buf, st.st_size);
  close(fd);
  return actual == crc;
}

static char *find_debug_via_debuglink(Elf *e, const char *binpath,
                                      int check_crc) {
  char fullpath[PATH_MAX];
  char *bindir = NULL;
  char *res = NULL;
  unsigned int crc;
  char *name;  // the name of the debuginfo file

  if (!find_debuglink(e, &name, &crc))
    return NULL;

  bindir = strdup(binpath);
  bindir = dirname(bindir);

  // Search for the file in 'binpath', but ignore the file we find if it
  // matches the binary itself: the binary will always be probed later on,
  // and it might contain poorer symbols (e.g. stripped or partial symbols)
  // than the external debuginfo that might be available elsewhere.
  snprintf(fullpath, sizeof(fullpath),"%s/%s", bindir, name);
  if (strcmp(fullpath, binpath) != 0 && access(fullpath, F_OK) != -1) {
    res = strdup(fullpath);
    goto DONE;
  }

  // Search for the file in 'binpath'/.debug
  snprintf(fullpath, sizeof(fullpath), "%s/.debug/%s", bindir, name);
  if (access(fullpath, F_OK) != -1) {
    res = strdup(fullpath);
    goto DONE;
  }

  // Search for the file in the global debug directory /usr/lib/debug/'binpath'
  snprintf(fullpath, sizeof(fullpath), "/usr/lib/debug%s/%s", bindir, name);
  if (access(fullpath, F_OK) != -1) {
    res = strdup(fullpath);
    goto DONE;
  }

DONE:
  free(bindir);
  if (check_crc && !verify_checksum(res, crc))
    return NULL;
  return res;
}

static char *find_debug_via_buildid(Elf *e) {
  char fullpath[PATH_MAX];
  char buildid[128];  // currently 40 seems to be default, let's be safe

  if (!find_buildid(e, buildid))
    return NULL;

  // Search for the file in the global debug directory with a sub-path:
  //    mm/nnnnnn...nnnn.debug
  // Where mm are the first two characters of the buildid, and nnnn are the
  // rest of the build id, followed by .debug.
  snprintf(fullpath, sizeof(fullpath), "/usr/lib/debug/.build-id/%c%c/%s.debug",
          buildid[0], buildid[1], buildid + 2);
  if (access(fullpath, F_OK) != -1) {
    return strdup(fullpath);
  }

  return NULL;
}

static int foreach_sym_core(const char *path, bcc_elf_symcb callback,
                            struct bcc_symbol_option *option, void *payload,
                            int is_debug_file) {
  Elf *e;
  int fd, res;
  char *debug_file;

  if (!option)
    return -1;

  if (openelf(path, &e, &fd) < 0)
    return -1;

  // If there is a separate debuginfo file, try to locate and read it, first
  // using the build-id section, then using the debuglink section. These are
  // also the rules that GDB folows.
  // See: https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html
  if (option->use_debug_file && !is_debug_file) {
    // The is_debug_file argument helps avoid infinitely resolving debuginfo
    // files for debuginfo files and so on.
    debug_file = find_debug_via_buildid(e);
    if (!debug_file)
      debug_file = find_debug_via_debuglink(e, path,
                                            option->check_debug_file_crc);
    if (debug_file) {
      foreach_sym_core(debug_file, callback, option, payload, 1);
      free(debug_file);
    }
  }

  res = listsymbols(e, callback, payload, option);
  elf_end(e);
  close(fd);
  return res;
}

int bcc_elf_foreach_sym(const char *path, bcc_elf_symcb callback,
                        void *option, void *payload) {
  return foreach_sym_core(
      path, callback, (struct bcc_symbol_option*)option, payload, 0);
}

int bcc_elf_foreach_load_section(const char *path,
                                 bcc_elf_load_sectioncb callback,
                                 void *payload) {
  Elf *e = NULL;
  int fd = -1, err = -1, res;
  size_t nhdrs, i;

  if (openelf(path, &e, &fd) < 0)
    goto exit;

  if (elf_getphdrnum(e, &nhdrs) != 0)
    goto exit;

  GElf_Phdr header;
  for (i = 0; i < nhdrs; i++) {
    if (!gelf_getphdr(e, (int)i, &header))
      continue;
    if (header.p_type != PT_LOAD || !(header.p_flags & PF_X))
      continue;
    res = callback(header.p_vaddr, header.p_memsz, header.p_offset, payload);
    if (res < 0) {
      err = 1;
      goto exit;
    }
  }
  err = 0;

exit:
  if (e)
    elf_end(e);
  if (fd >= 0)
    close(fd);
  return err;
}

int bcc_elf_get_type(const char *path) {
  Elf *e;
  GElf_Ehdr hdr;
  int fd;
  void* res = NULL;

  if (openelf(path, &e, &fd) < 0)
    return -1;

  res = (void*)gelf_getehdr(e, &hdr);
  elf_end(e);
  close(fd);

  if (!res)
    return -1;
  else
    return hdr.e_type;
}

int bcc_elf_is_exe(const char *path) {
  return (bcc_elf_get_type(path) != -1) && (access(path, X_OK) == 0);
}

int bcc_elf_is_shared_obj(const char *path) {
  return bcc_elf_get_type(path) == ET_DYN;
}

int bcc_elf_is_vdso(const char *name) {
  return strcmp(name, "[vdso]") == 0;
}

// -2: Failed
// -1: Not initialized
// >0: Initialized
static int vdso_image_fd = -1;

static int find_vdso(const char *name, uint64_t st, uint64_t en,
                     uint64_t offset, bool enter_ns, void *payload) {
  int fd;
  char tmpfile[128];
  if (!bcc_elf_is_vdso(name))
    return 0;

  void *image = malloc(en - st);
  if (!image)
    goto on_error;
  memcpy(image, (void *)st, en - st);

  snprintf(tmpfile, sizeof(tmpfile), "/tmp/bcc_%d_vdso_image_XXXXXX", getpid());
  fd = mkostemp(tmpfile, O_CLOEXEC);
  if (fd < 0) {
    fprintf(stderr, "Unable to create temp file: %s\n", strerror(errno));
    goto on_error;
  }
  // Unlink the file to avoid leaking
  if (unlink(tmpfile) == -1)
    fprintf(stderr, "Unlink %s failed: %s\n", tmpfile, strerror(errno));

  if (write(fd, image, en - st) == -1) {
    fprintf(stderr, "Failed to write to vDSO image: %s\n", strerror(errno));
    close(fd);
    goto on_error;
  }
  vdso_image_fd = fd;

on_error:
  if (image)
    free(image);
  // Always stop the iteration
  return -1;
}

int bcc_elf_foreach_vdso_sym(bcc_elf_symcb callback, void *payload) {
  Elf *elf;
  static struct bcc_symbol_option default_option = {
    .use_debug_file = 0,
    .check_debug_file_crc = 0,
    .use_symbol_type = (1 << STT_FUNC) | (1 << STT_GNU_IFUNC)
  };

  if (vdso_image_fd == -1) {
    vdso_image_fd = -2;
    bcc_procutils_each_module(getpid(), &find_vdso, NULL);
  }
  if (vdso_image_fd == -2)
    return -1;

  if (openelf_fd(vdso_image_fd, &elf) == -1)
    return -1;

  return listsymbols(elf, callback, payload, &default_option);
}

#if 0
#include <stdio.h>

int main(int argc, char *argv[])
{
  uint64_t addr;
  if (bcc_elf_findsym(argv[1], argv[2], -1, STT_FUNC, &addr) < 0)
    return -1;

  printf("%s: %p\n", argv[2], (void *)addr);
  return 0;
}
#endif
