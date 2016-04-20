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
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <gelf.h>
#include "bcc_elf.h"
#define NT_STAPSDT 3

static int openelf(const char *path, Elf **elf_out, int *fd_out) {
  if (elf_version(EV_CURRENT) == EV_NONE)
    return -1;

  *fd_out = open(path, O_RDONLY);
  if (*fd_out < 0)
    return -1;

  *elf_out = elf_begin(*fd_out, ELF_C_READ, 0);
  if (*elf_out == 0) {
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
                           void *payload) {
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

      if (parse_stapsdt_note(&probe, desc, elf_class) == desc_end)
        callback(binpath, &probe, payload);
    }
  }
  return 0;
}

static int listprobes(Elf *e, bcc_elf_probecb callback, const char *binpath,
                      void *payload) {
  Elf_Scn *section = NULL;
  size_t stridx;
  int elf_class = gelf_getclass(e);

  if (elf_getshdrstrndx(e, &stridx) != 0)
    return -1;

  while ((section = elf_nextscn(e, section)) != 0) {
    GElf_Shdr header;
    char *name;

    if (!gelf_getshdr(section, &header))
      continue;

    if (header.sh_type != SHT_NOTE)
      continue;

    name = elf_strptr(e, stridx, header.sh_name);
    if (name && !strcmp(name, ".note.stapsdt")) {
      if (do_note_segment(section, elf_class, callback, binpath, payload) < 0)
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

      if (callback(name, sym.st_value, sym.st_size, sym.st_info, payload) < 0)
        break;
    }
  }

  return 0;
}

static int listsymbols(Elf *e, bcc_elf_symcb callback, void *payload) {
  Elf_Scn *section = NULL;

  while ((section = elf_nextscn(e, section)) != 0) {
    GElf_Shdr header;

    if (!gelf_getshdr(section, &header))
      continue;

    if (header.sh_type != SHT_SYMTAB && header.sh_type != SHT_DYNSYM)
      continue;

    if (list_in_scn(e, section, header.sh_link, header.sh_entsize, callback,
                    payload) < 0)
      return -1;
  }

  return 0;
}

int bcc_elf_foreach_sym(const char *path, bcc_elf_symcb callback,
                        void *payload) {
  Elf *e;
  int fd, res;

  if (openelf(path, &e, &fd) < 0)
    return -1;

  res = listsymbols(e, callback, payload);
  elf_end(e);
  close(fd);
  return res;
}

static int loadaddr(Elf *e, uint64_t *addr) {
  size_t phnum, i;

  if (elf_getphdrnum(e, &phnum) != 0)
    return -1;

  for (i = 0; i < phnum; ++i) {
    GElf_Phdr header;

    if (!gelf_getphdr(e, (int)i, &header))
      continue;

    if (header.p_type != PT_LOAD)
      continue;

    *addr = (uint64_t)header.p_vaddr;
    return 0;
  }

  return -1;
}

int bcc_elf_loadaddr(const char *path, uint64_t *address) {
  Elf *e;
  int fd, res;

  if (openelf(path, &e, &fd) < 0)
    return -1;

  res = loadaddr(e, address);
  elf_end(e);
  close(fd);

  return res;
}

int bcc_elf_is_shared_obj(const char *path) {
  Elf *e;
  GElf_Ehdr hdr;
  int fd, res = -1;

  if (openelf(path, &e, &fd) < 0)
    return -1;

  if (gelf_getehdr(e, &hdr))
    res = (hdr.e_type == ET_DYN);

  elf_end(e);
  close(fd);

  return res;
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
