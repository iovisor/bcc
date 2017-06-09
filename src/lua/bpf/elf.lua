--[[
Copyright 2016 Marek Vavrusa <mvavrusa@cloudflare.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]
-- This is a tiny wrapper over libelf to extract load address
-- and offsets of dynamic symbols

local S = require('syscall')
local ffi = require('ffi')
ffi.cdef [[
/* Type for a 16-bit quantity.  */
typedef uint16_t Elf32_Half;
typedef uint16_t Elf64_Half;

/* Types for signed and unsigned 32-bit quantities.  */
typedef uint32_t Elf32_Word;
typedef int32_t  Elf32_Sword;
typedef uint32_t Elf64_Word;
typedef int32_t  Elf64_Sword;

/* Types for signed and unsigned 64-bit quantities.  */
typedef uint64_t Elf32_Xword;
typedef int64_t  Elf32_Sxword;
typedef uint64_t Elf64_Xword;
typedef int64_t  Elf64_Sxword;

/* Type of addresses.  */
typedef uint32_t Elf32_Addr;
typedef uint64_t Elf64_Addr;

/* Type of file offsets.  */
typedef uint32_t Elf32_Off;
typedef uint64_t Elf64_Off;

/* Type for section indices, which are 16-bit quantities.  */
typedef uint16_t Elf32_Section;
typedef uint16_t Elf64_Section;

/* Constants */
struct Elf_Cmd
{
  static const int READ              = 1;
  static const int RDWR              = 2;
  static const int WRITE             = 3;
  static const int CLR               = 4;
  static const int SET               = 5;
  static const int FDDONE            = 6;
  static const int FDREAD            = 7;
  static const int READ_MMAP         = 8;
  static const int RDWR_MMAP         = 9;
  static const int WRITE_MMAP        =10;
  static const int READ_MMAP_PRIVATE =11;
  static const int EMPTY             =12;
  static const int NUM               =13;
};

/* Descriptor for the ELF file.  */
typedef struct Elf Elf;
/* Descriptor for ELF file section.  */
typedef struct Elf_Scn Elf_Scn;
/* Container type for metatable */
struct Elf_object { int fd; Elf *elf; };
/* Program segment header.  */
typedef struct
{
  Elf64_Word    p_type;                 /* Segment type */
  Elf64_Word    p_flags;                /* Segment flags */
  Elf64_Off     p_offset;               /* Segment file offset */
  Elf64_Addr    p_vaddr;                /* Segment virtual address */
  Elf64_Addr    p_paddr;                /* Segment physical address */
  Elf64_Xword   p_filesz;               /* Segment size in file */
  Elf64_Xword   p_memsz;                /* Segment size in memory */
  Elf64_Xword   p_align;                /* Segment alignment */
} Elf64_Phdr;
typedef Elf64_Phdr GElf_Phdr;
/* Section header.  */
typedef struct
{
  Elf64_Word    sh_name;                /* Section name (string tbl index) */
  Elf64_Word    sh_type;                /* Section type */
  Elf64_Xword   sh_flags;               /* Section flags */
  Elf64_Addr    sh_addr;                /* Section virtual addr at execution */
  Elf64_Off     sh_offset;              /* Section file offset */
  Elf64_Xword   sh_size;                /* Section size in bytes */
  Elf64_Word    sh_link;                /* Link to another section */
  Elf64_Word    sh_info;                /* Additional section information */
  Elf64_Xword   sh_addralign;           /* Section alignment */
  Elf64_Xword   sh_entsize;             /* Entry size if section holds table */
} Elf64_Shdr;
typedef Elf64_Shdr GElf_Shdr;
/* Descriptor for data to be converted to or from memory format.  */
typedef struct
{
  void *d_buf;                  /* Pointer to the actual data.  */
  int d_type;                   /* Type of this piece of data.  */
  unsigned int d_version;       /* ELF version.  */
  size_t d_size;                /* Size in bytes.  */
  uint64_t d_off;               /* Offset into section.  */
  size_t d_align;               /* Alignment in section.  */
} Elf_Data;
/* Symbol table entry.  */
typedef struct
{
  Elf64_Word    st_name;                /* Symbol name (string tbl index) */
  unsigned char st_info;                /* Symbol type and binding */
  unsigned char st_other;               /* Symbol visibility */
  Elf64_Section st_shndx;               /* Section index */
  Elf64_Addr    st_value;               /* Symbol value */
  Elf64_Xword   st_size;                /* Symbol size */
} Elf64_Sym;
typedef Elf64_Sym GElf_Sym;

/* Coordinate ELF library and application versions.  */
unsigned int elf_version (unsigned int __version);
/* Return descriptor for ELF file to work according to CMD.  */
Elf *elf_begin (int __fildes, int __cmd, Elf *__ref);
/* Free resources allocated for ELF.  */
int elf_end (Elf *__elf);
/* Get the number of program headers in the ELF file.  If the file uses
   more headers than can be represented in the e_phnum field of the ELF
   header the information from the sh_info field in the zeroth section
   header is used.  */
int elf_getphdrnum (Elf *__elf, size_t *__dst);
/* Retrieve program header table entry.  */
GElf_Phdr *gelf_getphdr (Elf *__elf, int __ndx, GElf_Phdr *__dst);
/* Retrieve section header.  */
GElf_Shdr *gelf_getshdr (Elf_Scn *__scn, GElf_Shdr *__dst);
/* Retrieve symbol information from the symbol table at the given index.  */
GElf_Sym *gelf_getsym (Elf_Data *__data, int __ndx, GElf_Sym *__dst);
/* Get section with next section index.  */
Elf_Scn *elf_nextscn (Elf *__elf, Elf_Scn *__scn);
/* Get data from section while translating from file representation
   to memory representation.  */
Elf_Data *elf_getdata (Elf_Scn *__scn, Elf_Data *__data);
/* Return pointer to string at OFFSET in section INDEX.  */
char *elf_strptr (Elf *__elf, size_t __index, size_t __offset);
]]

local elf = ffi.load('elf')
local EV = { NONE=0, CURRENT=1, NUM=2 }
local PT = { NULL=0, LOAD=1, DYNAMIC=2, INTERP=3, NOTE=4, SHLIB=5, PHDR=6, TLS=7, NUM=8 }
local SHT = { NULL=0, PROGBITS=1, SYMTAB=2, STRTAB=3, RELA=4, HASH=5, DYNAMIC=6, NOTE=7,
              NOBITS=8, REL=9, SHLIB=10, DYNSYM=11, INIT_ARRAY=14, FINI_ARRAY=15, PREINIT_ARRAY=16,
              GROUP=17, SYMTAB_SHNDX=18, NUM=19 }
local ELF_C = ffi.new('struct Elf_Cmd')
local M = {}

-- Optional poor man's C++ demangler
local cpp_demangler = os.getenv('CPP_DEMANGLER')
if not cpp_demangler then
	for prefix in string.gmatch(os.getenv('PATH'), '[^;:]+') do
		if S.statfs(prefix..'/c++filt') then
			cpp_demangler = prefix..'/c++filt'
			break
		end
	end
end
local cpp_demangle = function (name) return name end
if cpp_demangler then
	cpp_demangle = function (name)
		local cmd = string.format('%s -p %s', cpp_demangler, name)
		local fp = assert(io.popen(cmd, 'r'))
		local output = fp:read('*all')
		fp:close()
		return output:match '^(.-)%s*$'
	end
end

-- Metatable for ELF object
ffi.metatype('struct Elf_object', {
	__gc = function (t) t:close() end,
	__index = {
		close = function (t)
			if t.elf ~= nil then
				elf.elf_end(t.elf)
				S.close(t.fd)
				t.elf = nil
			end
		end,
		-- Load library load address
		loadaddr = function(t)
			local phnum = ffi.new('size_t [1]')
			if elf.elf_getphdrnum(t.elf, phnum) == nil then
				return nil, 'cannot get phdrnum'
			end
			local header = ffi.new('GElf_Phdr [1]')
			for i = 0, tonumber(phnum[0])-1 do
				if elf.gelf_getphdr(t.elf, i, header) ~= nil
				   and header[0].p_type == PT.LOAD then
				   return header[0].p_vaddr
				end
			end
		end,
		-- Resolve symbol address
		resolve = function (t, k, pattern)
			local section = elf.elf_nextscn(t.elf, nil)
			while section ~= nil do
				local header = ffi.new('GElf_Shdr [1]')
				if elf.gelf_getshdr(section, header) ~= nil then
					if header[0].sh_type == SHT.SYMTAB or header[0].sh_type == SHT.DYNSYM then
						local data = elf.elf_getdata(section, nil)
						while data ~= nil do
							if data.d_size % header[0].sh_entsize > 0 then
								return nil, 'bad section header entity size'
							end
							local symcount = tonumber(data.d_size / header[0].sh_entsize)
							local sym = ffi.new('GElf_Sym [1]')
							for i = 0, symcount - 1 do
								if elf.gelf_getsym(data, i, sym) ~= nil then
									local name = elf.elf_strptr(t.elf, header[0].sh_link, sym[0].st_name)
									if name ~= nil then
										-- Demangle C++ symbols if necessary
										name = ffi.string(name)
										if name:sub(1,2) == '_Z' then
											name = cpp_demangle(name)
										end
										-- Match symbol name against pattern
										if pattern and string.match(name, k) or k == name then
											return sym[0]
										end
									end
								end
							end
							data = elf.elf_getdata(section, data)
						end
					end
				end
				section = elf.elf_nextscn(t.elf, section)
			end
		end,
	}
})

-- Open an ELF object
function M.open(path)
	if elf.elf_version(EV.CURRENT) == EV.NONE then
		return nil, 'bad version'
	end
	local fd, err = S.open(path, 'rdonly')
	if not fd then return nil, err end
	local pt = ffi.new('Elf *')
	pt = elf.elf_begin(fd:getfd(), ELF_C.READ, pt)
	if not pt then
		fd:close()
		return nil, 'cannot open elf object'
	end
	return ffi.new('struct Elf_object', fd:nogc():getfd(), pt)
end

return M