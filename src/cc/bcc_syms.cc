#include <vector>
#include <string>
#include <algorithm>
#include <unordered_map>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bcc_helpers.h"

class SymbolCache {
public:
	virtual void refresh() = 0;
	virtual bool resolve_addr(uint64_t addr, struct bcc_symbol *sym) = 0;
	virtual bool resolve_name(const char *name, uint64_t *addr) = 0;
};

class KSyms : SymbolCache {
	struct Symbol {
		Symbol(const char *name, uint64_t addr) :
			name(name), addr(addr) {}
		std::string name;
		uint64_t addr;

		bool operator<(const Symbol& rhs) const { return addr < rhs.addr; }
	};

	std::vector<Symbol> _syms;
	std::unordered_map<std::string, uint64_t> _sym_names;
	static void _add_symbol(const char *, uint64_t, void *);

public:
	virtual bool resolve_addr(uint64_t addr, struct bcc_symbol *sym);
	virtual bool resolve_name(const char *name, uint64_t *addr);
	virtual void refresh()
	{
		if (_syms.empty()) {
			bcc_procutils_each_ksym(_add_symbol, this);
			std::sort(_syms.begin(), _syms.end());
		}
	}
};

void KSyms::_add_symbol(const char *symname, uint64_t addr, void *p)
{
	KSyms *ks = static_cast<KSyms *>(p);
	ks->_syms.emplace_back(symname, addr);
}

bool KSyms::resolve_addr(uint64_t addr, struct bcc_symbol *sym)
{
	refresh();

	if (_syms.empty()) {
		sym->name = nullptr;
		sym->module = nullptr;
		sym->offset = 0x0;
		return false;
	}

	auto it = std::upper_bound(_syms.begin(), _syms.end(), Symbol("", addr)) - 1;
	sym->name = (*it).name.c_str();
	sym->module = "[kernel]";
	sym->offset = addr - (*it).addr;
	return true;
}

bool KSyms::resolve_name(const char *name, uint64_t *addr)
{
	refresh();

	if (_syms.size() != _sym_names.size()) {
		_sym_names.clear();
		for (Symbol &sym : _syms) {
			_sym_names[sym.name] = sym.addr;
		}
	}

	auto it = _sym_names.find(name);
	if (it == _sym_names.end())
		return false;

	*addr = it->second;
	return true;
}

class ProcStat {
	std::string _procfs;
	ino_t _inode;

	ino_t get_inode()
	{
		struct stat s;
		return (!stat(_procfs.c_str(), &s)) ? s.st_ino : -1;
	}

public:
	ProcStat(int pid) : _inode(-1)
	{
		char buffer[128];
		snprintf(buffer, sizeof(buffer), "/proc/%d/exe", pid);
		_procfs = buffer;
	}

	bool is_stale() { return _inode != get_inode(); }
	void reset() { _inode = get_inode(); }
};

static bool has_suffix(const std::string &str, const std::string &suffix)
{
	return str.size() >= suffix.size() &&
		str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

class ProcSyms : SymbolCache {
	struct Symbol {
		Symbol(const char *name, uint64_t start, uint64_t size, int flags = 0) :
			name(name), start(start), size(size), flags(flags) {}
		std::string name;
		uint64_t start;
		uint64_t size;
		int flags;
	};

	struct Module {
		Module(const char *name, uint64_t start, uint64_t end) :
			_name(name), _start(start), _end(end) {}
		std::string _name;
		uint64_t _start;
		uint64_t _end;
		std::vector<Symbol> _syms;

		void load_sym_table();
		bool decode_sym(uint64_t addr, struct bcc_symbol *sym);
		bool is_so() { return has_suffix(_name, ".so"); }

		static int _add_symbol(const char *symname,
				uint64_t start, uint64_t end, int flags, void *p);
	};

	int _pid;
	std::vector<Module> _modules;
	ProcStat _procstat;

	static void _add_module(const char *, uint64_t, uint64_t, void*);

public:
	ProcSyms(int pid);
	virtual void refresh();
	virtual bool resolve_addr(uint64_t addr, struct bcc_symbol *sym);
	virtual bool resolve_name(const char *name, uint64_t *addr);
};

ProcSyms::ProcSyms(int pid) : _pid(pid), _procstat(pid)
{
	refresh();
}

void ProcSyms::refresh()
{
	_modules.clear();
	bcc_procutils_each_module(_pid, _add_module, this);
	_procstat.reset();
}

void ProcSyms::_add_module(
	const char *modname, uint64_t start, uint64_t end, void *payload)
{
	ProcSyms *ps = static_cast<ProcSyms *>(payload);
	ps->_modules.emplace_back(modname, start, end);
}

bool ProcSyms::resolve_addr(uint64_t addr, struct bcc_symbol *sym)
{
	if (_procstat.is_stale())
		refresh();

	sym->module = nullptr;
	sym->name = nullptr;
	sym->offset = 0x0;

	for (Module &mod : _modules) {
		if (addr >= mod._start && addr <= mod._end)
			return mod.decode_sym(addr, sym);
	}
	return false;
}

bool ProcSyms::resolve_name(const char *name, uint64_t *addr)
{
	*addr = 0x0;
	return false;
}

int ProcSyms::Module::_add_symbol(const char *symname,
	uint64_t start, uint64_t end, int flags, void *p)
{
	Module *m = static_cast<Module *>(p);
	m->_syms.emplace_back(symname, start, end, flags);
	return 0;
}

void ProcSyms::Module::load_sym_table()
{
	if (_syms.size())
		return;

	bcc_elf_foreach_sym(_name.c_str(), _add_symbol, this);
}

bool ProcSyms::Module::decode_sym(uint64_t addr, struct bcc_symbol *sym)
{
	uint64_t offset = is_so() ? (addr - _start) : addr;

	load_sym_table();

	sym->module = _name.c_str();
	sym->offset = offset;

	for (Symbol &s : _syms) {
		if (offset >= s.start && offset <= (s.start + s.size)) {
			sym->name = s.name.c_str();
			sym->offset = (offset - s.start);
			return true;
		}
	}
	return false;
}

extern "C" {

void *bcc_symcache_new(int pid)
{
	if (pid < 0)
		return static_cast<void *>(new KSyms());
	return static_cast<void *>(new ProcSyms(pid));
}

int bcc_symcache_resolve(void *resolver, uint64_t addr, struct bcc_symbol *sym)
{
	SymbolCache *cache = static_cast<SymbolCache *>(resolver);
	return cache->resolve_addr(addr, sym) ? 0 : -1;
}

int bcc_symcache_resolve_name(void *resolver, const char *name, uint64_t *addr)
{
	SymbolCache *cache = static_cast<SymbolCache *>(resolver);
	return cache->resolve_name(name, addr) ? 0 : -1;
}

void bcc_symcache_refresh(void *resolver)
{
	SymbolCache *cache = static_cast<SymbolCache *>(resolver);
	cache->refresh();
}

}
