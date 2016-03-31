#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

static lua_State *globalL = NULL;
static const char *progname = NULL;

static void lstop (lua_State *L, lua_Debug *ar)
{
	(void)ar;  /* unused arg. */
	lua_sethook(L, NULL, 0, 0);
	luaL_error(L, "interrupted!");
}

static void laction (int i)
{
	signal(i, SIG_DFL);
	lua_sethook(globalL, lstop, LUA_MASKCALL | LUA_MASKRET | LUA_MASKCOUNT, 1);
}

static void l_message (const char *pname, const char *msg)
{
	if (pname) fprintf(stderr, "%s: ", pname);
	fprintf(stderr, "%s\n", msg);
	fflush(stderr);
}

static int report(lua_State *L, int status)
{
	if (status && !lua_isnil(L, -1)) {
		const char *msg = lua_tostring(L, -1);
		if (msg == NULL) msg = "(error object is not a string)";
		l_message(progname, msg);
		lua_pop(L, 1);
	}
	return status;
}

static int traceback (lua_State *L)
{
	if (!lua_isstring(L, 1))  /* 'message' not a string? */
		return 1;  /* keep it intact */
	lua_getfield(L, LUA_GLOBALSINDEX, "debug");
	if (!lua_istable(L, -1)) {
		lua_pop(L, 1);
		return 1;
	}
	lua_getfield(L, -1, "traceback");
	if (!lua_isfunction(L, -1)) {
		lua_pop(L, 2);
		return 1;
	}
	lua_pushvalue(L, 1);  /* pass error message */
	lua_pushinteger(L, 2);  /* skip this function and traceback */
	lua_call(L, 2, 1);  /* call debug.traceback */
	return 1;
}

static int docall (lua_State *L, int narg, int clear)
{
	int status;
	int base = lua_gettop(L) - narg;  /* function index */
	lua_pushcfunction(L, traceback);  /* push traceback function */
	lua_insert(L, base);  /* put it under chunk and args */
	signal(SIGINT, laction);
	status = lua_pcall(L, narg, (clear ? 0 : LUA_MULTRET), base);
	signal(SIGINT, SIG_DFL);
	lua_remove(L, base);  /* remove traceback function */
	/* force a complete garbage collection in case of errors */
	if (status != 0) lua_gc(L, LUA_GCCOLLECT, 0);
	return status;
}

static int dolibrary (lua_State *L, const char *name, int clear)
{
	lua_getglobal(L, "require");
	lua_pushstring(L, name);
	return report(L, docall(L, 1, clear));
}

struct Smain {
	int argc;
	char **argv;
	int status;
};

static void pushargv(lua_State *L, char **argv, int argc, int offset)
{
	int i, j;
	lua_createtable(L, argc, 0);
	for (i = offset, j = 1; i < argc; i++, j++) {
		lua_pushstring(L, argv[i]);
		lua_rawseti(L, -2, j);
	}
}

static int find_libbcc(lua_State *L)
{
	const char *libbcc = getenv("LIBBCC_SO_PATH");
	char buffer[4096];

	if (libbcc == NULL) {
		char *dirname;

		if (readlink("/proc/self/exe", buffer, sizeof(buffer)) < 0)
			return -1;

		dirname = strrchr(buffer, '/');
		if (dirname == NULL)
			return -1;

		strcpy(dirname + 1, "libbcc.so");
		libbcc = buffer;
	}

	if (access(libbcc, F_OK|R_OK|X_OK) != 0)
		return -1;

	lua_pushstring(L, libbcc);
	lua_setglobal(L, "LIBBCC_SO_PATH");
	return 0;
}

static int pmain(lua_State *L)
{
	struct Smain *s = (struct Smain *)lua_touserdata(L, 1);
	globalL = L;

	lua_gc(L, LUA_GCSTOP, 0);
	luaL_openlibs(L);
	lua_gc(L, LUA_GCRESTART, 0);

	if (find_libbcc(L) < 0) {
		s->status = 1;
		l_message(progname, "failed to find libbcc.so");
		return 0;
	}

	s->status = dolibrary(L, "bcc", 0);
	if (s->status)
		return 0;

	lua_pushboolean(L, 1);
	lua_setglobal(L, "BCC_STANDALONE");

	pushargv(L, s->argv, s->argc, 1);
	lua_setglobal(L, "arg");

	s->status = report(L, docall(L, 0, 1));
	return 0;
}

int main (int argc, char **argv)
{
	int status;
	struct Smain s;
	lua_State *L = lua_open();  /* create state */

	if (L == NULL) {
		l_message(argv[0], "cannot create state: not enough memory");
		return EXIT_FAILURE;
	}

	if (argc < 2) {
		fprintf(stderr, "usage: %s path_to_probe.lua [...]\n", argv[0]);
		return EXIT_FAILURE;
	}

	progname = argv[0];

	s.argc = argc;
	s.argv = argv;
	s.status = 0;

	status = lua_cpcall(L, &pmain, &s);
	report(L, status);
	lua_close(L);

	return (status || s.status) ? EXIT_FAILURE : EXIT_SUCCESS;
}
