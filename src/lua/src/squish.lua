#!/usr/bin/env lua

local short_opts = { v = "verbose", vv = "very_verbose", o = "output", q = "quiet", qq = "very_quiet", g = "debug" }
local opts = { use_http = false };

for _, opt in ipairs(arg) do
	if opt:match("^%-") then
		local name = opt:match("^%-%-?([^%s=]+)()")
		name = (short_opts[name] or name):gsub("%-+", "_");
		if name:match("^no_") then
			name = name:sub(4, -1);
			opts[name] = false;
		else
			opts[name] = opt:match("=(.*)$") or true;
		end
	else
		base_path = opt;
	end
end

if opts.very_verbose then opts.verbose = true; end
if opts.very_quiet then opts.quiet = true; end

local noprint = function () end
local print_err, print_info, print_verbose, print_debug = noprint, noprint, noprint, noprint;

if not opts.very_quiet then print_err = print; end
if not opts.quiet then print_info = print; end
if opts.verbose or opts.very_verbose then print_verbose = print; end
if opts.very_verbose then print_debug = print; end

print = print_verbose;

local modules, main_files, resources = {}, {}, {};

--  Functions to be called from squishy file  --

function Module(name)
	if modules[name] then
		print_verbose("Ignoring duplicate module definition for "..name);
		return function () end
	end
	local i = #modules+1;
	modules[i] = { name = name, url = ___fetch_url };
	modules[name] = modules[i];
	return function (path)
		modules[i].path = path;
	end
end

function Resource(name, path)
	local i = #resources+1;
	resources[i] = { name = name, path = path or name };
	return function (path)
		resources[i].path = path;
	end
end

function AutoFetchURL(url)
	___fetch_url = url;
end

function Main(fn)
	table.insert(main_files, fn);
end

function Output(fn)
	if opts.output == nil then
		out_fn = fn;
	end
end

function Option(name)
	name = name:gsub("%-", "_");
	if opts[name] == nil then
		opts[name] = true;
		return function (value)
			opts[name] = value;
		end
	else
		return function () end;
	end
end

function GetOption(name)
	return opts[name:gsub('%-', '_')];
end

function Message(message)
	if not opts.quiet then
		print_info(message);
	end
end

function Error(message)
	if not opts.very_quiet then
		print_err(message);
	end
end

function Exit()
	os.exit(1);
end
-- -- -- -- -- -- -- --- -- -- -- -- -- -- -- --

base_path = (base_path or "."):gsub("/$", "").."/"
squishy_file = base_path .. "squishy";
out_fn = opts.output;

local ok, err = pcall(dofile, squishy_file);

if not ok then
	print_err("Couldn't read squishy file: "..err);
	os.exit(1);
end

if not out_fn then
	print_err("No output file specified by user or squishy file");
	os.exit(1);
elseif #main_files == 0 and #modules == 0 and #resources == 0 then
	print_err("No files, modules or resources. Not going to generate an empty file.");
	os.exit(1);
end

local fetch = {};
function fetch.filesystem(path)
	local f, err = io.open(path);
	if not f then return false, err; end

	local data = f:read("*a");
	f:close();

	return data;
end

if opts.use_http then
	function fetch.http(url)
		local http = require "socket.http";

		local body, status = http.request(url);
		if status == 200 then
			return body;
		end
		return false, "HTTP status code: "..tostring(status);
	end
else
	function fetch.http(url)
		return false, "Module not found. Re-squish with --use-http option to fetch it from "..url;
	end
end

print_info("Writing "..out_fn.."...");
local f, err = io.open(out_fn, "w+");
if not f then
	print_err("Couldn't open output file: "..tostring(err));
	os.exit(1);
end

if opts.executable then
	if opts.executable == true then
		f:write("#!/usr/bin/env lua\n");
	else
		f:write(opts.executable, "\n");
	end
end

if opts.debug then
	f:write(require_resource("squish.debug"));
end

print_verbose("Resolving modules...");
do
	local LUA_DIRSEP = package.config:sub(1,1);
	local LUA_PATH_MARK = package.config:sub(5,5);

	local package_path = package.path:gsub("[^;]+", function (path)
			if not path:match("^%"..LUA_DIRSEP) then
				return base_path..path;
			end
		end):gsub("/%./", "/");
	local package_cpath = package.cpath:gsub("[^;]+", function (path)
			if not path:match("^%"..LUA_DIRSEP) then
				return base_path..path;
			end
		end):gsub("/%./", "/");

	function resolve_module(name, path)
	        name = name:gsub("%.", LUA_DIRSEP);
	        for c in path:gmatch("[^;]+") do
	                c = c:gsub("%"..LUA_PATH_MARK, name);
	                print_debug("Looking for "..c)
	                local f = io.open(c);
	                if f then
				print_debug("Found!");
	                        f:close();
                        return c;
			end
		end
		return nil; -- not found
	end

	for i, module in ipairs(modules) do
		if not module.path then
			module.path = resolve_module(module.name, package_path);
			if not module.path then
				print_err("Couldn't resolve module: "..module.name);
			else
				-- Strip base_path from resolved path
				module.path = module.path:gsub("^"..base_path:gsub("%p", "%%%1"), "");
			end
		end
	end
end


print_verbose("Packing modules...");
for _, module in ipairs(modules) do
	local modulename, path = module.name, module.path;
	if module.path:sub(1,1) ~= "/" then
		path = base_path..module.path;
	end
	print_debug("Packing "..modulename.." ("..path..")...");
	local data, err = fetch.filesystem(path);
	if (not data) and module.url then
		print_debug("Fetching: ".. module.url:gsub("%?", module.path))
		data, err = fetch.http(module.url:gsub("%?", module.path));
	end
	if data then
		f:write("package.preload['", modulename, "'] = (function (...)\n");
		f:write(data);
		f:write(" end)\n");
		if opts.debug then
			f:write(string.format("package.preload[%q] = ___adjust_chunk(package.preload[%q], %q);\n\n",
				modulename, modulename, "@"..path));
		end
	else
		print_err("Couldn't pack module '"..modulename.."': "..(err or "unknown error... path to module file correct?"));
		os.exit(1);
	end
end

if #resources > 0 then
	print_verbose("Packing resources...")
	f:write("do local resources = {};\n");
	for _, resource in ipairs(resources) do
		local name, path = resource.name, resource.path;
		local res_file, err = io.open(base_path..path, "rb");
		if not res_file then
			print_err("Couldn't load resource: "..tostring(err));
			os.exit(1);
		end
		local data = res_file:read("*a");
		local maxequals = 0;
		data:gsub("(=+)", function (equals_string) maxequals = math.max(maxequals, #equals_string); end);

		f:write(("resources[%q] = %q"):format(name, data));
--[[		f:write(("resources[%q] = ["):format(name), string.rep("=", maxequals+1), "[");
		f:write(data);
		f:write("]", string.rep("=", maxequals+1), "];"); ]]
	end
	if opts.virtual_io then
		local vio = require_resource("vio");
		if not vio then
			print_err("Virtual IO requested but is not enabled in this build of squish");
		else
			-- Insert vio library
			f:write(vio, "\n")
			-- Override standard functions to use vio if opening a resource
			f:write[[local io_open, io_lines = io.open, io.lines; function io.open(fn, mode)
					if not resources[fn] then
						return io_open(fn, mode);
					else
						return vio.open(resources[fn]);
				end end
				function io.lines(fn)
					if not resources[fn] then
						return io_lines(fn);
					else
						return vio.open(resources[fn]):lines()
				end end
				local _dofile = dofile;
				function dofile(fn)
					if not resources[fn] then
						return _dofile(fn);
					else
						return assert(loadstring(resources[fn]))();
				end end
				local _loadfile = loadfile;
				function loadfile(fn)
					if not resources[fn] then
						return _loadfile(fn);
					else
						return loadstring(resources[fn], "@"..fn);
				end end ]]
		end
	end
	f:write[[function require_resource(name) return resources[name] or error("resource '"..tostring(name).."' not found"); end end ]]
end

print_debug("Finalising...")
for _, fn in pairs(main_files) do
	local fin, err = io.open(base_path..fn);
	if not fin then
		print_err("Failed to open "..fn..": "..err);
		os.exit(1);
	else
		f:write((fin:read("*a"):gsub("^#.-\n", "")));
		fin:close();
	end
end

f:close();

print_info("OK!");
