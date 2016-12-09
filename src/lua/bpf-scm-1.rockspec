package = "bpf"
version = "scm-1"
source = {
   url = "git://github.com/iovisor/bcc.git"
}
description = {
   summary = "BCC - LuaJIT to BPF compiler.",
   detailed = [[
   ]],
   homepage = "https://github.com/iovisor/bcc",
   license = "BSD"
}
dependencies = {
   "lua >= 5.1",
   "ljsyscall >= 0.12",
}
external_dependencies = {
    LIBELF = {
       library = "elf"
    }
}
build = {
  type = "builtin",
  install = {
    bin = {
    }
  },
  modules = {
    bpf = "src/lua/bpf/bpf.lua",
    ["bpf.builtins"] = "src/lua/bpf/builtins.lua",
    ["bpf.cdef"] = "src/lua/bpf/cdef.lua",
    ["bpf.elf"] = "src/lua/bpf/elf.lua",
    ["bpf.init"] = "src/lua/bpf/init.lua",
    ["bpf.ljbytecode"] = "src/lua/bpf/ljbytecode.lua",
    ["bpf.proto"] = "src/lua/bpf/proto.lua",
  }
}
