import ctypes as ct
import os

lib = ct.cdll.LoadLibrary("libbpfprog.so")

# keep in sync with bpf_common.h
lib.bpf_module_create.restype = ct.c_void_p
lib.bpf_module_create.argtypes = [ct.c_char_p, ct.c_char_p, ct.c_uint]
lib.bpf_module_create_from_string.restype = ct.c_void_p
lib.bpf_module_create_from_string.argtypes = [ct.c_char_p, ct.c_uint]
lib.bpf_module_destroy.restype = None
lib.bpf_module_destroy.argtypes = [ct.c_void_p]
lib.bpf_module_license.restype = ct.c_char_p
lib.bpf_module_license.argtypes = [ct.c_void_p]
lib.bpf_module_kern_version.restype = ct.c_uint
lib.bpf_module_kern_version.argtypes = [ct.c_void_p]
lib.bpf_function_start.restype = ct.c_void_p
lib.bpf_function_start.argtypes = [ct.c_void_p, ct.c_char_p]
lib.bpf_function_size.restype = ct.c_size_t
lib.bpf_function_size.argtypes = [ct.c_void_p, ct.c_char_p]
lib.bpf_table_fd.restype = ct.c_int
lib.bpf_table_fd.argtypes = [ct.c_void_p, ct.c_char_p]

# keep in sync with libbpf.h
lib.bpf_get_next_key.restype = ct.c_int
lib.bpf_get_next_key.argtypes = [ct.c_int, ct.c_void_p, ct.c_void_p]
lib.bpf_lookup_elem.restype = ct.c_int
lib.bpf_lookup_elem.argtypes = [ct.c_int, ct.c_void_p, ct.c_void_p]
lib.bpf_update_elem.restype = ct.c_int
lib.bpf_update_elem.argtypes = [ct.c_int, ct.c_void_p, ct.c_void_p,
        ct.c_ulonglong]
lib.bpf_delete_elem.restype = ct.c_int
lib.bpf_delete_elem.argtypes = [ct.c_int, ct.c_void_p]
lib.bpf_open_raw_sock.restype = ct.c_int
lib.bpf_open_raw_sock.argtypes = [ct.c_char_p]
lib.bpf_attach_socket.restype = ct.c_int
lib.bpf_attach_socket.argtypes = [ct.c_int, ct.c_int]
lib.bpf_attach_filter.restype = ct.c_int
lib.bpf_attach_filter.argtypes = [ct.c_int, ct.c_char_p, ct.c_uint, ct.c_ubyte, ct.c_uint]
lib.bpf_prog_load.restype = ct.c_int
lib.bpf_prog_load.argtypes = [ct.c_int, ct.c_void_p, ct.c_size_t,
        ct.c_char_p, ct.c_uint]
lib.bpf_attach_kprobe.restype = ct.c_int
lib.bpf_attach_kprobe.argtypes = [ct.c_int, ct.c_char_p, ct.c_char_p, ct.c_int, ct.c_int, ct.c_int]

class BPF(object):
    SOCKET_FILTER = 1
    KPROBE = 2
    SCHED_CLS = 3
    SCHED_ACT = 4

    class Function(object):
        def __init__(self, bpf, name, fd):
            self.bpf = bpf
            self.name = name
            self.fd = fd

    class Table(object):
        def __init__(self, bpf, map_fd, keytype, leaftype):
            self.bpf = bpf
            self.map_fd = map_fd
            self.keytype = keytype
            self.leaftype = leaftype

        def get(self, key):
            key_p = ct.pointer(key)
            leaf = self.leaftype()
            leaf_p = ct.pointer(leaf)
            res = lib.bpf_lookup_elem(self.map_fd,
                    ct.cast(key_p, ct.c_void_p),
                    ct.cast(leaf_p, ct.c_void_p))
            if res < 0:
                raise Exception("Could not lookup in table")
            return leaf

        def put(self, key, leaf, flags=0):
            key_p = ct.pointer(key)
            leaf_p = ct.pointer(leaf)
            res = lib.bpf_update_elem(self.map_fd,
                    ct.cast(key_p, ct.c_void_p),
                    ct.cast(leaf_p, ct.c_void_p), flags)
            if res < 0:
                raise Exception("Could not update table")

        class Iter(object):
            def __init__(self, table, keytype):
                self.keytype = keytype
                self.table = table
                self.key = keytype()
            def __iter__(self):
                return self
            def __next__(self):
                return self.next()
            def next(self):
                self.key = self.table.next(self.key)
                return self.key

        def iter(self):
            return BPF.Table.Iter(self, self.keytype)

        def next(self, key):
            next_key = self.keytype()
            next_key_p = ct.pointer(next_key)
            key_p = ct.pointer(key)
            res = lib.bpf_get_next_key(self.map_fd,
                    ct.cast(key_p, ct.c_void_p),
                    ct.cast(next_key_p, ct.c_void_p))
            if res < 0:
                raise StopIteration()
            return next_key

    def __init__(self, dp_file="", dph_file="", text=None, debug=0):
        self.debug = debug
        self.funcs = {}
        if text:
            self.module = lib.bpf_module_create_from_string(text.encode("ascii"), self.debug)
        else:
            self.module = lib.bpf_module_create(dp_file.encode("ascii"),
                    dph_file.encode("ascii"), self.debug)

        if self.module == None:
            raise Exception("Failed to compile BPF module %s" % dp_file)

    def load_func(self, func_name, prog_type):
        if lib.bpf_function_start(self.module, func_name.encode("ascii")) == None:
            raise Exception("Unknown program %s" % func_name)

        fd = lib.bpf_prog_load(prog_type,
                lib.bpf_function_start(self.module, func_name.encode("ascii")),
                lib.bpf_function_size(self.module, func_name.encode("ascii")),
                lib.bpf_module_license(self.module),
                lib.bpf_module_kern_version(self.module))

        if fd < 0:
            print((ct.c_char * 65536).in_dll(lib, "bpf_log_buf").value)
            #print(ct.c_char_p.in_dll(lib, "bpf_log_buf").value)
            raise Exception("Failed to load BPF program %s" % func_name)

        fn = BPF.Function(self, func_name, fd)
        self.funcs[func_name] = fn

        return fn

    def get_table(self, name, keytype, leaftype):
        map_fd = lib.bpf_table_fd(self.module,
                ct.c_char_p(name.encode("ascii")))
        if map_fd < 0:
            raise Exception("Failed to find BPF Table %s" % name)
        return BPF.Table(self, map_fd, keytype, leaftype)

    @staticmethod
    def attach_socket(fn, dev):
        if not isinstance(fn, BPF.Function):
            raise Exception("arg 1 must be of type BPF.Function")
        sock = lib.bpf_open_raw_sock(dev.encode("ascii"))
        if sock < 0:
            errstr = os.strerror(ct.get_errno())
            raise Exception("Failed to open raw device %s: %s" % (dev, errstr))
        res = lib.bpf_attach_socket(sock, fn.fd)
        if res < 0:
            errstr = os.strerror(ct.get_errno())
            raise Exception("Failed to attach BPF to device %s: %s"
                    % (dev, errstr))
        fn.sock = sock

    @staticmethod
    def attach_classifier(fn, ifname, prio=10, classid=1):
        with open("/sys/class/net/%s/ifindex" % ifname) as f:
            ifindex = int(f.read())
        if not isinstance(fn, BPF.Function):
            raise Exception("arg 1 must be of type BPF.Function")
        res = lib.bpf_attach_filter(fn.fd, fn.name, ifindex, prio, classid)
        if res < 0:
            raise Exception("Failed to filter with BPF")

    @staticmethod
    def attach_kprobe(fn, event, pid=-1, cpu=0, group_fd=-1):
        if not isinstance(fn, BPF.Function):
            raise Exception("arg 1 must be of type BPF.Function")
        ev_name = "p_" + event.replace("+", "_")
        desc = "p:kprobes/%s %s" % (ev_name, event)
        res = lib.bpf_attach_kprobe(fn.fd, ev_name.encode("ascii"),
                desc.encode("ascii"), pid, cpu, group_fd)
        if res < 0:
            raise Exception("Failed to attach BPF to kprobe")
        return res

    @staticmethod
    def attach_kretprobe(fn, event, pid=-1, cpu=0, group_fd=-1):
        if not isinstance(fn, BPF.Function):
            raise Exception("arg 1 must be of type BPF.Function")
        ev_name = "r_" + event.replace("+", "_")
        desc = "r:kprobes/%s %s" % (ev_name, event)
        res = lib.bpf_attach_kprobe(fn.fd, ev_name.encode("ascii"),
                desc.encode("ascii"), pid, cpu, group_fd)
        if res < 0:
            raise Exception("Failed to attach BPF to kprobe")
        return res

