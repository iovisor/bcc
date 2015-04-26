import ctypes as ct
import os
import pyroute2 as pr

lib = ct.cdll.LoadLibrary("libbpfprog.so")

lib.bpf_program_create.restype = ct.c_void_p
lib.bpf_program_create.argtypes = [ct.c_char_p, ct.c_char_p, ct.c_uint]
lib.bpf_program_destroy.restype = None
lib.bpf_program_destroy.argtypes = [ct.c_void_p]
lib.bpf_program_start.restype = ct.c_void_p
lib.bpf_program_start.argtypes = [ct.c_void_p, ct.c_char_p]
lib.bpf_program_size.restype = ct.c_size_t
lib.bpf_program_size.argtypes = [ct.c_void_p, ct.c_char_p]
lib.bpf_program_license.restype = ct.c_char_p
lib.bpf_program_license.argtypes = [ct.c_void_p]
lib.bpf_program_table_fd.restype = ct.c_int
lib.bpf_program_table_fd.argtypes = [ct.c_void_p, ct.c_char_p]

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
        ct.c_char_p]

class BPF(object):
    BPF_PROG_TYPE_SOCKET_FILTER = 1
    BPF_PROG_TYPE_SCHED_CLS = 2
    BPF_PROG_TYPE_SCHED_ACT = 3
    def __init__(self, name, dp_file, dph_file,
            prog_type=BPF_PROG_TYPE_SOCKET_FILTER,
            debug=0):
        self.debug = debug
        self.name = name
        self.prog = lib.bpf_program_create(dp_file.encode("ascii"),
                dph_file.encode("ascii"), self.debug)

        if self.prog == ct.c_void_p(None):
            raise Exception("Failed to compile BPF program %s" % dp_file)

        if lib.bpf_program_start(self.prog,
                self.name.encode("ascii")) == ct.c_void_p(None):
            raise Exception("Unknown program %s" % self.name)

        self.fd = lib.bpf_prog_load(prog_type,
                lib.bpf_program_start(self.prog, self.name.encode("ascii")),
                lib.bpf_program_size(self.prog, self.name.encode("ascii")),
                lib.bpf_program_license(self.prog))

        if self.fd < 0:
            print((ct.c_char * 65536).in_dll(lib, "bpf_log_buf").value)
            #print(ct.c_char_p.in_dll(lib, "bpf_log_buf").value)
            raise Exception("Failed to load BPF program %s" % dp_file)

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

    def table(self, name, keytype, leaftype):
        map_fd = lib.bpf_program_table_fd(self.prog,
                ct.c_char_p(name.encode("ascii")))
        if map_fd < 0:
            raise Exception("Failed to find BPF Table %s" % name)
        return BPF.Table(self, map_fd, keytype, leaftype)

    def attach(self, dev):
        self.sock = lib.bpf_open_raw_sock(dev.encode("ascii"))
        if self.sock < 0:
            errstr = os.strerror(ct.get_errno())
            raise Exception("Failed to open raw device %s: %s" % (dev, errstr))
        res = lib.bpf_attach_socket(self.sock, self.fd)
        if res < 0:
            errstr = os.strerror(ct.get_errno())
            raise Exception("Failed to attach BPF to device %s: %s"
                    % (dev, errstr))

    def attach_filter(self, ifindex, prio, classid):
        res = lib.bpf_attach_filter(self.fd, self.name.encode("ascii"), ifindex, prio, classid)
        if res < 0:
            raise Exception("Failed to filter with BPF")


