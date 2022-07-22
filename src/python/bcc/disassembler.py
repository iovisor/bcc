# Copyright 2019 Clevernet
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from os import linesep
import ctypes as ct
from .table import get_table_type_name

class OffsetUnion(ct.Union):
    _fields_ = [('offsetu', ct.c_uint16), ('offset', ct.c_int16)]

class ImmUnion(ct.Union):
    _fields_ = [('immu', ct.c_uint32), ('imm', ct.c_int32)]

class BPFInstrFields(ct.Structure):
    _pack_ = 1
    _anonymous_ = ('o', 'i')
    _fields_ = [('opcode', ct.c_uint8),
                ('dst', ct.c_uint8, 4),
                ('src', ct.c_uint8, 4),
                ('o', OffsetUnion),
                ('i', ImmUnion)]

class BPFInstr(ct.Union):
    _pack_ = 1
    _anonymous_ = ('s')
    _fields_ = [('s', BPFInstrFields), ('instr', ct.c_uint64)]

class BPFDecoder():
    BPF_PSEUDO_CALL = 1
    bpf_helpers = ['unspec',
                   'map_lookup_elem',
                   'map_update_elem',
                   'map_delete_elem',
                   'probe_read',
                   'ktime_get_ns',
                   'trace_printk',
                   'get_prandom_u32',
                   'get_smp_processor_id',
                   'skb_store_bytes',
                   'l3_csum_replace',
                   'l4_csum_replace',
                   'tail_call',
                   'clone_redirect',
                   'get_current_pid_tgid',
                   'get_current_uid_gid',
                   'get_current_comm',
                   'get_cgroup_classid',
                   'skb_vlan_push',
                   'skb_vlan_pop',
                   'skb_get_tunnel_key',
                   'skb_set_tunnel_key',
                   'perf_event_read',
                   'redirect',
                   'get_route_realm',
                   'perf_event_output',
                   'skb_load_bytes',
                   'get_stackid',
                   'csum_diff',
                   'skb_get_tunnel_opt',
                   'skb_set_tunnel_opt',
                   'skb_change_proto',
                   'skb_change_type',
                   'skb_under_cgroup',
                   'get_hash_recalc',
                   'get_current_task',
                   'probe_write_user',
                   'current_task_under_cgroup',
                   'skb_change_tail',
                   'skb_pull_data',
                   'csum_update',
                   'set_hash_invalid',
                   'get_numa_node_id',
                   'skb_change_head',
                   'xdp_adjust_head',
                   'probe_read_str',
                   'get_socket_cookie',
                   'get_socket_uid',
                   'set_hash',
                   'setsockopt',
                   'skb_adjust_room',
                   'redirect_map',
                   'sk_redirect_map',
                   'sock_map_update',
                   'xdp_adjust_meta',
                   'perf_event_read_value',
                   'perf_prog_read_value',
                   'getsockopt',
                   'override_return',
                   'sock_ops_cb_flags_set',
                   'msg_redirect_map',
                   'msg_apply_bytes',
                   'msg_cork_bytes',
                   'msg_pull_data',
                   'bind',
                   'xdp_adjust_tail',
                   'skb_get_xfrm_state',
                   'get_stack',
                   'skb_load_bytes_relative',
                   'fib_lookup',
                   'sock_hash_update',
                   'msg_redirect_hash',
                   'sk_redirect_hash',
                   'lwt_push_encap',
                   'lwt_seg6_store_bytes',
                   'lwt_seg6_adjust_srh',
                   'lwt_seg6_action',
                   'rc_repeat',
                   'rc_keydown',
                   'skb_cgroup_id',
                   'get_current_cgroup_id',
                   'get_local_storage',
                   'sk_select_reuseport',
                   'skb_ancestor_cgroup_id',
                   'sk_lookup_tcp',
                   'sk_lookup_udp',
                   'sk_release',
                   'map_push_elem',
                   'map_pop_elem',
                   'map_peek_elem',
                   'msg_push_data',
                   'msg_pop_data',
                   'rc_pointer_rel']

    opcodes = {0x04: ('add32',    'dstimm',     '+=',     32),
               0x05: ('ja',       'joff',       None,     64),
               0x07: ('add',      'dstimm',     '+=',     64),
               0x0c: ('add32',    'dstsrc',     '+=',     32),
               0x0f: ('add',      'dstsrc',     '+=',     64),
               0x14: ('sub32',    'dstimm',     '-=',     32),
               0x15: ('jeq',      'jdstimmoff', '==',     64),
               0x17: ('sub',      'dstimm',     '-=',     64),
               0x18: ('lddw',     'lddw',       None,     64),
               0x1c: ('sub32',    'dstsrc',     '-=',     32),
               0x1d: ('jeq',      'jdstsrcoff', '==',     64),
               0x1f: ('sub',      'dstsrc',     '-=',     64),
               0x20: ('ldabsw',   'ldabs',      None,     32),
               0x24: ('mul32',    'dstimm',     '*=',     32),
               0x25: ('jgt',      'jdstimmoff', '>',      64),
               0x27: ('mul',      'dstimm',     '*=',     64),
               0x28: ('ldabsh',   'ldabs',      None,     16),
               0x2c: ('mul32',    'dstsrc',     '*=',     32),
               0x2d: ('jgt',      'jdstsrcoff', '>',      64),
               0x2f: ('mul',      'dstsrc',     '*=',     64),
               0x30: ('ldabsb',   'ldabs',      None,      8),
               0x34: ('div32',    'dstimm',     '/=',     32),
               0x35: ('jge',      'jdstimmoff', '>=',     64),
               0x37: ('div',      'dstimm',     '/=',     64),
               0x38: ('ldabsdw',  'ldabs',      None,     64),
               0x3c: ('div32',    'dstsrc',     '/=',     32),
               0x3d: ('jge',      'jdstsrcoff', '>=',     64),
               0x3f: ('div',      'dstsrc',     '/=',     64),
               0x40: ('ldindw',   'ldind',      None,     32),
               0x44: ('or32',     'dstimm_bw',  '|=',     32),
               0x45: ('jset',     'jdstimmoff', '&',      64),
               0x47: ('or',       'dstimm_bw',  '|=',     64),
               0x48: ('ldindh',   'ldind',      None,     16),
               0x4c: ('or32',     'dstsrc',     '|=',     32),
               0x4d: ('jset',     'jdstsrcoff', '&',      64),
               0x4f: ('or',       'dstsrc',     '|=',     64),
               0x50: ('ldindb',   'ldind',      None,      8),
               0x54: ('and32',    'dstimm_bw',  '&=',     32),
               0x55: ('jne',      'jdstimmoff', '!=',     64),
               0x57: ('and',      'dstimm_bw',  '&=',     64),
               0x58: ('ldinddw',  'ldind',      None,     64),
               0x5c: ('and32',    'dstsrc',     '&=',     32),
               0x5d: ('jne',      'jdstsrcoff', '!=',     64),
               0x5f: ('and',      'dstsrc',     '&=',     64),
               0x61: ('ldxw',     'ldstsrcoff', None,     32),
               0x62: ('stw',      'sdstoffimm', None,     32),
               0x63: ('stxw',     'sdstoffsrc', None,     32),
               0x64: ('lsh32',    'dstimm',     '<<=',    32),
               0x65: ('jsgt',     'jdstimmoff', 's>',     64),
               0x67: ('lsh',      'dstimm',     '<<=',    64),
               0x69: ('ldxh',     'ldstsrcoff', None,     16),
               0x6a: ('sth',      'sdstoffimm', None,     16),
               0x6b: ('stxh',     'sdstoffsrc', None,     16),
               0x6c: ('lsh32',    'dstsrc',     '<<=',    32),
               0x6d: ('jsgt',     'jdstsrcoff', 's>',     64),
               0x6f: ('lsh',      'dstsrc',     '<<=',    64),
               0x71: ('ldxb',     'ldstsrcoff', None,      8),
               0x72: ('stb',      'sdstoffimm', None,      8),
               0x73: ('stxb',     'sdstoffsrc', None,      8),
               0x74: ('rsh32',    'dstimm',     '>>=',    32),
               0x75: ('jsge',     'jdstimmoff', 's>=',    64),
               0x77: ('rsh',      'dstimm',     '>>=',    64),
               0x79: ('ldxdw',    'ldstsrcoff', None,     64),
               0x7a: ('stdw',     'sdstoffimm', None,     64),
               0x7b: ('stxdw',    'sdstoffsrc', None,     64),
               0x7c: ('rsh32',    'dstsrc',     '>>=',    32),
               0x7d: ('jsge',     'jdstsrcoff', 's>=',    64),
               0x7f: ('rsh',      'dstsrc',     '>>=',    64),
               0x84: ('neg32',    'dst',        '~',      32),
               0x85: ('call',     'call',       None,     64),
               0x87: ('neg',      'dst',        '~',      64),
               0x94: ('mod32',    'dstimm',     '%=',     32),
               0x95: ('exit',     'exit',       None,     64),
               0x97: ('mod',      'dstimm',     '%=',     64),
               0x9c: ('mod32',    'dstsrc',     '%=',     32),
               0x9f: ('mod',      'dstsrc',     '%=',     64),
               0xa4: ('xor32',    'dstimm_bw',  '^=',     32),
               0xa5: ('jlt',      'jdstimmoff', '<',      64),
               0xa7: ('xor',      'dstimm_bw',  '^=',     64),
               0xac: ('xor32',    'dstsrc',     '^=',     32),
               0xad: ('jlt',      'jdstsrcoff', '<',      64),
               0xaf: ('xor',      'dstsrc',     '^=',     64),
               0xb4: ('mov32',    'dstimm',     '=',      32),
               0xb5: ('jle',      'jdstimmoff', '<=',     64),
               0xb7: ('mov',      'dstimm',     '=',      64),
               0xbc: ('mov32',    'dstsrc',     '=',      32),
               0xbd: ('jle',      'jdstsrcoff', '<=',     64),
               0xbf: ('mov',      'dstsrc',     '=',      64),
               0xc4: ('arsh32',   'dstimm',     's>>=',   32),
               0xc5: ('jslt',     'jdstimmoff', 's<',     64),
               0xc7: ('arsh',     'dstimm',     's>>=',   64),
               0xcc: ('arsh32',   'dstsrc',     's>>=',   32),
               0xcd: ('jslt',     'jdstsrcoff', 's<',     64),
               0xcf: ('arsh',     'dstsrc',     's>>=',   64),
               0xd5: ('jsle',     'jdstimmoff', 's<=',    64),
               0xdc: ('endian32', 'dstsrc',     'endian', 32),
               0xdd: ('jsle',     'jdstimmoff', 's<=',    64),}

    @classmethod
    def decode(cls, i, w, w1):
        try:
            name, opclass, op, bits = cls.opcodes[w.opcode]
            if opclass == 'dstimm':
                return 'r%d %s %d' % (w.dst, op, w.imm), 0

            elif opclass == 'dstimm_bw':
                return 'r%d %s 0x%x' % (w.dst, op, w.immu), 0

            elif opclass == 'joff':
                return 'goto %s <%d>' % ('%+d' % (w.offset),
                                         i + w.offset + 1), 0

            elif opclass == 'dstsrc':
                return 'r%d %s r%d' % (w.dst, op, w.src), 0

            elif opclass == 'jdstimmoff':
                return 'if r%d %s %d goto pc%s <%d>' % (w.dst, op, w.imm,
                                                      '%+d' % (w.offset),
                                                      i + w.offset + 1), 0

            elif opclass == 'jdstsrcoff':
                return 'if r%d %s r%d goto pc%s <%d>' % (w.dst, op, w.src,
                                                       '%+d' % (w.offset),
                                                       i + w.offset + 1), 0

            elif opclass == 'lddw':
                # imm contains the file descriptor (FD) of the map being loaded;
                # the kernel will translate this into the proper address
                if w1 is None:
                    raise Exception("lddw requires two instructions to be disassembled")
                if w1.imm == 0:
                    return 'r%d = <map at fd #%d>' % (w.dst, w.imm), 1
                imm = (w1.imm << 32) | w.imm
                return 'r%d = 0x%x' % (w.dst, imm), 1

            elif opclass == 'ldabs':
                return 'r0 = *(u%s*)skb[%s]' % (bits, w.imm), 0

            elif opclass == 'ldind':
                return 'r0 = *(u%d*)skb[r%d %s]' % (bits, w.src,
                                                    '%+d' % (w.imm)), 0

            elif opclass == 'ldstsrcoff':
                return 'r%d = *(u%d*)(r%d %s)' % (w.dst, bits, w.src,
                                                  '%+d' % (w.offset)), 0

            elif opclass == 'sdstoffimm':
                return '*(u%d*)(r%d %s) = %d' % (bits, w.dst,
                                                 '%+d' % (w.offset), w.imm), 0

            elif opclass == 'sdstoffsrc':
                return '*(u%d*)(r%d %s) = r%d' % (bits, w.dst,
                                                  '%+d' % (w.offset), w.src), 0

            elif opclass == 'dst':
                return 'r%d = %s (u%s)r%d' % (w.dst, op, bits, w.dst), 0

            elif opclass == 'call':
                if w.src != cls.BPF_PSEUDO_CALL:
                    try:
                        return '%s bpf_%s#%d' % (name, cls.bpf_helpers[w.immu], w.immu), 0
                    except IndexError:
                        return '%s <unknown helper #%d>' % (op, w.immu), 0
                return '%s %s' % (name, '%+d' % (w.imm)), 0
            elif opclass == 'exit':
                return name, 0
            else:
                raise Exception('unknown opcode class')

        except KeyError:
            return 'unknown <0x%x>' % (w.opcode)

def disassemble_instruction(i, w0, w1=None):
    instr, skip = BPFDecoder.decode(i, w0, w1)
    return "%4d: (%02x) %s" % (i, w0.opcode, instr), skip

def disassemble_str(bpfstr):
    ptr = ct.cast(ct.c_char_p(bpfstr), ct.POINTER(BPFInstr))
    numinstr = int(len(bpfstr) / 8)
    w0 = ptr[0]
    skip = 0
    instr_list = []
    for i in range(1, numinstr):
        w1 = ptr[i]
        if skip:
            skip -= 1
            instr_str = "%4d:      (64-bit upper word)" % (i)
        else:
            instr_str, skip = disassemble_instruction(i - 1, w0, w1)
        instr_list.append(instr_str)
        w0 = w1
    instr_str, skip = disassemble_instruction(numinstr - 1, w0, None)
    instr_list.append(instr_str)
    return instr_list

def disassemble_prog(func_name, bpfstr):
    instr_list = ["Disassemble of BPF program %s:" % (func_name)]
    instr_list += disassemble_str(bpfstr)
    return linesep.join(instr_list)

class MapDecoder ():
    ctype2str = {ct.c_bool: u"_Bool",
                 ct.c_char: u"char",
                 ct.c_wchar: u"wchar_t",
                 ct.c_ubyte: u"unsigned char",
                 ct.c_short: u"short",
                 ct.c_ushort: u"unsigned short",
                 ct.c_int: u"int",
                 ct.c_uint: u"unsigned int",
                 ct.c_long: u"long",
                 ct.c_ulong: u"unsigned long",
                 ct.c_longlong: u"long long",
                 ct.c_ulonglong: u"unsigned long long",
                 ct.c_float: u"float",
                 ct.c_double: u"double",
                 ct.c_longdouble: u"long double",
                 ct.c_int64 * 2: u"__int128",
                 ct.c_uint64 * 2: u"unsigned __int128",}

    @classmethod
    def get_ct_name(cls, t):
        try:
            if issubclass(t, ct.Structure):
                field_type_name = "struct"
            elif issubclass(t, ct.Union):
                field_type_name = "union"
            elif issubclass(t, ct.Array):
                field_type_name = cls.ctype2str[t._type_] + "[" + str(t._length_) + "]"
            else:
                field_type_name = cls.ctype2str[t]
        except KeyError:
            field_type_name = str(t)
        return field_type_name

    @classmethod
    def format_size_info(cls, offset, size, enabled=False, bitoffset=None):
        if not enabled:
            return ""
        if bitoffset is not None:
            return "[%d,%d +%d bit]" % (offset, bitoffset, size)
        return "[%d +%d] " % (offset, size)

    @classmethod
    def print_ct_map(cls, t, indent="", offset=0, sizeinfo=False):
        map_lines = []
        try:
            for field_name, field_type in t._fields_:
                is_structured = (issubclass(field_type, ct.Structure) or
                                 issubclass(field_type, ct.Union))
                field_type_name = cls.get_ct_name(field_type)
                field_offset = getattr(t, field_name).offset
                field_size = ct.sizeof(field_type)
                sizedesc = cls.format_size_info(offset + field_offset,
                                                field_size, sizeinfo)
                if is_structured:
                    map_lines.append("%s%s%s {" % (indent, sizedesc, field_type_name))
                    map_lines += cls.print_ct_map(field_type,
                                                  indent + "  ",
                                                  offset + field_offset)
                    map_lines.append("%s} %s;" % (indent, field_name))
                else:
                    map_lines.append("%s%s%s %s;" % (indent, sizedesc,
                                                     field_type_name,
                                                     field_name))
        except ValueError:
            # is a bit field
            offset_bits = 0
            for field in t._fields_:
                if len(field) == 3:
                    field_name, field_type, field_bits = field
                    field_type_name = cls.get_ct_name(field_type)
                    sizedesc = cls.format_size_info(offset, offset_bits,
                                                    sizeinfo, field_bits)
                    map_lines.append("%s%s%s %s:%d;" % (indent, sizedesc,
                                                        field_type_name,
                                                        field_name,
                                                        field_bits))
                else:
                    # end of previous bit field
                    field_name, field_type = field
                    field_type_name = cls.get_ct_name(field_type)
                    field_offset = getattr(t, field_name).offset
                    field_size = ct.sizeof(field_type)
                    field_bits = 0
                    offset_bits = 0
                    sizedesc = cls.format_size_info(offset + field_offset,
                                                    field_size, sizeinfo)
                    map_lines.append("%s%s%s %s;" % (indent, sizedesc,
                                                     field_type_name,
                                                     field_name))
                    offset += field_offset
                offset_bits += field_bits
        return map_lines

    @classmethod
    def print_map_ctype(cls, t, field_name, sizeinfo):
        is_structured = (issubclass(t, ct.Structure) or
                         issubclass(t, ct.Union))
        type_name = cls.get_ct_name(t)
        if is_structured:
            map_lines = ["  %s {" % (type_name)]
            map_lines += cls.print_ct_map(t, "    ", sizeinfo=sizeinfo)
            map_lines.append("  } %s;" % (field_name))
        else:
            map_lines = ["  %s %s;" % (type_name, field_name)]
        return map_lines

    @classmethod
    def decode_map(cls, map_name, map_obj, map_type, sizeinfo=False):
        map_lines = ['Layout of BPF map %s (type %s, FD %d, ID %d):' % (map_name,
                                                                        map_type,
                                                                        map_obj.map_fd,
                                                                        map_obj.map_id)]
        map_lines += cls.print_map_ctype(map_obj.Key, 'key', sizeinfo=sizeinfo)
        map_lines += cls.print_map_ctype(map_obj.Leaf, 'value', sizeinfo=sizeinfo)
        return linesep.join(map_lines)

def decode_map(map_name, map_obj, map_type, sizeinfo=False):
    map_type_name = get_table_type_name(map_type)
    return MapDecoder.decode_map(map_name, map_obj, map_type_name, sizeinfo=sizeinfo)
