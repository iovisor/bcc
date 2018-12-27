#!/usr/bin/env bcc-lua
--[[
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

18-Mar-2017  Simon Liu Created this.
--]]

local ffi = require("ffi")
local bit = require("bit")

ffi.cdef[[
const char *inet_ntop(int af, const void *src, char *dst, int size);
uint16_t ntohs(uint16_t netshort);
]]

local program = [[
#include <uapi/linux/ptrace.h>
#define KBUILD_MODNAME "foo"
#include <linux/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(birth, struct sock *, u64);

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    // XXX: switch some to u32's when supported
    u64 ts_us;
    u64 pid;
    u64 saddr;
    u64 daddr;
    u64 ports;
    u64 rx_b;
    u64 tx_b;
    u64 span_us;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u64 ts_us;
    u64 pid;
    u64 saddr[2];
    u64 daddr[2];
    u64 ports;
    u64 rx_b;
    u64 tx_b;
    u64 span_us;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_events);

struct id_t {
    u32 pid;
    char task[TASK_COMM_LEN];
};
BPF_HASH(whoami, struct sock *, struct id_t);

int trace_tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state)
{
    bpf_trace_printk("tcp_set_stat");
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // lport is either used in a filter here, or later
    u16 lport = sk->__sk_common.skc_num;
    FILTER_LPORT

    // dport is either used in a filter here, or later
    u16 dport = sk->__sk_common.skc_dport;
    FILTER_DPORT

    /*
     * This tool includes PID and comm context. It's best effort, and may
     * be wrong in some situations. It currently works like this:
     * - record timestamp on any state < TCP_FIN_WAIT1
     * - cache task context on:
     *       TCP_SYN_SENT: tracing from client
     *       TCP_LAST_ACK: client-closed from server
     * - do output on TCP_CLOSE:
     *       fetch task context if cached, or use current task
     */

    // capture birth time
    if (state < TCP_FIN_WAIT1) {
        /*
         * Matching just ESTABLISHED may be sufficient, provided no code-path
         * sets ESTABLISHED without a tcp_set_state() call. Until we know
         * that for sure, match all early states to increase chances a
         * timestamp is set.
         * Note that this needs to be set before the PID filter later on,
         * since the PID isn't reliable for these early stages, so we must
         * save all timestamps and do the PID filter later when we can.
         */
        u64 ts = bpf_ktime_get_ns();
        birth.update(&sk, &ts);
    }

    // record PID & comm on SYN_SENT
    if (state == TCP_SYN_SENT || state == TCP_LAST_ACK) {
        // now we can PID filter, both here and a little later on for CLOSE
        FILTER_PID
        struct id_t me = {.pid = pid};
        bpf_get_current_comm(&me.task, sizeof(me.task));
        whoami.update(&sk, &me);
    }

    if (state != TCP_CLOSE)
        return 0;

    // calculate lifespan
    u64 *tsp, delta_us;
    tsp = birth.lookup(&sk);
    if (tsp == 0) {
        whoami.delete(&sk);     // may not exist
        return 0;               // missed create
    }
    delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
    birth.delete(&sk);

    // fetch possible cached data, and filter
    struct id_t *mep;
    mep = whoami.lookup(&sk);
    if (mep != 0)
        pid = mep->pid;
    FILTER_PID

    // get throughput stats. see tcp_get_info().
    u64 rx_b = 0, tx_b = 0, sport = 0;
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    rx_b = tp->bytes_received;
    tx_b = tp->bytes_acked;

    u16 family = sk->__sk_common.skc_family;

    if (family == AF_INET) {
        struct ipv4_data_t data4 = {.span_us = delta_us,
            .rx_b = rx_b, .tx_b = tx_b};
        data4.ts_us = bpf_ktime_get_ns() / 1000;
        data4.saddr = sk->__sk_common.skc_rcv_saddr;
        data4.daddr = sk->__sk_common.skc_daddr;
        // a workaround until data4 compiles with separate lport/dport
        data4.pid = pid;
        data4.ports = ntohs(dport) + ((0ULL + lport) << 32);
        if (mep == 0) {
            bpf_get_current_comm(&data4.task, sizeof(data4.task));
        } else {
            bpf_probe_read(&data4.task, sizeof(data4.task), (void *)mep->task);
        }
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));

    } else /* 6 */ {
        struct ipv6_data_t data6 = {.span_us = delta_us,
            .rx_b = rx_b, .tx_b = tx_b};
        data6.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
            sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
            sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        // a workaround until data6 compiles with separate lport/dport
        data6.ports = ntohs(dport) + ((0ULL + lport) << 32);
        data6.pid = pid;
        if (mep == 0) {
            bpf_get_current_comm(&data6.task, sizeof(data6.task));
        } else {
            bpf_probe_read(&data6.task, sizeof(data6.task), (void *)mep->task);
        }
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }

    if (mep != 0)
        whoami.delete(&sk);

    return 0;
}
]]

local debug = false
local start_ts = 0

local inet_addresslen = #"255.255.255.255"
local inet6_addresslen = #"ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"
local AF_INET = 2
local AF_INET6 = 10

local header_string = "%-5s %-10.10s %s%-15s %-5s %-15s %-5s %5s %5s %s"
local format_string = "%-5d %-10.10s %s%-15s %-5d %-15s %-5d %5d %5d %.2f"
local ip_string = ""
local ip_version = false
local arg_timestamp = false
local arg_csv = false
local arg_time = false

local examples = [[examples:
    ./tcplife           # trace all TCP connect()s
    ./tcplife -t        # include time column (HH:MM:SS)
    ./tcplife -w        # wider colums (fit IPv6)
    ./tcplife -stT      # csv output, with times & timestamps
    ./tcplife -p 181    # only trace PID 181
    ./tcplife -L 80     # only trace local port 80
    ./tcplife -L 80,81  # only trace local ports 80 and 81
    ./tcplife -D 80     # only trace remote port 80
]]

local function split(str,sep)
   local t = {}
   for w in string.gmatch(str, '([^,]+)') do
      table.insert(t, w)
   end
   return t
end

local function inet_ntop(af, addr, len)
   local addr_dst = ffi.new("char[?]", len)
   local addr_src
   if af == AF_INET then
      addr_src = ffi.new("uint64_t[1]", addr)
   else
      addr_src = ffi.new("uint64_t[2]", addr)
   end
   ffi.C.inet_ntop(af, addr_src, addr_dst, len)
   return ffi.string(addr_dst, len)
end

local function inet_ntohs(port)
   local p = tonumber(port)
   return ffi.C.ntohs(p)
end

local function print_ipv4_event(cpu, event)

   local event_pid = tonumber(event.pid)
   local event_task = ffi.string(event.task)
   local event_ports = tonumber(event.ports)
   local event_tx_b = tonumber(event.tx_b)
   local event_rx_b = tonumber(event.rx_b)
   local event_span_us = tonumber(event.span_us)
   local event_ts_us = tonumber(event.ts_us)
   local event_saddr = inet_ntop(AF_INET, tonumber(event.saddr), inet_addresslen)
   local event_daddr = inet_ntop(AF_INET, tonumber(event.daddr), inet_addresslen)
   if arg_time then
      if arg_csv then
         io.write("%s," % os.date("%H:%M:%S"))
      else
         io.write("%-8s " % os.date("%H:%M:%S"))
      end
   end
   if arg_timestamp then
      if start_ts == 0 then
         start_ts = event_ts_us
      end
      local delta_s = (event_ts_us - start_ts) / 1000000
      if arg.csv then
         io.write("%.6f," % delta_s)
      else
         io.write("%-9.6f " % delta_s)
      end
   end
   local iv = ""
   if ip_version then
      iv = "4"
   end
   print(string.format(format_string, event_pid, event_task, iv,
                       event_saddr, bit.rshift(event_ports,32),
                       event_daddr, bit.band(event_ports,0xffffffff),
                       (event_tx_b / 1024), (event_rx_b / 1024), event_span_us/ 1000))
end


local function print_ipv6_event(cpu, event)
   local event_pid = tonumber(event.pid)
   local event_task = ffi.string(event.task)
   local event_ports = tonumber(event.ports)
   local event_tx_b = tonumber(event.tx_b)
   local event_rx_b = tonumber(event.rx_b)
   local event_span_us = tonumber(event.span_us)
   local event_ts_us = tonumber(event.ts_us)
   local event_saddr = inet_ntop(AF_INET6, {tonumber(event.saddr[0]), tonumber(event.saddr[1])}, inet6_addresslen)
   local event_daddr = inet_ntop(AF_INET6, {tonumber(event.daddr[0]), tonumber(event.daddr[1])}, inet6_addresslen)
   if arg_time then
      if arg_csv then
         io.write("%s," % os.date("%H:%M:%S"))
      else
         io.write("%-8s " % os.date("%H:%M:%S"))
      end
   end
   if arg_timestamp then
      if start_ts == 0 then
         start_ts = event_ts_us
      end
      local delta_s = (event_ts_us - start_ts) / 1000000
      if arg.csv then
         io.write("%.6f," % delta_s)
      else
         io.write("%-9.6f " % delta_s)
      end
   end
   local iv = ""
   if ip_version then
      iv = "6"
   end
   print(string.format(format_string, event_pid, event_task, iv,
                       event_saddr, bit.rshift(event_ports,32),
                       event_daddr, bit.band(event_ports,0xffffffff),
                       (event_tx_b / 1024), (event_rx_b / 1024), event_span_us/ 1000))
end

local function parse_arg(utils)
   local parser = utils.argparse("tcplife",
                                 "Trace the lifespan of TCP sessions and summarize", examples)

   parser:flag("-T --time", "include time column on output (HH:MM:SS)")
   parser:flag("-t --timestamp", "include timestamp on output (seconds)")
   parser:flag("-w --wide", "wide column output (fits IPv6 addresses)")
   parser:flag("-s --csv", "comma separated values output")
   parser:option("-p --pid", "trace this PID only"):convert(tonumber)
   parser:option("-L --localport", "comma-separated list of local ports to trace.")
   parser:option("-D --remoteport", "comma-separated list of remote ports to trace.")

   local args = parser:parse()
   if args.pid then
      local filter = 'if (pid != %d) { return 0; }' % args.pid
      program = program.gsub('FILTER_PID', filter)
   end

   if args.remoteport then
      local dports = split(args.remoteport, ",")
      local dports_if = ""
      for i,d in ipairs(dports) do
         if dports_if == "" then
            dports_if = 'dport != %d' % inet_ntohs(d)
         else
            dports_if = dports_if .. ' && ' .. ('dport != %d' % inet_ntohs(d))
         end
      end
      local filter = "if (%s) { birth.delete(&sk); return 0; }" % dports_if
      program = program:gsub('FILTER_DPORT', filter)
   end
   if args.localport then
      local lports = split(args.localport,",")
      local lports_if = ""
      for i,l in ipairs(lports) do
         if lports_if == "" then
            lports_if = 'lport != %d' % inet_ntohs(l)
         else
            lports_if = lports_if .. ' && ' .. ('lport != %d' % inet_ntohs(l))
         end
      end
      local filter = "if (%s) { birth.delete(&sk); return 0; }" % lports_if
      program = program:gsub('FILTER_LPORT', filter)
   end
   program = program:gsub('FILTER_PID', '')
   program = program:gsub('FILTER_DPORT', '')
   program = program:gsub('FILTER_LPORT', '')

   if args.wide then
      header_string = "%-5s %-16.16s %-2s %-26s %-5s %-26s %-5s %6s %6s %s"
      format_string = "%-5d %-16.16s %-2s %-26s %-5s %-26s %-5d %6d %6d %.2f"
      ip_string = "IP"
      ip_version = true
   end
   if args.csv then
      header_string = "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s"
      format_string = "%d,%s,%s,%s,%s,%s,%d,%d,%d,%.2f"
      ip_string = "IP"
      ip_version = true
      arg_csv = true
   end

   if args.time then
      arg_time = true
      if args.csv then
         io.write("%s," % ("TIME"))
      else
         io.write("%-8s " % ("TIME"))
      end
   end

   if args.timestamp then
      arg_timestamp = true
      if args.csv then
         io.write("%s," % ("TIME(s)"))
      else
         io.write("%-9s " % ("TIME(s)"))
      end
   end

end

return function(BPF, utils)
   parse_arg(utils)
   if debug then
      print(program)
   end

   local bpf = BPF:new{text=program}
   bpf:attach_kprobe{event="tcp_set_state", fn_name="trace_tcp_set_state"}
   print(header_string % {"PID", "COMM",
                          ip_string, "LADDR",
                          "LPORT", "RADDR", "RPORT", "TX_KB", "RX_KB", "MS"})
   local TASK_COMM_LEN = 16 -- linux/sched.h
   bpf:get_table("ipv4_events"):open_perf_buffer(print_ipv4_event, [[
    struct {
      uint64_t ts_us;
      uint64_t pid;
      uint64_t saddr;
      uint64_t daddr;
      uint64_t ports;
      uint64_t rx_b;
      uint64_t tx_b;
      uint64_t span_us;
      char task[$];
    }
   ]], {TASK_COMM_LEN}, 64)
   bpf:get_table("ipv6_events"):open_perf_buffer(print_ipv6_event, [[
    struct {
      uint64_t ts_us;
      uint64_t pid;
      uint64_t saddr[2];
      uint64_t daddr[2];
      uint64_t ports;
      uint64_t rx_b;
      uint64_t tx_b;
      uint64_t span_us;
      char task[$];
    }
   ]], {TASK_COMM_LEN}, 64)

   bpf:perf_buffer_poll_loop()
end
