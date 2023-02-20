#!/usr/bin/python
# author: https://github.com/agentzex
# Licensed under the Apache License, Version 2.0 (the "License")

# tcp_mon_block.py - uses netlink TC, kernel tracepoints and kprobes to monitor outgoing connections from given PIDs
# and block connections to all addresses initiated from them (acting like an in-process firewall), unless they are listed in allow_list

# outputs blocked connections attempts from monitored processes
# Usage:
#   python3 tcp_mon_block.py -i network_interface_name
#   python3 tcp_mon_block.py -v -i network_interface_name (-v --verbose - will output all connections attempts, including allowed ones)
#


from bcc import BPF
import pyroute2
import socket
import struct
import json
import argparse
from urllib.parse import urlparse


# TCP flags
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


verbose_states = {
    1: "Connection not allowed detected - forwarding to block",
    2: "Connection allowed",
    3: "Connection destroyed",
}


def get_verbose_message(state):
    if state not in verbose_states:
        return ""

    return verbose_states[state]


def parse_tcp_flags(flags):
    found_flags = ""
    if flags & FIN:
        found_flags += "FIN; "
    if flags & SYN:
        found_flags += "SYN; "
    if flags & RST:
        found_flags += "RST; "
    if flags & PSH:
        found_flags += "PSH; "
    if flags & ACK:
        found_flags += "ACK; "
    if flags & URG:
        found_flags += "URG; "
    if flags & ECE:
        found_flags += "ECE; "
    if flags & CWR:
        found_flags += "CWR;"

    return found_flags


def ip_to_network_address(ip):
    return struct.unpack("I", socket.inet_aton(ip))[0]


def network_address_to_ip(ip):
    return socket.inet_ntop(socket.AF_INET, struct.pack("I", ip))


def parse_address(url_or_ip):
    is_ipv4 = True
    domain = ""

    #first check if valid ipv4
    try:
        socket.inet_aton(url_or_ip)
    except socket.error:
        is_ipv4 = False

    if is_ipv4:
        return [url_or_ip]

    # if not check if valid URL, parse and get its domain, resolve it to IPv4 and return it
    try:
        domain = urlparse(url_or_ip).netloc
    except:
        print(f"[-] {url_or_ip} is invalid IPv4 or URL")
        return False

    # should get a list of IPv4 addresses resolved from the domain
    try:
        hostname, aliaslist, ipaddrlist = socket.gethostbyname_ex(domain)
    except:
        print(f"[-] Failed to resolve {url_or_ip} to Ipv4")
        return False

    return ipaddrlist


def create_bpf_allow_list(bpf):
    bpf_allow_list = bpf.get_table("allow_list")
    bpf_pid_list = bpf.get_table("pid_list")
    with open("allow_list.json", "r") as f:
        pids_to_list = json.loads(f.read())

    print("[+] Reading and parsing allow_list.json")
    for pid_to_list in pids_to_list:
        try:
            pid = int(pid_to_list["pid"])
        except ValueError:
            print(f"[-] invalid PID: {pid_to_list['pid']}")
            continue

        print(f"[+] Adding {pid} to monitored processes")
        bpf_pid_list[bpf_pid_list.Key(pid)] = bpf_pid_list.Leaf(pid)

        for url_or_ip in pid_to_list["allow_list"]:
            ips = parse_address(url_or_ip)
            if not ips:
                continue
            for ip in ips:
                print(f"[+] Adding {ip} to allowed IPs")
                ip = ip_to_network_address(ip)
                bpf_allow_list[bpf_allow_list.Key(ip)] = bpf_allow_list.Leaf(ip)


def create_tc(interface):
    ip = pyroute2.IPRoute()
    ipdb = pyroute2.IPDB(nl=ip)
    try:
        idx = ipdb.interfaces[interface].index
    except:
        print(f"[-] {interface} interface not found")
        return False, False, False

    try:
        # deleting if exists from previous run
        ip.tc("del", "clsact", idx)
    except:
        pass
    ip.tc("add", "clsact", idx)
    return ip, ipdb, idx


def parse_blocked_event(cpu, data, size):
    event = bpf["blocked_events"].event(data)
    src_ip = network_address_to_ip(event.src_ip)
    dst_ip = network_address_to_ip(event.dst_ip)
    flags = parse_tcp_flags(event.tcp_flags)
    print(f"{event.pid}: {event.comm.decode()} - {src_ip}:{event.src_port} -> {dst_ip}:{event.dst_port} Flags: {flags} was blocked!")


def parse_verbose_event(cpu, data, size):
    event = bpf["verbose_events"].event(data)
    src_ip = network_address_to_ip(event.src_ip)
    dst_ip = network_address_to_ip(event.dst_ip)
    verbose_message = get_verbose_message(event.state)
    print(f"{event.pid}: {event.comm.decode()} - {src_ip}:{event.src_port} -> {dst_ip}:{event.dst_port} - {verbose_message}")



parser = argparse.ArgumentParser(description="Monitor given PIDs and block outgoing connections to all addresses initiated from them, unless they are listed in allow_list.json")
parser.add_argument("-i", "--interface", help="Network interface name to monitor traffic on", required=True, type=str)
parser.add_argument("-v", "--verbose", action="store_true", help="Set verbose output")
args = parser.parse_args()
print(f"[+] Monitoring {args.interface} interface")


with open("tcp_mon_block.c", "r") as f:
    bpf_text = f.read()

if args.verbose:
    print("[+] Verbose output is ON!")
    bpf_text = bpf_text.replace("static bool VERBOSE_OUTPUT = false", "static bool VERBOSE_OUTPUT = true")


ip, ipdb, idx = create_tc(args.interface)
if not ip:
    exit(-1)

bpf = BPF(text=bpf_text)
create_bpf_allow_list(bpf)

# loading kprobe
bpf.attach_kprobe(event="tcp_connect", fn_name="trace_connect_entry")

# loading TC
fn = bpf.load_func("handle_egress", BPF.SCHED_CLS)

#default parent handlers:
#https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/pkt_sched.h?id=1f211a1b929c804100e138c5d3d656992cfd5622
#define TC_H_MIN_INGRESS	0xFFF2U
#define TC_H_MIN_EGRESS		0xFFF3U

ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff3", classid=1, direct_action=True)
bpf["blocked_events"].open_perf_buffer(parse_blocked_event)
bpf["verbose_events"].open_perf_buffer(parse_verbose_event)


print("[+] Monitoring started\n")
while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        break

ip.tc("del", "clsact", idx)
ipdb.release()










