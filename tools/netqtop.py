#!/usr/bin/python

from bcc import BPF
from ctypes import *
import argparse
import os
from time import sleep,time,localtime,asctime
import types

# pre defines -------------------------------
ROOT_PATH = "/sys/class/net"
IFNAMSIZ = 16
COL_WIDTH = 10
MAX_QUEUE_NUM = 1024
EBPF_FILE = "netqtop.c"

# structure for network interface name array
class Devname(Structure):
    _fields_=[
        ('name', c_char*IFNAMSIZ)
    ]

################## printer for results ###################
def to_str(num):
    s = ""
    if num > 1000000:
        return str(round(num/(1024*1024.0), 2)) + 'M'
    elif num > 1000:
        return str(round(num/1024.0, 2)) + 'K'
    else:
        if type(num) == types.FloatType:
            return str(round(num, 2))
        else:
            return str(num)

def print_table(table, qnum):
    global print_interval

    # ---- print headers ----------------
    headers = [
		"QueueID", 
		"avg_size", 
		"[0, 64)", 
		"[64, 512)", 
		"[512, 2K)", 
		"[2K, 16K)",
		"[16K, 64K)"
	]
    if args.throughput:
        headers.append("BPS")
        headers.append("PPS")

    for hd in headers:
		print(hd.center(COL_WIDTH)),
    print

    # ------- calculates --------------
    qids=[]
    tBPS = 0
    tPPS = 0
    tAVG = 0
    tGroup = [0,0,0,0,0]
    tpkt = 0
    tlen = 0
    for k, v in table.items():
        qids += [k.value]
        tlen += v.total_pkt_len
        tpkt += v.num_pkt
        tGroup[0] += v.size_64B
        tGroup[1] += v.size_512B
        tGroup[2] += v.size_2K
        tGroup[3] += v.size_16K
        tGroup[4] += v.size_64K
    tBPS = tlen / print_interval
    tPPS = tpkt / print_interval
    if tpkt != 0:
        tAVG = tlen / tpkt

    # -------- print table --------------
    for k in range(qnum):
        if k in qids:
            item = table[c_ushort(k)]
            data = [
                k,
                item.total_pkt_len,
                item.num_pkt,
                item.size_64B,
                item.size_512B,
                item.size_2K,
                item.size_16K,
                item.size_64K
            ]
        else:
            data = [k,0,0,0,0,0,0,0]
        
        # print a line per queue
        avg = 0
        if data[2] != 0:
            avg = data[1] / data[2]
        print("%5d %11s %10s %10s %10s %10s %10s" % (
            data[0],
            to_str(avg),
            to_str(data[3]),
            to_str(data[4]),
            to_str(data[5]),
            to_str(data[6]),
            to_str(data[7])
        )),
        if args.throughput:
            BPS = data[1] / print_interval
            PPS = data[2] / print_interval
            print("%10s %10s" % (
                to_str(BPS),
                to_str(PPS)
            ))
        else:
            print
    
    # ------- print total --------------
    print(" Total %10s %10s %10s %10s %10s %10s" % (
        to_str(tAVG),
        to_str(tGroup[0]),
        to_str(tGroup[1]),
        to_str(tGroup[2]),
        to_str(tGroup[3]),
        to_str(tGroup[4])
    )),

    if args.throughput:
        print("%10s %10s" % (
            to_str(tBPS),
            to_str(tPPS)
        ))
    else:
        print


def print_result(b):
    # --------- print tx queues ---------------
    print(asctime(localtime(time())))
    print("TX")
    table = b['tx_q']
    print_table(table, tx_num)
    b['tx_q'].clear()

    # --------- print rx queues ---------------
    print("")
    print("RX")
    table = b['rx_q']
    print_table(table, rx_num)
    b['rx_q'].clear()
    if args.throughput:
        print("-"*95)
    else:
        print("-"*76)

############## specify network interface #################
parser = argparse.ArgumentParser(description="")
parser.add_argument("--name", "-n", type=str, default="")
parser.add_argument("--interval", "-i", type=float, default=1)
parser.add_argument("--throughput", "-t", action="store_true")
parser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)
args = parser.parse_args()

if args.ebpf:
    with open(EBPF_FILE) as fileobj:
        progtxt = fileobj.read()
        print(progtxt)
    exit()

if args.name == "":
	print ("Please specify a network interface.")
	exit()
else:
	dev_name = args.name

if len(dev_name) > IFNAMSIZ-1:
    print ("NIC name too long")
    exit()

print_interval = args.interval + 0.0
if print_interval == 0:
    print "print interval must be non-zero"
    exit()

################ get number of queues #####################
tx_num = 0
rx_num = 0
path = ROOT_PATH + "/" + dev_name + "/queues"
if not os.path.exists(path):
	print "Net interface", dev_name, "does not exits."
	exit()

list = os.listdir(path)
for s in list:
    if s[0] == 'r':
        rx_num += 1
    if s[0] == 't':
        tx_num += 1

if tx_num > MAX_QUEUE_NUM or rx_num > MAX_QUEUE_NUM:
    print "number of queues over 1024 is not supported."
    exit()

################## start tracing ##################
b = BPF(src_file = EBPF_FILE)
# --------- set hash array --------
devname_map = b['name_map']
_name = Devname()
_name.name = dev_name
devname_map[0] = _name

while 1:
    try:
        sleep(print_interval)
        print_result(b)
    except KeyboardInterrupt:
        exit()
