#!/usr/bin/python2

from bcc import BPF
from ctypes import *
import argparse
import os
from bcc.utils import printb
from time import sleep,time,localtime,asctime
import types

# pre defines -------------------------------
ROOT_PATH = "/sys/class/net"
IFNAMSIZ = 16
COL_WIDTH = 10

# structure for network interface name array
class Devname(Structure):
    _fields_=[
        ('name', c_char*IFNAMSIZ)
    ]

class QueueData(Structure):
    _fields_=[
        ('datalen', c_ulonglong),
        ('pkg', c_uint),
        ('size64', c_uint),
        ('size512', c_uint),
        ('size2048', c_uint),
        ('size16384', c_uint),
        ('size65536', c_uint),
    ]

################## printer for results ###################
def toStr(num):
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
		"BPS", 
		"PPS", 
		"avg_size", 
		"[0, 64)", 
		"[64, 512)", 
		"[512, 2K)", 
		"[2K, 16K)",
		"[16K, 64K)"
	]
    for hd in headers:
		print(hd.center(COL_WIDTH)),
    print

    # ------- calculates --------------
    qids=[]
    tBPS = 0
    tPPS = 0
    tAVG = 0
    tGroup = [0,0,0,0,0]
    tpkg = 0
    tlen = 0
    for k, v in table.items():
        qids += [k.value]
        tlen += v.datalen
        tpkg += v.pkg
        tGroup[0] += v.size64
        tGroup[1] += v.size512
        tGroup[2] += v.size2048
        tGroup[3] += v.size16384
        tGroup[4] += v.size65536
    tBPS = tlen / print_interval
    tPPS = tpkg / print_interval
    if tpkg != 0:
        tAVG = tlen / tpkg

    # -------- print table --------------
    for k in range(qnum):
        if k in qids:
            item = table[c_ushort(k)]
            data = [
                k,
                item.datalen,
                item.pkg,
                item.size64,
                item.size512,
                item.size2048,
                item.size16384,
                item.size65536
            ]
        else:
            data = [k,0,0,0,0,0,0,0]
        
        # print a line per queue
        BPS = data[1] / print_interval
        PPS = data[2] / print_interval
        avg = 0
        if data[2] != 0:
            avg = data[1] / data[2]
        printb(b"%5d %11s %10s %10s %10s %10s %10s %10s %10s" % (
            data[0],
            toStr(BPS),
            toStr(PPS),
            toStr(avg),
            toStr(data[3]),
            toStr(data[4]),
            toStr(data[5]),
            toStr(data[6]),
            toStr(data[7])
        ))
    
    # ------- print total --------------
    printb(b" Total %10s %10s %10s %10s %10s %10s %10s %10s" % (
        toStr(tBPS),
        toStr(tPPS),
        toStr(tAVG),
        toStr(tGroup[0]),
        toStr(tGroup[1]),
        toStr(tGroup[2]),
        toStr(tGroup[3]),
        toStr(tGroup[4])
    ))


def print_result(b):
    # --------- print tx queues ---------------
    print(asctime(localtime(time())))
    print("TX")
    table = b['TXq']
    print_table(table, tx_num)
    b['TXq'].clear()

    # --------- print rx queues ---------------
    print("")
    print("RX")
    table = b['RXq']
    print_table(table, rx_num)
    b['RXq'].clear()
    print("-" * 100)

############## specify network interface #################
parser = argparse.ArgumentParser(description="")
parser.add_argument("--name", "-n", type=str, default="")
parser.add_argument("--interval", "-i", type=float, default=1)
args = parser.parse_args()
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

################## start tracing ##################
b = BPF(src_file = "netqtop.c")
# --------- set hash array --------
devname_map = b['nameMap']
_name = Devname()
_name.name = dev_name
devname_map[0] = _name

while 1:
    try:
        sleep(print_interval)
        print_result(b)
    except KeyboardInterrupt:
        exit()

'''
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print msg
        #print b['nameMap'][0].name
    except KeyboardInterrupt:
        exit()
'''