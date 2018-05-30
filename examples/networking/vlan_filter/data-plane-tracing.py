#!/usr/bin/python
from __future__ import print_function
from bcc import BPF

import sys
import socket
import os
import argparse
import time
import netifaces as ni

from sys import argv
from kafka import KafkaProducer
from kafka.errors import KafkaError
from datetime import datetime

#args
def usage():
    print("USAGE: %s [-i <if_name>]" % argv[0])
    print("")
    print("Try '%s -h' for more options." % argv[0])
    exit()

#help
def help():
    print("USAGE: %s [-i <if_name>][-k <kafka_server_name:kafka_port>]" % argv[0])
    print("")
    print("optional arguments:")
    print("   -h                       print this help")
    print("   -i if_name               select interface if_name. Default is eth0")
    print("   -k kafka_server_name     select kafka server name. Default is save to file")
    print("                            If -k option is not specified data will be saved to file.")
    
    print("")
    print("examples:")
    print("    data-plane-tracing                                      # bind socket to eth0")
    print("    data-plane-tracing -i eno2 -k vc.manage.overcloud:9092  # bind socket to eno2 and send data to kafka server in iovisor-topic.")
    exit()

#arguments
interface="eth0"
kafkaserver=''
        
#check provided arguments
if len(argv) == 2:
    if str(argv[1]) == '-h':
        help()
    else:
        usage()

if len(argv) == 3:
    if str(argv[1]) == '-i':
        interface = argv[2]
    elif str(argv[1]) == '-k':
        kafkaserver = argv[2] 
    else:
        usage()
    
if len(argv) == 5:
    if str(argv[1]) == '-i':
        interface = argv[2]
        kafkaserver = argv[4]
    elif str(argv[1]) == '-k':
        kafkaserver = argv[2] 
        interface = argv[4]
    else:
        usage()

if len(argv) > 5:
    usage()

print ("binding socket to '%s'" % interface)	
 
#initialize BPF - load source code from http-parse-simple.c
bpf = BPF(src_file = "data-plane-tracing.c", debug = 0)

#load eBPF program http_filter of type SOCKET_FILTER into the kernel eBPF vm
#more info about eBPF program types http://man7.org/linux/man-pages/man2/bpf.2.html
function_vlan_filter = bpf.load_func("vlan_filter", BPF.SOCKET_FILTER)

#create raw socket, bind it to eth0
#attach bpf program to socket created
BPF.attach_raw_socket(function_vlan_filter, interface)

#get file descriptor of the socket previously created inside BPF.attach_raw_socket
socket_fd = function_vlan_filter.sock

#create python socket object, from the file descriptor
sock = socket.fromfd(socket_fd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)

#set it as blocking socket
sock.setblocking(True)

#get interface ip address. In case ip is not set then just add 127.0.0.1.
ni.ifaddresses(interface)
try:
    ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
except:
    ip = '127.0.0.1'    

print("| Timestamp | Host Name | Host IP | IP Version | Source Host IP | Dest Host IP | Source Host Port | Dest Host Port | VNI | Source VM MAC | Dest VM MAC | VLAN ID | Source VM IP | Dest VM IP | Protocol | Source VM Port | Dest VM Port | Packet Length |")

while 1:
    #retrieve raw packet from socket
    packet_str = os.read(socket_fd, 2048)
    
    #convert packet into bytearray
    packet_bytearray = bytearray(packet_str)
    
    #ethernet header length
    ETH_HLEN = 14 
    
    #VXLAN header length
    VXLAN_HLEN = 8
    
    #VLAN header length
    VLAN_HLEN = 4
    
    #Inner TCP/UDP header length
    TCP_HLEN = 20
    UDP_HLEN = 8
    
    #calculate packet total length
    total_length = packet_bytearray[ETH_HLEN + 2]               #load MSB
    total_length = total_length << 8                            #shift MSB
    total_length = total_length + packet_bytearray[ETH_HLEN+3]  #add LSB
    
    #calculate ip header length
    ip_header_length = packet_bytearray[ETH_HLEN]               #load Byte
    ip_header_length = ip_header_length & 0x0F                  #mask bits 0..3
    ip_header_length = ip_header_length << 2                    #shift to obtain length
    
    #calculate payload offset
    payload_offset = ETH_HLEN + ip_header_length + UDP_HLEN + VXLAN_HLEN
    
    #parsing ip version from ip packet header
    ipversion = str(bin(packet_bytearray[14])[2:5])
    
    #parsing source ip address, destination ip address from ip packet header
    src_host_ip = str(packet_bytearray[26]) + "." + str(packet_bytearray[27]) + "." + str(packet_bytearray[28]) + "." + str(packet_bytearray[29])
    dest_host_ip = str(packet_bytearray[30]) + "." + str(packet_bytearray[31]) + "." + str(packet_bytearray[32]) + "." + str(packet_bytearray[33])
    
    #parsing source port and destination port
    src_host_port = packet_bytearray[34] << 8 | packet_bytearray[35]
    dest_host_port = packet_bytearray[36] << 8 | packet_bytearray[37]
    
    #parsing VNI from VXLAN header
    VNI = str((packet_bytearray[46])+(packet_bytearray[47])+(packet_bytearray[48]))
    
    #parsing source mac address and destination mac address
    mac_add = [packet_bytearray[50], packet_bytearray[51], packet_bytearray[52], packet_bytearray[53], packet_bytearray[54], packet_bytearray[55]]
    src_vm_mac = ":".join(map(lambda b: format(b, "02x"), mac_add))
    mac_add = [packet_bytearray[56], packet_bytearray[57], packet_bytearray[58], packet_bytearray[59], packet_bytearray[60], packet_bytearray[61]]
    dest_vm_mac = ":".join(map(lambda b: format(b, "02x"), mac_add))
    
    #parsing VLANID from VLAN header
    VLANID=""
    VLANID = str((packet_bytearray[64])+(packet_bytearray[65]))

    #parsing source vm ip address, destination vm ip address from encapsulated ip packet header
    src_vm_ip = str(packet_bytearray[80]) + "." + str(packet_bytearray[81]) + "." + str(packet_bytearray[82]) + "." + str(packet_bytearray[83])
    dest_vm_ip = str(packet_bytearray[84]) + "." + str(packet_bytearray[85]) + "." + str(packet_bytearray[86]) + "." + str(packet_bytearray[87]) 
    
    #parsing source port and destination port
    if (packet_bytearray[77]==6 or packet_bytearray[77]==17):
        src_vm_port = packet_bytearray[88] << 8 | packet_bytearray[88]
        dest_vm_port = packet_bytearray[90] << 8 | packet_bytearray[91]
    elif (packet_bytearray[77]==1):
        src_vm_port = -1
        dest_vm_port = -1
        type = str(packet_bytearray[88])
    else:
        continue
    
    timestamp = str(datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S.%f'))
    
    #send data to remote server via Kafka Messaging Bus
    if kafkaserver:
        MESSAGE = (timestamp, socket.gethostname(),ip, str(int(ipversion, 2)), str(src_host_ip), str(dest_host_ip), str(src_host_port), str(dest_host_port), str(int(VNI)), str(src_vm_mac), str(dest_vm_mac), str(int(VLANID)), src_vm_ip, dest_vm_ip, str(packet_bytearray[77]), str(src_vm_port), str(dest_vm_port), str(total_length))
        print (MESSAGE)
        MESSAGE = ','.join(MESSAGE)
        MESSAGE = MESSAGE.encode() 
        producer = KafkaProducer(bootstrap_servers=[kafkaserver])
        producer.send('iovisor-topic', key=b'iovisor', value=MESSAGE)
    
    #save data to files
    else:
        MESSAGE = timestamp+","+socket.gethostname()+","+ip+","+str(int(ipversion, 2))+","+src_host_ip+","+dest_host_ip+","+str(src_host_port)+","+str(dest_host_port)+","+str(int(VNI))+","+str(src_vm_mac)+","+str(dest_vm_mac)+","+str(int(VLANID))+","+src_vm_ip+","+dest_vm_ip+","+str(packet_bytearray[77])+","+str(src_vm_port)+","+str(dest_vm_port)+","+str(total_length)
        print (MESSAGE)
        #save data to a file on hour basis 
        filename = "./vlan-data-"+time.strftime("%Y-%m-%d-%H")+"-00"
        with open(filename, "a") as f:
            f.write("%s\n" % MESSAGE)
