#!/bin/bash

# This script must be executed by root user
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

# add namespaces
ip netns add netns11
ip netns add netns12
ip netns add netns21
ip netns add netns22
ip netns add netns3
ip netns add netns4

# set up veth devices in netns11 to netns21 with connection to netns3  
ip link add veth11 type veth peer name veth13
ip link add veth21 type veth peer name veth23
ip link set veth11 netns netns11
ip link set veth21 netns netns21
ip link set veth13 netns netns3
ip link set veth23 netns netns3

# set up veth devices in netns12 and netns22 with connection to netns4 
ip link add veth12 type veth peer name veth14
ip link add veth22 type veth peer name veth24
ip link set veth12 netns netns12
ip link set veth22 netns netns22
ip link set veth14 netns netns4
ip link set veth24 netns netns4
  
# assign IP addresses and set the devices up 
ip netns exec netns11 ifconfig veth11 192.168.100.11/24 up
ip netns exec netns11 ip link set lo up
ip netns exec netns12 ifconfig veth12 192.168.100.12/24 up
ip netns exec netns12 ip link set lo up
ip netns exec netns21 ifconfig veth21 192.168.200.21/24 up
ip netns exec netns21 ip link set lo up
ip netns exec netns22 ifconfig veth22 192.168.200.22/24 up
ip netns exec netns22 ip link set lo up

# set up bridge brx and its ports 
ip netns exec netns3 brctl addbr brx  
ip netns exec netns3 ip link set brx up
ip netns exec netns3 ip link set veth13 up
ip netns exec netns3 ip link set veth23 up
ip netns exec netns3 brctl addif brx veth13
ip netns exec netns3 brctl addif brx veth23

# set up bridge bry and its ports 
ip netns exec netns4 brctl addbr bry  
ip netns exec netns4 ip link set bry up
ip netns exec netns4 ip link set veth14 up
ip netns exec netns4 ip link set veth24 up
ip netns exec netns4 brctl addif bry veth14
ip netns exec netns4 brctl addif bry veth24

# create veth devices to connect the bridges
ip link add vethx type veth peer name vethx11
ip link add vethy type veth peer name vethy11
ip link set vethx netns netns3
ip link set vethx11 netns netns3
ip link set vethy netns netns4
ip link set vethy11 netns netns4

ip netns exec netns3 brctl addif brx vethx
ip netns exec netns3 ip link set vethx up
ip netns exec netns3 bridge vlan add vid 100 tagged dev vethx
ip netns exec netns3 bridge vlan add vid 200 tagged dev vethx
ip netns exec netns3 bridge vlan del vid 1 dev vethx
ip netns exec netns3 bridge vlan show

ip netns exec netns4 brctl addif bry vethy
ip netns exec netns4 ip link set vethy up
ip netns exec netns4 bridge vlan add vid 100 tagged dev vethy
ip netns exec netns4 bridge vlan add vid 200 tagged dev vethy
ip netns exec netns4 bridge vlan del vid 1 dev vethy
ip netns exec netns4 bridge vlan show

ip netns exec netns3 ip link set dev brx type bridge vlan_filtering 1
ip netns exec netns4 ip link set dev bry type bridge vlan_filtering 1
ip netns exec netns3 bridge vlan del vid 1 dev brx self
ip netns exec netns4 bridge vlan del vid 1 dev bry self
ip netns exec netns3 bridge vlan show
ip netns exec netns4 bridge vlan show

ip netns exec netns3 bridge vlan add vid 100 pvid untagged dev veth13
ip netns exec netns3 bridge vlan add vid 200 pvid untagged dev veth23
ip netns exec netns4 bridge vlan add vid 100 pvid untagged dev veth14
ip netns exec netns4 bridge vlan add vid 200 pvid untagged dev veth24

ip netns exec netns3 bridge vlan del vid 1 dev veth13
ip netns exec netns3 bridge vlan del vid 1 dev veth23
ip netns exec netns4 bridge vlan del vid 1 dev veth14
ip netns exec netns4 bridge vlan del vid 1 dev veth24

# set up bridge brvx and its ports 
ip netns exec netns3 brctl addbr brvx  
ip netns exec netns3 ip link set brvx up
ip netns exec netns3 ip link set vethx11 up
ip netns exec netns3 brctl addif brvx vethx11

# set up bridge brvy and its ports 
ip netns exec netns4 brctl addbr brvy  
ip netns exec netns4 ip link set brvy up
ip netns exec netns4 ip link set vethy11 up
ip netns exec netns4 brctl addif brvy vethy11

# create veth devices to connect the vxlan bridges
ip link add veth3 type veth peer name veth4
ip link add veth5 type veth peer name veth6
ip link set veth3 netns netns3
ip link set veth5 netns netns4
ip netns exec netns3 ip link set veth3 up
ip netns exec netns4 ip link set veth5 up
ip link set veth4 up
ip link set veth6 up
ip netns exec netns3 ifconfig veth3 10.1.1.11/24 up
ip netns exec netns4 ifconfig veth5 10.1.1.12/24 up

# add vxlan ports
ip netns exec netns3 ip link add vxlan-10 type vxlan id 10 remote 10.1.1.12 dstport 4789 dev veth3
ip netns exec netns4 ip link add vxlan-10 type vxlan id 10 remote 10.1.1.11 dstport 4789 dev veth5
ip netns exec netns3 ip link set vxlan-10 up
ip netns exec netns4 ip link set vxlan-10 up
ip netns exec netns3 brctl addif brvx vxlan-10
ip netns exec netns4 brctl addif brvy vxlan-10

# create veth devices to connect the vxlan bridges
ip link add veth7 type veth peer name veth8
ip link set veth7 up
ip link set veth8 up

# set up bridge brjx and its ports 
brctl addbr brjx  
ip link set brjx up
ip link set veth4 up
brctl addif brjx veth4
brctl addif brjx veth7

# set up bridge brjy and its ports 
brctl addbr brjy  
ip link set brjy up
ip link set veth6 up
brctl addif brjy veth6
brctl addif brjy veth8
