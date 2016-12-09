#!/bin/bash
# Run this script if for some reason the endToEndTest.py crashed
# and left some garbage state

ip netns del sw
ip netns del srv
ip netns del clt

ip link del dev veth-clt-sw
ip link del dev veth-srv-sw

