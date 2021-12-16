#!/bin/bash

ip netns exec netns11 ping 192.168.100.12 -c 10
ip netns exec netns22 ping 192.168.200.21 -c 10
