This example shows how a combination of BPF programs can be used to perform
per-IP classification and rate limiting. The simulation in this example
shows an example where N+M devices are combined and use 1 WAN. Traffic sent
from/to the "neighbor" devices have their combined bandwidth capped at
128kbit, and the rest of the traffic can use an additional 1Mbit.

This works by sharing a map between various tc ingress filters, each with
a related set of bpf functions attached. The map stores a list of dynamically
learned ip addresses that were seen on the neighbor devices and should be
throttled.

                         /------------\                        |
neigh1 --|->->->->->->->-|            |                        |
neigh2 --|->->->->->->->-|    <-128kb-|        /------\        |
neigh3 --|->->->->->->->-|            |  wan0  | wan  |        |
         | ^             |   br100    |-<-<-<--| sim  |        |
         | clsfy_neigh() |            |   ^    \------/        |
lan1 ----|->->->->->->->-|    <--1Mb--|   |                    |
lan2 ----|->->->->->->->-|            |   classify_wan()       |
           ^             \------------/                        |
           pass()                                              |

To run the example:

$ sudo /path/to/neighbor_sharing/neighbor_sharing.py
Starting netserver with host 'IN(6)ADDR_ANY' port '12865' and family AF_UNSPEC
Starting netserver with host 'IN(6)ADDR_ANY' port '12865' and family AF_UNSPEC
Starting netserver with host 'IN(6)ADDR_ANY' port '12865' and family AF_UNSPEC
Starting netserver with host 'IN(6)ADDR_ANY' port '12865' and family AF_UNSPEC
Starting netserver with host 'IN(6)ADDR_ANY' port '12865' and family AF_UNSPEC
Network ready. Create a shell in the wan0 namespace and test with netperf
   (Neighbors are 172.16.1.100-102, and LAN clients are 172.16.1.150-151)
 e.g.: ip netns exec wan0 netperf -H 172.16.1.100 -l 2
Press enter when finished:


In another shell:
$ sudo ip netns exec wan0 netperf -H 172.16.1.100 -l 2
MIGRATED TCP STREAM TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 172.16.1.100 () port 0 AF_INET : demo
Recv   Send    Send
Socket Socket  Message  Elapsed
Size   Size    Size     Time     Throughput
bytes  bytes   bytes    secs.    10^6bits/sec

 87380  16384  16384    4.30        0.18

$ sudo ip netns exec wan0 netperf -H 172.16.1.150 -l 2
MIGRATED TCP STREAM TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 172.16.1.150 () port 0 AF_INET : demo
Recv   Send    Send
Socket Socket  Message  Elapsed
Size   Size    Size     Time     Throughput
bytes  bytes   bytes    secs.    10^6bits/sec

 87380  16384  16384    4.10        1.01


The bandwidth is throttled according to the IP.
