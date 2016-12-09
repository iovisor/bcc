This example shows a unique way to use a BPF program to demux any ethernet
traffic into a pool of worker veth+namespaces (or any ifindex-based
destination) depending on a configurable mapping of src-mac to ifindex. As
part of the ingress processing, the program will dynamically learn the source
ifindex of the matched source mac.

Simulate a physical network with a vlan aware switch and clients that may
connect to any vlan. The program will detect the known clients and pass the
traffic through to a dedicated namespace for processing. Clients may have
overlapping IP spaces and the traffic will still work.

               |           bpf program                      |
cli0 --|       |                            /--|-- worker0  |
cli1 --| trunk | +->--->-handle_p2v(pkt)-> /---|-- worker1  |
cli2 --|=======|=+                        /----|-- worker2  |
...  --|       | +-<---<-handle_v2p(pkt)-<-----|--  ...     |
cliN --|       |                          \----|-- workerM  |
       |       |                              ^             |
     phys      |                            veth            |
    switch     |                                            |

To run the example, simply:

sudo /path/to/vlan_learning/vlan_learning.py

Serving HTTP on 0.0.0.0 port 80 ...
Serving HTTP on 0.0.0.0 port 80 ...
Serving HTTP on 0.0.0.0 port 80 ...
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0172.16.1.100 - - [04/Nov/2015 10:54:47] "GET / HTTP/1.1" 200 -
100   574  100   574    0     0  45580      0 --:--:-- --:--:-- --:--:-- 47833

...

Press enter to exit:
mac 020000000000 rx pkts = 95, rx bytes = 7022
                 tx pkts = 0, tx bytes = 0
mac 020000000001 rx pkts = 95, rx bytes = 7022
                 tx pkts = 0, tx bytes = 0
mac 020000000002 rx pkts = 97, rx bytes = 7154
                 tx pkts = 0, tx bytes = 0

