## Tunnel Monitor Example

This example shows how to use a BPF program to parse packets across an
encapsulation boundary. It uses this ability to record inner+outer ip addresses
as well as vxlan id into a hash table. The entries in that table store bytes
and packets received/transmitted. One novel part of this program is its use of
`bpf_tail_call` to parse two different IP headers (inner/outer) using the same
state machine logic.

Also part of this example is a simulation of a multi-host environment with an
overlay network (using vxlan in this case), and each host contains multiple
clients in different segments of the overlay network. The script `traffic.sh`
can be used to simulate a subset of clients on host0 talking to various other
clients+hosts at different traffic rates.

![Overlay Diagram](vxlan.jpg)

Once the simulation is running, the statistics kept by the BPF program can be
displayed to give a visual clue as to the nature of the traffic flowing over
the physical interface, post-encapsulation.

![Chord Diagram](chord.png)

To get the example running, change into the examples/tunnel_monitor directory.
If this is the first time, run `setup.sh` to pull in the UI component and
dependencies. You will need nodejs+npm installed on the system to run this, but
the setup script will only install packages in the local directory.

```
[user@localhost tunnel_monitor]$ ./setup.sh 
Cloning into 'chord-transitions'...
remote: Counting objects: 294, done.
...
jquery#2.1.4 bower_components/jquery
modernizr#2.8.3 bower_components/modernizr
fastclick#1.0.6 bower_components/fastclick
[user@localhost tunnel_monitor]$
```

Then, start the simulation by running main.py:

```
[root@bcc-dev tunnel_monitor]# python main.py 
Launching host 1 of 9
Launching host 2 of 9
...
Starting tunnel 8 of 9
Starting tunnel 9 of 9
HTTPServer listening on 0.0.0.0:8080
Press enter to quit:
```

The prompt will remain until you choose to exit. In the background, the script
has started a python SimpleHTTPServer on port 8080, which you may now try to
connect to from your browser. There will likely be a blank canvas until traffic
is sent through the tunnels.

To simulate traffic, use the traffic.sh script to generate a distribution of
pings between various clients and hosts. Check back on the chord diagram to
see a visualization. Try clicking on a host IP address to see a breakdown of
the inner IP addresses sent to/from that host.

As an exercise, try modifying the traffic.sh script to cause one of the clients
to send much more traffic than the others, and use the chord diagram to identify
the culprit.
