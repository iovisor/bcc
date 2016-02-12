#Simple HTTP Filter: Project purpose

Write an eBPF application that parses HTTP packets and extracts (and prints on screen) the URL contained in the GET/POST request.

[eBPF HTTP Filter - Short Presentation](https://github.com/iovisor/bpf-docs/blob/master/ebpf_http_filter.pdf)

#Usage Example

```Shell
$ sudo python http-parse-v2.py 
GET /pipermail/iovisor-dev/ HTTP/1.1
HTTP/1.1 200 OK
GET /favicon.ico HTTP/1.1
HTTP/1.1 404 Not Found
GET /pipermail/iovisor-dev/2016-January/thread.html HTTP/1.1
HTTP/1.1 200 OK
GET /pipermail/iovisor-dev/2016-January/000046.html HTTP/1.1
HTTP/1.1 200 OK
```

#Implementation using BCC

eBPF socket filter.<br />
Filters IP and TCP packets, containing "HTTP", "GET", "POST" in payload and all subsequent packets belonging to the same session, having the same (ip_src,ip_dst,port_src,port_dst).<br />
Program is loaded as PROG_TYPE_SOCKET_FILTER and attached to a socket, bind to eth0. <br />
Matching packets are forwarded to user space, others dropped by the filter.<br />
<br />
Python script reads filtered raw packets from the socket, if necessary reassembles packets belonging to the same session, and prints on stdout the first line of the HTTP GET/POST request. <br />

#v1 vs v2

First version is the simple one: if the url is too long (splitted in more than one packet) is truncated. <br />
Second version is quite more complex: if necessary reassembles packets belonging to the same session and prints the complete url.

#To run:

```Shell
$ sudo python http-parse.py
$ sudo python http-parse-v2.py
```