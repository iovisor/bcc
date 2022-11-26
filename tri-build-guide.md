# Build BCC on Ubuntu 20.04

## Precheck

```shell
$ ./build-precheck.sh
```

## Build from source

```shell
$ ./build-bcc.sh
```

## Post check

```shell
$ sudo bash -c /usr/share/bcc/tools/biotop
```

Test may fail with the following error:

```shell
bash: /usr/share/bcc/tools/biotop: /usr/bin/python: bad interpreter: No such file or directory
```

Fix it with:

```shell
$ sudo ln -s /usr/bin/python3 /usr/bin/python
```

Now it should be OK:

```shell
$ sudo bash -c /usr/share/bcc/tools/biotop
Tracing... Output every 1 secs. Hit Ctrl-C to end
02:52:40 loadavg: 0.10 0.10 0.19 2/318 10090

PID     COMM             D MAJ MIN DISK       I/O  Kbytes  AVGms
02:52:41 loadavg: 0.10 0.10 0.19 7/318 10091

PID     COMM             D MAJ MIN DISK       I/O  Kbytes  AVGms
02:52:42 loadavg: 0.10 0.10 0.19 2/318 10092
```

More tests:

```shell
$ sudo bash -c /usr/share/bcc/tools/tcplife
PID   COMM       LADDR           LPORT RADDR           RPORT TX_KB RX_KB MS
10267 curl       172.31.16.191   35264 110.242.68.66   80        0     0 454.03
10273 curl       172.31.16.191   47668 172.253.115.113 80        0     0 9.38
```
