Demonstrations of swapin, the Linux BCC/eBPF version.


This tool counts swapins by process, to show which process is affected by
swapping. For example:

# swapin.py 
Counting swap ins. Ctrl-C to end.
13:36:58
COMM             PID    COUNT

13:36:59
COMM             PID    COUNT
gnome-shell      2239   12410

13:37:00
COMM             PID    COUNT
chrome           4536   14635

13:37:01
COMM             PID    COUNT
gnome-shell      2239   14
cron             1180   23

13:37:02
COMM             PID    COUNT
gnome-shell      2239   2496
[...]

While tracing, this showed that PID 2239 (gnome-shell) and PID 4536 (chrome)
suffered over ten thousand swapins.



USAGE:

# swapin.py -h
usage: swapin.py [-h] [-T] [interval] [count]

Count swapin events by process.

positional arguments:
  interval      output interval, in seconds
  count         number of outputs

optional arguments:
  -h, --help    show this help message and exit
  -T, --notime  do not show the timestamp (HH:MM:SS)
