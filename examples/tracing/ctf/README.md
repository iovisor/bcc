## eBPF to CTF

A possible extension to BCC can be to convert trace data coming from maps 
and write it as Common Trace Format (CTF) data. The CTF format is a 
compact binary trace format which is used by tools such as LTTng and can 
allow traces to be viewed in a very nice fashion in Trace Compass. This 
would allow efficient trace storage for post-mortem analysis. Also, it would
allow traces to be viewed graphically. Trace Compass has very interesting 
features such as flame-charts, critical flow view, resource view etc. 
Eventually we also lan to have data-driven XML based views which are BPF 
specific and generated from combination of dynamically selected BPF events.
For now, we use Babeltrace python bindings which allows us to directly 
hook onto python programs and record CTF traces.
 
### More Info
**CTF** : http://diamon.org/ctf/  
**Babeltrace** : http://diamon.org/babeltrace/  
**TraceCompass** : http://tracecompass.org/

### Requirements
Current implementation requires `libbabeltrace` 2.0.0-pre to be installed. We 
will move to the stable babeltrace 1.5 immediately until 2.0 is eventually 
released. Follow the installation instructions 
[here](http://diamon.org/babeltrace/) to install babeltrace library as well 
as python bindings.

### Example

#### Recording a Trace
    $ sudo ./open2ctf.py
    
#### Viewing a Trace
Change ownership of trace directory to current user and use the `babeltrace` 
command to view traces as text :
 
    $ sudo chown -R suchakra:suchakra /tmp/opentrace
    $ babeltrace /tmp/opentrace 
    [11:32:19.482715248] (+0.000068367) 0 sys_open: { }, { comm = "java", filename = "/proc/self/stat", pid = 10912 }
    [11:32:19.514412607] (+0.031697359) 0 sys_open: { }, { comm = "iio-sensor-prox", filename = "/dev/iio:device1", pid = 904 }
    [11:32:19.514569626] (+0.000157019) 0 sys_open: { }, { comm = "iio-sensor-prox", filename = "/dev/iio:device2", pid = 904 }
    [11:32:19.519500964] (+0.004931338) 0 sys_open: { }, { comm = "gnome-shell", filename = "/proc/self/stat", pid = 1217 }
    [11:32:19.520207238] (+0.000706274) 0 sys_open: { }, { comm = "gnome-shell", filename = "/proc/self/stat", pid = 1824 }
    [11:32:19.526897588] (+0.006690350) 0 sys_open: { }, { comm = "gnome-settings-", filename = "/proc/self/fd", pid = 7994 }
    [11:32:19.527390265] (+0.000492677) 0 sys_open: { }, { comm = "gnome-settings-", filename = "", pid = 7994 }
    [11:32:19.537103679] (+0.009713414) 0 sys_open: { }, { comm = "gsd-backlight-h", filename = "/etc/ld.so.cache", pid = 7994 }

Though this is quite basic for now, traces can also be viewed graphically using Trace Compass :

![TC](http://step.polymtl.ca/~suchakra/opentrace_ctf.png)

#### Known Issues

* Trace streams are per-CPU, but not context information yet in CTF so we
can't see CPU in Trace Compass view.
* Time delta is OK, but timing needs to be improved
* For high frequency events, events sometimes get lost and trace is not 
recorded properly. We need to fix this soon.
