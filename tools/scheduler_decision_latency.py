#!/usr/bin/python
# scheduler_decision_latency    collect stats for scheduler and decision latencies
#                                across the entire system or for a specific comm
#
# scheduler latency is the amount of time a task waits on a cpu before it actually
# gets a chance to run.
#
# decision latency is the time taken by the cpu to decide on which cpu the task
# needs to be woken up.
#
# USAGE: scheduler_decision_latency.py [-h] [-c COMM]
#
# 23-Aug-2023 Madadi Vineeth Reddy created this.

import argparse
from bcc import BPF
import math
import signal

print("Press ctrl-c to end")

parser = argparse.ArgumentParser()
parser.add_argument('-c','--comm',help="Collects stats only for the comm specified",default="")
args = parser.parse_args()

b = BPF(text="""
#include <linux/sched.h>
BPF_HASH(sl_ptime);
BPF_HASH(dl_ptime);
struct sl_data {
    u64 sched_latency;
    char comm[TASK_COMM_LEN];
};
struct dl_data {
    u64 dec_latency;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(sl_events);
BPF_PERF_OUTPUT(dl_events);
TRACEPOINT_PROBE(sched,sched_waking)
{
    u64 time = bpf_ktime_get_ns();
    time = time / 1000;
    u64 proc_id = args->pid;
    dl_ptime.update(&proc_id,&time);
    return 0; 
}

TRACEPOINT_PROBE(sched,sched_wakeup)
{
    u64 time = bpf_ktime_get_ns();
    time = time / 1000;
    u64 proc_id = args->pid;
    sl_ptime.update(&proc_id,&time);
    struct dl_data data = {};
    u64 *dat;
    dat = dl_ptime.lookup(&proc_id);
    bpf_probe_read_kernel_str(&data.comm,sizeof(data.comm),args->comm);
    if (dat)
    {
        time = time - *dat;
        data.dec_latency = time;
        dl_events.perf_submit(args,&data,sizeof(data));
        dl_ptime.delete(&proc_id);
    }
    return 0; 
}

TRACEPOINT_PROBE(sched,sched_switch)
{
    u64 time = bpf_ktime_get_ns(); 
    struct sl_data data = {};
    time = time/1000;
    u64 *dat;
    u64 proc_id = args->next_pid;
    dat = sl_ptime.lookup(&proc_id);
    bpf_probe_read_kernel_str(&data.comm,sizeof(data.comm),args->next_comm);
    if (dat)
    {
        time = time - *dat;
        data.sched_latency = time;
        sl_events.perf_submit(args,&data,sizeof(data));
        sl_ptime.delete(&proc_id);
    }
    return 0;
}
""")

def print_percentile(type_check,final_wt):
    for val in [50,90,95,99,99.99]:
        ind = int(math.ceil(len(final_wt)*(val/100)))-1
        print (f"The {val}th %ile {type_check} latency is {round(final_wt[ind], 3)} microseconds")

scheduler_latency = []
decision_latency = []

def print_event(cpu, data, size):
    global scheduler_latency
    event = b["sl_events"].event(data)
    if ((args.comm != "" and args.comm == event.comm.decode()) or (args.comm == "")):
        scheduler_latency.append(event.sched_latency);

def print_now(cpu, data, size):
    global decision_latency
    event = b["dl_events"].event(data)
    if ((args.comm != "" and args.comm == event.comm.decode()) or (args.comm == "")):
        decision_latency.append(event.dec_latency);

b["sl_events"].open_perf_buffer(print_event)
b["dl_events"].open_perf_buffer(print_now)
done = 0

def calculate_stats(latency_type,label):
    if len(latency_type) > 2:
        print (f"The minimum and maximum {label} latency is",round(min(latency_type),3),"and",
               round(max(latency_type),3),"microseconds");
        average = sum(latency_type)/(len(latency_type))
        print (f"The avg {label} latency is",round(average,3), "microseconds")
        latency_type.sort()
        print_percentile(label,latency_type);
    else:
        print (f"No {label} latency as number of records are less than 3")

def handler(signum, frame):
    global scheduler_latency,decision_latency,done
    calculate_stats(scheduler_latency,"scheduler")
    print()
    calculate_stats(decision_latency,"decision")
    done = 1
signal.signal(signal.SIGINT, handler)

while 1:
    b.perf_buffer_poll()
    if(done == 1):
        break
