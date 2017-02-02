#!/usr/bin/env python
#
# deadlock_detector  Detects potential deadlocks (lock order inversions)
#                    on a running process. For Linux, uses BCC, eBPF.
#
# USAGE: deadlock_detector.py [-h] [--dump-graph DUMP_GRAPH]
#                             [--lock-symbols LOCK_SYMBOLS]
#                             [--unlock-symbols UNLOCK_SYMBOLS]
#                             binary pid
#
# This traces pthread mutex lock and unlock calls to build a directed graph
# representing the mutex wait graph:
#
# - Nodes in the graph represent mutexes.
# - Edge (A, B) exists if there exists some thread T where lock(A) was called
#   and lock(B) was called before unlock(A) was called.
#
# If the program finds a potential lock order inversion, the program will dump
# the cycle of mutexes and the stack traces where each mutex was acquired, and
# then exit.
#
# Note: This tool does not work for shared mutexes or recursive mutexes.
#
# For shared (read-write) mutexes, a deadlock requires a cycle in the wait
# graph where at least one of the mutexes in the cycle is acquiring exclusive
# (write) ownership.
#
# For recursive mutexes, lock() is called multiple times on the same mutex.
# However, there is no way to determine if a mutex is a recursive mutex
# after the mutex has been created. As a result, this tool will not find
# potential deadlocks that involve only one mutex.
#
# Copyright 2017 Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 01-Feb-2017   Kenny Yu   Created this.

from __future__ import (
    absolute_import, division, unicode_literals, print_function
)
from bcc import BPF
import argparse
import json
import networkx
from networkx.readwrite import json_graph
import sys
import time


def find_cycle(graph):
    '''
    Looks for a cycle in the graph. If found, returns the first cycle.
    If nodes a1, a2, ..., an are in a cycle, then this returns:

    [(a1,a2), (a2,a3), ... (an-1,an), (an, a1)]

    Otherwise returns an empty list.
    '''
    cycles = list(networkx.simple_cycles(graph))
    if cycles:
        nodes = cycles[0]
        nodes.append(nodes[0])
        edges = []
        prev = nodes[0]
        for node in nodes[1:]:
            edges.append((prev, node))
            prev = node
        return edges
    else:
        return []


def find_cycle_and_print(graph, thread_to_parent, print_stack_trace_fn):
    '''
    Detects if there is a cycle in the mutex graph. If there is, dump
    the following information and return True. Otherwise returns False.

    Potential Deadlock Detected!

    Cycle in lock order graph: M0 => M1 => M2 => M0

    for (m, n) in cycle:
        Mutex n acquired here while holding Mutex m in thread T:
            [ stack trace ]

        Mutex m previously acquired by thread T here:
            [ stack trace ]

    for T in all threads:
        Thread T was created here:
            [ stack trace ]
    '''
    edges = find_cycle(graph)
    if not edges:
        return False

    # List of mutexes in the cycle, first and last repeated
    nodes_in_order = []
    # Map mutex address -> readable alias
    node_addr_to_name = {}
    for counter, (m, n) in enumerate(edges):
        nodes_in_order.append(m)
        node_addr_to_name[m] = 'Mutex M%d (0x%016x)' % (counter, m)
    nodes_in_order.append(nodes_in_order[0])

    print('----------------\nPotential Deadlock Detected!\n')
    print(
        'Cycle in lock order graph: %s\n' %
        (' => '.join([node_addr_to_name[n] for n in nodes_in_order]))
    )

    # Set of threads involved in the lock inversion
    thread_pids = set()

    # For each edge in the cycle, print where the two mutexes were held
    for (m, n) in edges:
        thread_pid = graph[m][n]['thread_pid']
        thread_comm = graph[m][n]['thread_comm']
        first_mutex_stack_id = graph[m][n]['first_mutex_stack_id']
        second_mutex_stack_id = graph[m][n]['second_mutex_stack_id']
        thread_pids.add(thread_pid)
        print(
            '%s acquired here while holding %s in Thread %d (%s):' % (
                node_addr_to_name[n], node_addr_to_name[m], thread_pid,
                thread_comm
            )
        )
        print_stack_trace_fn(second_mutex_stack_id)
        print('')
        print(
            '%s previously acquired by the same Thread %d (%s) here:' %
            (node_addr_to_name[m], thread_pid, thread_comm)
        )
        print_stack_trace_fn(first_mutex_stack_id)
        print('')

    # Print where the threads were created, if available
    for thread_pid in thread_pids:
        parent_pid, stack_id, parent_comm = thread_to_parent.get(
            thread_pid, (None, None, None)
        )
        if parent_pid:
            print(
                'Thread %d created by Thread %d (%s) here: ' %
                (thread_pid, parent_pid, parent_comm)
            )
            print_stack_trace_fn(stack_id)
        else:
            print(
                'Could not find stack trace where Thread %d was created' %
                thread_pid
            )
        print('')
    return True


def strlist(s):
    '''
    Given a comma-separated string, returns a list of substrings
    '''
    return s.strip().split(',')


def main():
    parser = argparse.ArgumentParser(
        description=(
            'Detect potential deadlocks (lock inversions) in a running binary.'
            ' Must be run as root.'
        )
    )
    parser.add_argument('binary', type=str, help='Absolute path to binary')
    parser.add_argument('pid', type=int, help='Pid to trace')
    parser.add_argument(
        '--dump-graph',
        type=str,
        default='',
        help='If set, this will dump the mutex graph to the specified file.',
    )
    parser.add_argument(
        '--lock-symbols',
        type=strlist,
        default=['pthread_mutex_lock'],
        help='Comma-separated list of lock symbols to trace. Default is '
        'pthread_mutex_lock',
    )
    parser.add_argument(
        '--unlock-symbols',
        type=strlist,
        default=['pthread_mutex_unlock'],
        help='Comma-separated list of unlock symbols to trace. Default is '
        'pthread_mutex_unlock',
    )
    args = parser.parse_args()
    bpf = BPF(src_file='deadlock_detector.c')

    # Trace where threads are created
    bpf.attach_kretprobe(
        event='sys_clone',
        fn_name='trace_clone',
        pid=args.pid
    )

    # We must trace unlock first, otherwise in the time we attached the probe
    # on lock() and have not yet attached the probe on unlock(), a thread
    # can acquire multiple mutexes and released them, but the release
    # events will not be traced, resulting in noisy reports.
    for symbol in args.unlock_symbols:
        try:
            bpf.attach_uprobe(
                name=args.binary,
                sym=symbol,
                fn_name='trace_mutex_release',
                pid=args.pid,
            )
        except Exception as e:
            print(e)
            sys.exit(1)
    for symbol in args.lock_symbols:
        try:
            bpf.attach_uprobe(
                name=args.binary,
                sym=symbol,
                fn_name='trace_mutex_acquire',
                pid=args.pid,
            )
        except Exception as e:
            print(e)
            sys.exit(1)

    def print_stack_trace(stack_id):
        '''
        Closure that prints the symbolized stack trace. Captures: `bpf`, `args`
        '''
        for addr in bpf.get_table('stack_traces').walk(stack_id):
            line = bpf.sym(addr, args.pid)
            print('@ %016x %s' % (addr, line))

    print('Tracing... Hit Ctrl-C to end.')
    while True:
        try:
            # Mutex wait directed graph. Nodes are mutexes. Edge (A,B) exists
            # if there exists some thread T where lock(A) was called and
            # lock(B) was called before unlock(A) was called.
            graph = networkx.DiGraph()
            for key, leaf in bpf.get_table('edges').items():
                graph.add_edge(
                    key.mutex1,
                    key.mutex2,
                    thread_pid=leaf.thread_pid,
                    thread_comm=leaf.comm.decode('utf-8'),
                    first_mutex_stack_id=leaf.mutex1_stack_id,
                    second_mutex_stack_id=leaf.mutex2_stack_id,
                )
            if args.dump_graph:
                with open(args.dump_graph, 'w') as f:
                    data = json_graph.node_link_data(graph)
                    f.write(json.dumps(data, indent=2))

            # Map of child thread pid -> parent info
            thread_to_parent_dict = {
                child.value: (parent.parent_pid, parent.stack_id, parent.comm)
                for child, parent in bpf.get_table('thread_to_parent').items()
            }

            start = time.time()
            has_cycle = find_cycle_and_print(
                graph, thread_to_parent_dict, print_stack_trace
            )
            print(
                'Nodes: %d, Edges: %d, Looking for cycle took %f seconds' %
                (len(graph.nodes()), len(graph.edges()), (time.time() - start))
            )
            if has_cycle:
                sys.exit(1)

            time.sleep(1)
        except KeyboardInterrupt:
            break


if __name__ == '__main__':
    main()
