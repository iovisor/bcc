# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#
# Antonin Bas (antonin@barefootnetworks.com)
#
#

# -*- coding: utf-8 -*-


class Node(object):
    def __init__(self, n):
        self.n = n
        self.edges = set()

    def add_edge_to(self, other):
        assert(isinstance(other, Node))
        self.edges.add(other)

    def __str__(self):
        return str(self.n)


class Graph(object):
    def __init__(self):
        self.nodes = {}
        self.root = None

    def add_node(self, node):
        assert(node not in self.nodes)
        self.nodes[node] = Node(node)

    def __contains__(self, node):
        return node in self.nodes

    def get_node(self, node):
        return self.nodes[node]

    def produce_topo_sorting(self):
        def visit(node, topo_sorting, sequence=None):
            if sequence is not None:
                sequence += [str(node)]
            if node._behavioral_topo_sorting_mark == 1:
                if sequence is not None:
                    print "cycle", sequence
                return False
            if node._behavioral_topo_sorting_mark != 2:
                node._behavioral_topo_sorting_mark = 1
                for next_node in node.edges:
                    res = visit(next_node, topo_sorting, sequence)
                    if not res:
                        return False
                node._behavioral_topo_sorting_mark = 2
                topo_sorting.insert(0, node.n)
            return True

        has_cycle = False
        topo_sorting = []

        for node in self.nodes.values():
            # 0 is unmarked, 1 is temp, 2 is permanent
            node._behavioral_topo_sorting_mark = 0
        for node in self.nodes.values():
            if node._behavioral_topo_sorting_mark == 0:
                if not visit(node, topo_sorting, sequence=[]):
                    has_cycle = True
                    break
        # removing mark
        for node in self.nodes.values():
            del node._behavioral_topo_sorting_mark

        if has_cycle:
            return None

        return topo_sorting
