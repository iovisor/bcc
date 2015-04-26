#!/usr/bin/env python
import sys
from src.bpf import BPF
prog = BPF(sys.argv[1], sys.argv[2], sys.argv[3],
        prog_type=int(sys.argv[4]), debug=int(sys.argv[5]))

