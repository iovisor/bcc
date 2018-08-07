#!/usr/bin/env python
#
# This script generates a BPF program with structure inspired by trace.py. The
# generated program operates on PID-indexed stacks. Generally speaking,
# bookkeeping is done at every intermediate function kprobe/kretprobe to enforce
# the goal of "fail iff this call chain and these predicates".
#
# Top level functions(the ones at the end of the call chain) are responsible for
# creating the pid_struct and deleting it from the map in kprobe and kretprobe
# respectively.
#
# Intermediate functions(between should_fail_whatever and the top level
# functions) are responsible for updating the stack to indicate "I have been
# called and one of my predicate(s) passed" in their entry probes. In their exit
# probes, they do the opposite, popping their stack to maintain correctness.
# This implementation aims to ensure correctness in edge cases like recursive
# calls, so there's some additional information stored in pid_struct for that.
#
# At the bottom level function(should_fail_whatever), we do a simple check to
# ensure all necessary calls/predicates have passed before error injection.
#
# Note: presently there are a few hacks to get around various rewriter/verifier
# issues.
#
# Note: this tool requires:
# - CONFIG_BPF_KPROBE_OVERRIDE
#
# USAGE: inject [-h] [-I header] [-P probability] [-v] mode spec
#
# Copyright (c) 2018 Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 16-Mar-2018   Howard McLauchlan   Created this.

import argparse
import re
from bcc import BPF


class Probe:
    errno_mapping = {
        "kmalloc": "-ENOMEM",
        "bio": "-EIO",
    }

    @classmethod
    def configure(cls, mode, probability):
        cls.mode = mode
        cls.probability = probability

    def __init__(self, func, preds, length, entry):
        # length of call chain
        self.length = length
        self.func = func
        self.preds = preds
        self.is_entry = entry

    def _bail(self, err):
        raise ValueError("error in probe '%s': %s" %
                (self.spec, err))

    def _get_err(self):
        return Probe.errno_mapping[Probe.mode]

    def _get_if_top(self):
        # ordering guarantees that if this function is top, the last tup is top
        chk = self.preds[0][1] == 0
        if not chk:
            return ""

        if Probe.probability == 1:
            early_pred = "false"
        else:
            early_pred = "bpf_get_prandom_u32() > %s" % str(int((1<<32)*Probe.probability))
        # init the map
        # dont do an early exit here so the singular case works automatically
        # have an early exit for probability option
        enter = """
        /*
         * Early exit for probability case
         */
        if (%s)
               return 0;
        /*
         * Top level function init map
         */
        struct pid_struct p_struct = {0, 0};
        m.insert(&pid, &p_struct);
        """ % early_pred

        # kill the entry
        exit = """
        /*
         * Top level function clean up map
         */
        m.delete(&pid);
        """

        return enter if self.is_entry else exit

    def _get_heading(self):

        # we need to insert identifier and ctx into self.func
        # gonna make a lot of formatting assumptions to make this work
        left = self.func.find("(")
        right = self.func.rfind(")")

        # self.event and self.func_name need to be accessible
        self.event = self.func[0:left]
        self.func_name = self.event + ("_entry" if self.is_entry else "_exit")
        func_sig = "struct pt_regs *ctx"

        # assume theres something in there, no guarantee its well formed
        if right > left + 1 and self.is_entry:
            func_sig += ", " + self.func[left + 1:right]

        return "int %s(%s)" % (self.func_name, func_sig)

    def _get_entry_logic(self):
        # there is at least one tup(pred, place) for this function
        text = """

        if (p->conds_met >= %s)
                return 0;
        if (p->conds_met == %s && %s) {
                p->stack[%s] = p->curr_call;
                p->conds_met++;
        }"""
        text = text % (self.length, self.preds[0][1], self.preds[0][0],
                self.preds[0][1])

        # for each additional pred
        for tup in self.preds[1:]:
            text += """
        else if (p->conds_met == %s && %s) {
                p->stack[%s] = p->curr_call;
                p->conds_met++;
        }
            """ % (tup[1], tup[0], tup[1])
        return text

    def _generate_entry(self):
        prog = self._get_heading() + """
{
        u32 pid = bpf_get_current_pid_tgid();
        %s

        struct pid_struct *p = m.lookup(&pid);

        if (!p)
                return 0;

        /*
         * preparation for predicate, if necessary
         */
         %s
        /*
         * Generate entry logic
         */
        %s

        p->curr_call++;

        return 0;
}"""

        prog = prog % (self._get_if_top(), self.prep, self._get_entry_logic())
        return prog

    # only need to check top of stack
    def _get_exit_logic(self):
        text = """
        if (p->conds_met < 1 || p->conds_met >= %s)
                return 0;

        if (p->stack[p->conds_met - 1] == p->curr_call)
                p->conds_met--;
        """
        return text % str(self.length + 1)

    def _generate_exit(self):
        prog = self._get_heading() + """
{
        u32 pid = bpf_get_current_pid_tgid();

        struct pid_struct *p = m.lookup(&pid);

        if (!p)
                return 0;

        p->curr_call--;

        /*
         * Generate exit logic
         */
        %s
        %s
        return 0;
}"""

        prog = prog % (self._get_exit_logic(), self._get_if_top())

        return prog

    # Special case for should_fail_whatever
    def _generate_bottom(self):
        pred = self.preds[0][0]
        text = self._get_heading() + """
{
        /*
         * preparation for predicate, if necessary
         */
         %s
        /*
         * If this is the only call in the chain and predicate passes
         */
        if (%s == 1 && %s) {
                bpf_override_return(ctx, %s);
                return 0;
        }
        u32 pid = bpf_get_current_pid_tgid();

        struct pid_struct *p = m.lookup(&pid);

        if (!p)
                return 0;

        /*
         * If all conds have been met and predicate passes
         */
        if (p->conds_met == %s && %s)
                bpf_override_return(ctx, %s);
        return 0;
}"""
        return text % (self.prep, self.length, pred, self._get_err(),
                    self.length - 1, pred, self._get_err())

    # presently parses and replaces STRCMP
    # STRCMP exists because string comparison is inconvenient and somewhat buggy
    # https://github.com/iovisor/bcc/issues/1617
    def _prepare_pred(self):
        self.prep = ""
        for i in range(len(self.preds)):
            new_pred = ""
            pred = self.preds[i][0]
            place = self.preds[i][1]
            start, ind = 0, 0
            while start < len(pred):
                ind = pred.find("STRCMP(", start)
                if ind == -1:
                    break
                new_pred += pred[start:ind]
                # 7 is len("STRCMP(")
                start = pred.find(")", start + 7) + 1

                # then ind ... start is STRCMP(...)
                ptr, literal = pred[ind + 7:start - 1].split(",")
                literal = literal.strip()

                # x->y->z, some string literal
                # we make unique id with place_ind
                uuid = "%s_%s" % (place, ind)
                unique_bool = "is_true_%s" % uuid
                self.prep += """
        char *str_%s = %s;
        bool %s = true;\n""" % (uuid, ptr.strip(), unique_bool)

                check = "\t%s &= *(str_%s++) == '%%s';\n" % (unique_bool, uuid)

                for ch in literal:
                    self.prep += check % ch
                self.prep += check % r'\0'
                new_pred += unique_bool

            new_pred += pred[start:]
            self.preds[i] = (new_pred, place)

    def generate_program(self):
        # generate code to work around various rewriter issues
        self._prepare_pred()

        # special case for bottom
        if self.preds[-1][1] == self.length - 1:
            return self._generate_bottom()

        return self._generate_entry() if self.is_entry else self._generate_exit()

    def attach(self, bpf):
        if self.is_entry:
            bpf.attach_kprobe(event=self.event,
                    fn_name=self.func_name)
        else:
            bpf.attach_kretprobe(event=self.event,
                    fn_name=self.func_name)


class Tool:

    examples ="""
EXAMPLES:
# ./inject.py kmalloc -v 'SyS_mount()'
    Fails all calls to syscall mount
# ./inject.py kmalloc -v '(true) => SyS_mount()(true)'
    Explicit rewriting of above
# ./inject.py kmalloc -v 'mount_subtree() => btrfs_mount()'
    Fails btrfs mounts only
# ./inject.py kmalloc -v 'd_alloc_parallel(struct dentry *parent, const struct \\
    qstr *name)(STRCMP(name->name, 'bananas'))'
    Fails dentry allocations of files named 'bananas'
# ./inject.py kmalloc -v -P 0.01 'SyS_mount()'
    Fails calls to syscall mount with 1% probability
    """
    # add cases as necessary
    error_injection_mapping = {
        "kmalloc": "should_failslab(struct kmem_cache *s, gfp_t gfpflags)",
        "bio": "should_fail_bio(struct bio *bio)",
    }

    def __init__(self):
        parser = argparse.ArgumentParser(description="Fail specified kernel" +
                " functionality when call chain and predicates are met",
                formatter_class=argparse.RawDescriptionHelpFormatter,
                epilog=Tool.examples)
        parser.add_argument(dest="mode", choices=['kmalloc','bio'],
                help="indicate which base kernel function to fail")
        parser.add_argument(metavar="spec", dest="spec",
                help="specify call chain")
        parser.add_argument("-I", "--include", action="append",
                metavar="header",
                help="additional header files to include in the BPF program")
        parser.add_argument("-P", "--probability", default=1,
                metavar="probability", type=float,
                help="probability that this call chain will fail")
        parser.add_argument("-v", "--verbose", action="store_true",
                help="print BPF program")
        self.args = parser.parse_args()

        self.program = ""
        self.spec = self.args.spec
        self.map = {}
        self.probes = []
        self.key = Tool.error_injection_mapping[self.args.mode]

    # create_probes and associated stuff
    def _create_probes(self):
        self._parse_spec()
        Probe.configure(self.args.mode, self.args.probability)
        # self, func, preds, total, entry

        # create all the pair probes
        for fx, preds in self.map.items():

            # do the enter
            self.probes.append(Probe(fx, preds, self.length, True))

            if self.key == fx:
                continue

            # do the exit
            self.probes.append(Probe(fx, preds, self.length, False))

    def _parse_frames(self):
        # sentinel
        data = self.spec + '\0'
        start, count = 0, 0

        frames = []
        cur_frame = []
        i = 0
        last_frame_added = 0

        while i < len(data):
            # improper input
            if count < 0:
                raise Exception("Check your parentheses")
            c = data[i]
            count += c == '('
            count -= c == ')'
            if not count:
                if c == '\0' or (c == '=' and data[i + 1] == '>'):
                    # This block is closing a chunk. This means cur_frame must
                    # have something in it.
                    if not cur_frame:
                        raise Exception("Cannot parse spec, missing parens")
                    if len(cur_frame) == 2:
                        frame = tuple(cur_frame)
                    elif cur_frame[0][0] == '(':
                        frame = self.key, cur_frame[0]
                    else:
                        frame = cur_frame[0], '(true)'
                    frames.append(frame)
                    del cur_frame[:]
                    i += 1
                    start = i + 1
                elif c == ')':
                    cur_frame.append(data[start:i + 1].strip())
                    start = i + 1
                    last_frame_added = start
            i += 1

        # We only permit spaces after the last frame
        if self.spec[last_frame_added:].strip():
            raise Exception("Invalid characters found after last frame");
        # improper input
        if count:
            raise Exception("Check your parentheses")
        return frames

    def _parse_spec(self):
        frames = self._parse_frames()
        frames.reverse()

        absolute_order = 0
        for f in frames:
            # default case
            func, pred = f[0], f[1]

            if not self._validate_predicate(pred):
                raise Exception("Invalid predicate")
            if not self._validate_identifier(func):
                raise Exception("Invalid function identifier")
            tup = (pred, absolute_order)

            if func not in self.map:
                self.map[func] = [tup]
            else:
                self.map[func].append(tup)

            absolute_order += 1

        if self.key not in self.map:
            self.map[self.key] = [('(true)', absolute_order)]
            absolute_order += 1

        self.length = absolute_order

    def _validate_identifier(self, func):
        # We've already established paren balancing. We will only look for
        # identifier validity here.
        paren_index = func.find("(")
        potential_id = func[:paren_index]
        pattern = '[_a-zA-z][_a-zA-Z0-9]*$'
        if re.match(pattern, potential_id):
            return True
        return False

    def _validate_predicate(self, pred):

        if len(pred) > 0 and pred[0] == "(":
            open = 1
            for i in range(1, len(pred)):
                if pred[i] == "(":
                    open += 1
                elif pred[i] == ")":
                    open -= 1
            if open != 0:
                # not well formed, break
                return False

        return True

    def _def_pid_struct(self):
        text = """
struct pid_struct {
    u64 curr_call; /* book keeping to handle recursion */
    u64 conds_met; /* stack pointer */
    u64 stack[%s];
};
""" % self.length
        return text

    def _attach_probes(self):
        self.bpf = BPF(text=self.program)
        for p in self.probes:
            p.attach(self.bpf)

    def _generate_program(self):
        # leave out auto includes for now
        self.program += '#include <linux/mm.h>\n'
        for include in (self.args.include or []):
            self.program += "#include <%s>\n" % include

        self.program += self._def_pid_struct()
        self.program += "BPF_HASH(m, u32, struct pid_struct);\n"
        for p in self.probes:
            self.program += p.generate_program() + "\n"

        if self.args.verbose:
            print(self.program)

    def _main_loop(self):
        while True:
            self.bpf.perf_buffer_poll()

    def run(self):
        self._create_probes()
        self._generate_program()
        self._attach_probes()
        self._main_loop()


if __name__ == "__main__":
    Tool().run()
