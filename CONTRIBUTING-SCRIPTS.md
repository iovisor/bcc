# Contributing bcc/eBPF scripts

If you want to contribute scripts to bcc, or improve your own bcc programs, great! Please read this first.

_(Written by Brendan Gregg.)_

## Type of script

bcc has 2 types of scripts, in different directories:

- **/examples**: intended as short examples of bcc & eBPF code. You should focus on keeping it short, neat, and documented (code comments). A submission can just be the example code.
- **/tools**: intended as production safe performance and troubleshooting tools. You should focus on it being useful, tested, low overhead, documented (incl. all caveats), and easy to use. A submission should involve 4 changes: the tool, a man page, an example file, and an addition to README.md. Follow [my lead](https://github.com/brendangregg/bcc/commit/9fa156273b395cfc5505f0fff5d6b7b1396f7daa), and see the checklist below. These will be run in mission critical environments as root, so if spending hours testing isn't for you, please submit your idea as an issue instead, or chat with us on irc.

More detail for each below.

## Examples

These are grouped into subdirectories (networking, tracing). Your example can either be a Python program with embedded C (eg, tracing/strlen_count.py), or separate Python and C files (eg, tracing/vfsreadlat.*).

As said earlier: keep it short, neat, and documented (code comments).

## Tools

A checklist for bcc tool development:

1. **Research the topic landscape**. Learn the existing tools and metrics (incl. from /proc). Determine what real world problems exist and need solving. We have too many tools and metrics as it is, we don't need more "I guess that's useful" tools, we need more "ah-hah! I couldn't do this before!" tools. Consider asking other developers about your idea. Many of us can be found in IRC, in the #iovisor channel on irc.oftc.net. There's also the mailing list (see the README.md), and github for issues.
1. **Create a known workload for testing**. This might involving writing a 10 line C program, using a micro-benchmark, or just improvising at the shell. If you don't know how to create a workload, learn! Figuring this out will provide invaluable context and details that you may have otherwise overlooked. Sometimes it's easy, and I'm able to just use dd(1) from /dev/urandom or a disk device to /dev/null. It lets me set the I/O size, count, and provides throughput statistics for cross-checking my tool output. But other times I need a micro-benchmark, or some C.
1. **Write the tool to solve the problem and no more**. Unix philosophy: do one thing and do it well. netstat doesn't have an option to dump packets, tcpdump-style. They are two different tools.
1. **Check your tool correctly measures your known workload**. If possible, run a prime number of events (eg, 23) and check that the numbers match. Try other workload variations.
1. **Use other observability tools to perform a cross-check or sanity check**. Eg, imagine you write a PCI bus tool that shows current throughput is 28 Gbytes/sec. How could you sanity test that? Well, what PCI devices are there? Disks and network cards? Measure their throughput (iostat, nicstat, sar), and check if is in the ballpark of 28 Gbytes/sec (which would include PCI frame overheads). Ideally, your numbers match.
1. **Measure the overhead of the tool**. If you are running a micro-benchmark, how much slower is it with the tool running. Is more CPU consumed? Try to determine the worst case: run the micro-benchmark so that CPU headroom is exhausted, and then run the bcc tool. Can overhead be lowered?
1. **Test again, and stress test**. You want to discover and fix all the bad things before others hit them.
1. **Consider command line options**. Should it have -p for filtering on a PID? -T for timestamps? -i for interval? See other tools for examples, and copy the style: the usage message should list example usage at the end. Remember to keep the tool doing one thing and doing it well. Also, if there's one option that seems to be the common case, perhaps it should just be the first argument and not need a switch (no -X). A special case of this is *stat tools, like iostat/vmstat/etc, where the convention is [interval [count]].
1. **Concise, intuitive, self-explanatory output**. The default output should meet the common need concisely. Leave much less useful fields and data to be shown with options: -v for verbose, etc. Consider including a startup message that's self-explanatory, eg "Tracing block I/O. Output every 1 seconds. Ctrl-C to end.". Also, try hard to keep the output less than 80 characters wide, especially the default output of the tool. That way, the output not only fits on the smallest reasonable terminal, it also fits well in slide decks, blog posts, articles, and printed material, all of which help education and adoption. Publishers of technical books often have templates they require books to conform to: it may not be an option to shrink or narrow the font to fit your output.
1. **Use pep8 to check Python style**: pep8 --show-source --ignore=E123,E125,E126,E127,E128,E302 filename . Note that it misses some things, like consistent usage, so you'll still need to double check your script.
1. **Make sure your script is Python3-ready**: Adding `from __future__ import absolute_import, division, print_function, unicode_literals` helps make your script Python3-ready.
1. **Write an _example.txt file**. Copy the style in tools/biolatency_example.txt: start with an intro sentence, then have examples, and finish with the USAGE message. Explain everything: the first example should explain what we are seeing, even if this seems obvious. For some people it won't be obvious. Also explain why we are running the tool: what problems it's solving. It can take a long time (hours) to come up with good examples, but it's worth it. These will get copied around (eg, presentations, articles).
1. **Read your example.txt file**. Does this sound too niche or convoluted? Are you spending too much time explaining caveats? These can be hints that perhaps you should fix your tool, or abandon it! Perhaps it better belongs as an /example, and not a tool. I've abandoned many tools at this stage.
1. **Write a man page**. Either ROFF (.8), markdown (.md), or plain text (.txt): so long as it documents the important sections, particularly columns (fields) and caveats. These go under man/man8. See the other examples. Include a section on overhead, and pull no punches. It's better for end users to know about high overhead beforehand, than to discover it the hard way. Also explain caveats. Don't assume those will be obvious to tool users.
1. **Read your man page**. For ROFF: nroff -man filename. Like before, this exercise is like saying something out loud. Does it sound too niche or convoluted? Again, hints that you might need to go back and fix things, or abandon it.
1. **Spell check your documentation**. Use a spell checker like aspell to check your document quality before committing.
1. **Add an entry to README.md**.
1. **Add a smoke test** to [test_tools_smoke.py](https://github.com/iovisor/bcc/blob/master/tests/python/test_tools_smoke.py), which serves as a basic check that your tool still works when we make changes to the core library.
1. If you made it this far, pull request!
