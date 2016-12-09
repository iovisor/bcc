This folder contains tests for the P4->C->EBPF compiler

- cleanup.sh should be run if for some reason endToEndTest.py crashes
  and leaves garbage namespaces or links

- testP4toEbpf.py compiles all P4 files in the testprograms folder and
  deposits the corresponding C files in the testoutputs folder

- endToEndTest.py runs a complete end-to-end test compiling the
  testprograms/simple.p4 program, creating a virtual network with 3
  boxes (using network namespaces): client, server, switch, loading
  the EBPF into the kernel of the switch box using the TC, and
  implementing the forwarding in the switch solely using the P4
  program.
  
  
