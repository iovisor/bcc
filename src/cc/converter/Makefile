.PHONY: build
build: bcc-front
	./bcc-front source.bcc.c 1>source_rewrite.bcc.c
	clang -E -P -C -nostdinc source_rewrite.bcc.c 1> pre_output.bpf.c || true
	cat libbpf_include.c > output.bpf.c
	cat pre_output.bpf.c >> output.bpf.c
	# clang-format -i output.bpf.c

bcc-front:
	mkdir -p ../../../build
	cd ../../../build && cmake ..
	make -C ../../../build
	cp ../../../build/examples/cpp/ConvertBCCtoLibbbpf bcc-front
