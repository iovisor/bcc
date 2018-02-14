#!/bin/bash
ret=0

grep -oP '(?<={")\w+(?=", "\d\.\d+")' src/cc/libbpf.c | sort > /tmp/libbpf.txt
grep -oP "(?<=BPF_FUNC_)\w+" docs/kernel-versions.md | sort > /tmp/doc.txt
dif=`diff /tmp/libbpf.txt /tmp/doc.txt`
if [ $? -ne 0 ]; then
	echo "The lists of helpers in src/cc/libbpf.c and docs/kernel-versions.md differ:"
	echo -e "$dif\n"
	((ret++))
fi

grep -oP "(?<=^\sFN\()\w+" src/cc/compat/linux/bpf.h | tail -n +2 | sort > /tmp/compat.txt
dif=`diff /tmp/doc.txt /tmp/compat.txt`
if [ $? -ne 0 ]; then
	echo "The lists of helpers in docs/kernel-versions.md and src/cc/compat/linux/bpf.h differ:"
	echo -e "$dif\n"
	((ret++))
fi

grep -oP "(?<=BPF_FUNC_)\w+" src/cc/export/helpers.h | sort -u > /tmp/export.txt
dif=`diff /tmp/compat.txt /tmp/export.txt`
if [ $? -ne 0 ]; then
	echo "The lists of helpers in src/cc/compat/linux/bpf.h and src/cc/export/helpers.h differ:"
	echo "$dif"
	((ret++))
fi

exit $ret
