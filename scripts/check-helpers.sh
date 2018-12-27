#!/bin/bash
ret=0

libbpf=$(grep -oP '(?<={")\w+(?=", "\d\.\d+")' src/cc/libbpf.c | sort)
doc=$(grep -oP "(?<=BPF_FUNC_)\w+" docs/kernel-versions.md | sort)
dif=$(diff <(echo "$doc") <(echo "$libbpf"))
if [ $? -ne 0 ]; then
	echo "The lists of helpers in src/cc/libbpf.c and docs/kernel-versions.md differ:"
	echo -e "$dif\n"
	((ret++))
fi

compat=$(grep -oP "(?<=^\sFN\()\w+" src/cc/compat/linux/bpf.h | tail -n +2 | sort)
dif=$(diff <(echo "$doc") <(echo "$compat"))
if [ $? -ne 0 ]; then
	echo "The lists of helpers in docs/kernel-versions.md and src/cc/compat/linux/bpf.h differ:"
	echo -e "$dif\n"
	((ret++))
fi

virtual=$(grep -oP "(?<=^\sFN\()\w+" src/cc/compat/linux/virtual_bpf.h | tail -n +2 | sort -u)
dif=$(diff <(echo "$compat") <(echo "$virtual"))
if [ $? -ne 0 ]; then
	echo "The lists of helpers in src/cc/compat/linux/bpf.h and src/cc/compat/linux/virtual_bpf.h differ:"
	echo "$dif"
	((ret++))
fi

export=$(grep -oP "(?<=BPF_FUNC_)\w+" src/cc/export/helpers.h | sort -u)
dif=$(diff <(echo "$compat") <(echo "$export"))
if [ $? -ne 0 ]; then
	echo "The lists of helpers in src/cc/compat/linux/bpf.h and src/cc/export/helpers.h differ:"
	echo "$dif"
	((ret++))
fi

exit $ret
