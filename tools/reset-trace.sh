#!/bin/bash
#
# reset-trace - reset state of tracing, disabling all tracing.
#               Written for Linux.
#
# If a bcc tool crashed and you suspect tracing is partially enabled, you
# can use this tool to reset the state of tracing, disabling anything still
# enabled. Only use this tool in the case of error, and, consider filing a
# bcc ticket so we can fix the error.
#
# bcc-used tracing facilities are reset. Other tracing facilities (ftrace) are
# checked, and if not in an expected state, a note is printed. All tracing
# files can be reset with -F for force, but this will interfere with any other
# running tracing sessions (eg, ftrace).
#
# USAGE: ./reset-trace [-Fhqv]
#
# REQUIREMENTS: debugfs mounted on /sys/kernel/debug
#
# COPYRIGHT: Copyright (c) 2016 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 20-Jul-2014	Brendan Gregg	Created this.
# 18-Oct-2016      "      "     Updated for bcc use.

tracing=/sys/kernel/debug/tracing
opt_force=0; opt_verbose=0; opt_quiet=0

function usage {
	cat <<-END >&2
	USAGE: reset-trace [-Fhqv]
	                 -F             # force: reset all tracing files
	                 -v             # verbose: print details while working
	                 -h             # this usage message
	                 -q             # quiet: no output
	  eg,
	       reset-trace              # disable semi-enabled tracing
END
	exit
}

function die {
	echo >&2 "$@"
	exit 1
}

function vecho {
	(( ! opt_verbose )) && return
	echo "$@"
}

function writefile {
	file=$1
	write=$2
	if [[ ! -w $file ]]; then
		echo >&2 "WARNING: file $file not writable/exists. Skipping."
		return
	fi

	vecho "Checking $PWD/$file"
        contents=$(grep -v '^#' $file)
	if [[ "$contents" != "$expected" ]]; then
		(( ! opt_quiet )) && echo "Needed to reset $PWD/$file"
		vecho "$file, before (line enumerated):"
		(( opt_verbose )) && cat -nv $file
		cmd="echo $write > $file"
		if ! eval "$cmd"; then
			echo >&2 "WARNING: command failed \"$cmd\"." \
			    "bcc still running? Continuing."
		fi
		vecho "$file, after (line enumerated):"
		(( opt_verbose )) && cat -nv $file
		vecho
	fi
}

# only write when force is used
function checkfile {
	file=$1
	write=$2
	expected=$3
	if [[ ! -e $file ]]; then
		echo >&2 "WARNING: file $file doesn't exist. Skipping."
		return
	fi
	if (( opt_force )); then
		writefile $file $write
		return
	fi
	(( opt_quiet )) && return

	vecho "Checking $PWD/$file"
        contents=$(grep -v '^#' $file)
	if [[ "$contents" != "$expected" ]]; then
		echo "Noticed unrelated tracing file $PWD/$file isn't set as" \
		    "expected. Not reseting (-F to force, -v for verbose)."
		vecho "Contents of $file is (line enumerated):"
		(( opt_verbose )) && cat -nv $file
		vecho "Expected \"$expected\"."
	fi
}

### process options
while getopts Fhqv opt
do
	case $opt in
	F)	opt_force=1 ;;
	q)	opt_quiet=1 ;;
	v)	opt_verbose=1 ;;
	h|?)	usage ;;
	esac
done
shift $(( $OPTIND - 1 ))

### reset tracing state
vecho "Reseting tracing state..."
vecho
cd $tracing || die "ERROR: accessing tracing. Root user? /sys/kernel/debug?"

# files bcc uses
writefile kprobe_events "" ""
writefile uprobe_events "" ""
writefile trace "" ""         # clears trace_pipe

# non-bcc files
checkfile current_tracer nop nop
checkfile set_ftrace_filter "" ""
checkfile set_graph_function "" ""
checkfile set_ftrace_pid "" "no pid"
checkfile events/enable 0 0
checkfile tracing_thresh 0 0
checkfile tracing_on 1 1

vecho
vecho "Done."
