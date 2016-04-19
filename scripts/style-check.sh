#!/bin/bash

# Runs clang-format on the files changed between HEAD and $1, which defaults to
# origin/master.

# to pick up git-clang-format from scripts/
export PATH=$(dirname $0):$PATH

CLANG_FORMAT=${CLANG_FORMAT:-clang-format}
GITREF=${1:-origin/master}

if ! hash $CLANG_FORMAT 2> /dev/null; then
  echo "Could not find clang-format tool" 1>&2
  exit 1
fi

cmd="git clang-format $GITREF --binary $CLANG_FORMAT --diff --extensions h,c,cc"

n=$($cmd --quiet | wc -l)
if [ $n -gt 0 ]; then
  $cmd -v
  exit 1
fi
