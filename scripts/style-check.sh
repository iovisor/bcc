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

n=$(git clang-format $GITREF --binary $CLANG_FORMAT --style llvm --diff --quiet | wc -l)
if [ $n -gt 0 ]; then
  echo "git clang-format $GITREF --binary $CLANG_FORMAT --style llvm --diff"
  echo
  git clang-format $GITREF --binary $CLANG_FORMAT --style llvm --diff
  echo
  echo "clang-format returned non-empty diff, please fixup the style" 1>&2
  exit 1
fi
