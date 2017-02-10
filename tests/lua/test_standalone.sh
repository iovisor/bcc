#!/bin/bash
# Copyright (c) GitHub, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

set -xe
cd "src/lua"

function fail {
    echo "test failed: $1" >&2
    exit 1
}

if [[ ! -x bcc-lua ]]; then
    echo "bcc-lua not built --- skipping"
    exit 0
fi

if ldd bcc-lua | grep -q luajit; then
    fail "bcc-lua depends on libluajit"
fi

rm -f probe.lua
echo "return function(BPF) print(\"Hello world\") end" > probe.lua

PROBE="../../../examples/lua/offcputime.lua"

if ! sudo ./bcc-lua "$PROBE" -d 1 >/dev/null 2>/dev/null; then
    fail "bcc-lua cannot run complex probes"
fi

rm -f libbcc.so probe.lua
