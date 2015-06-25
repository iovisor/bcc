#!/bin/bash
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# this script:
#  1. checks for bower to be installed
#  2. clones the chord-transitions UI from github
#  3. installs locally the packages required by the UI

function which_() { hash "$1" &>/dev/null; }

if [[ ! -d chord-transitions ]]; then
  git clone https://github.com/iovisor/chord-transitions.git
fi

cd chord-transitions

export PATH=node_modules/.bin:$PATH

if ! which_ bower; then
  if ! which_ npm; then
    echo "Error: required binary 'npm' not found, please install nodejs"
    exit 1
  fi
  npm install bower
fi

if [[ "$(id -u)" = "0" ]]; then
  args="--allow-root"
fi

bower install $args
