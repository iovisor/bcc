#!/bin/bash
lib=$(dirname $0)/lib
$lib/ustat.py -l php "$@"
