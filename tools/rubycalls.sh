#!/bin/bash
lib=$(dirname $0)/lib
$lib/ucalls.py -l ruby "$@"
