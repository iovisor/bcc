#!/bin/bash
lib=$(dirname $0)/lib
$lib/uflow.py -l php "$@"
