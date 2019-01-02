#!/bin/bash

set -euo pipefail

# TODO: stop ignoring this. Maybe autopep8 existing stuff?
find tools -type f -name "*.py" | xargs pep8 -r --show-source --ignore=E123,E125,E126,E127,E128,E302 || \
    echo "pep8 run failed, please fix it" >&2
