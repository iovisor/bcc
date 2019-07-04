#!/bin/bash

set -euo pipefail

# TODO: stop ignoring the issues in .flake8. Maybe autopep8, python/black, or yapf the codebase?
flake8 . || echo "flake8 run failed, please fix it" >&2

NO_PROPER_SHEBANG="$(find tools examples -type f -executable -name '*.py' | xargs grep -L '#!/usr/bin/python')"
if [ -n "$NO_PROPER_SHEBANG" ]; then
    echo "bad shebangs found:"
    echo "$NO_PROPER_SHEBANG"
    echo
    echo "either add proper shebang or remove executable bit" >&2

    exit 1
fi
