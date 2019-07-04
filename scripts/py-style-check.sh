#!/bin/bash

set -euo pipefail

# TODO: stop ignoring this. Maybe autopep8 existing stuff?
find tools -type f -name "*.py" | xargs flake8 || echo "flake8 run failed, please fix it" >&2
flake8 . || echo "flake8 run failed, please fix it" >&2

NO_PROPER_SHEBANG="$(find tools examples -type f -executable -name '*.py' | xargs grep -L '#!/usr/bin/python')"
if [ -n "$NO_PROPER_SHEBANG" ]; then
    echo "bad shebangs found:"
    echo "$NO_PROPER_SHEBANG"
    echo
    echo "either add proper shebang or remove executable bit" >&2

    exit 1
fi
