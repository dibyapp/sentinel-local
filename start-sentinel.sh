#!/bin/sh
set -eu
task_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
task_python="$task_dir/.venv/bin/python"
if [ ! -x "$task_python" ]; then task_python=python3; fi
if ! "$task_python" -c 'import psutil' >/dev/null 2>&1; then
    echo 'Setup needed: install Python 3.11+ and run python3 -m pip install -r requirements.txt in this folder.' >&2
    exit 1
fi
exec "$task_python" "$task_dir/app.py" --open "$@"
