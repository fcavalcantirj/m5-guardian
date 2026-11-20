#!/bin/sh
set -eu
project_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
exec "$project_dir/ralph.sh" --engine claude "$@"
