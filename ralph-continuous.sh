#!/bin/sh
set -eu
project_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
case "${1:-}" in
    -h|--help) exec "$project_dir/ralph.sh" --help ;;
esac
engine=${1:-${ENGINE:-claude}}
if [ "$#" -gt 0 ]; then shift; fi
exec "$project_dir/ralph.sh" --engine "$engine" --continuous "$@"
