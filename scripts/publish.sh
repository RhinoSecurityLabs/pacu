#!/usr/bin/env bash

set -euo pipefail

err() {
    echo "[ERR] LineNo: ${1}"
}
trap 'err "$LINENO"' err

if [[ -z "${1:-}" ]]; then
    echo "Usage: $0 [patch, minor, major, prepatch, preminor, premajor, prerelease]"
    exit 1
fi

if ! git branch --show-current|grep master; then
    echo "[ERR] Must be on the master branch."
    exit 2
fi

git fetch origin
if ! git --no-pager diff HEAD..master; then
    echo "[ERR] Not up to date with origin/master."
    exit 3
fi


poetry version "${1}"
ver="$(poetry version -s)"
git tag "v${ver}"
git push --tags
