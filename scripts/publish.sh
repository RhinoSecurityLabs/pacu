#!/usr/bin/env bash

set -euo pipefail

err() {
    echo "[ERR] LineNo: ${1}"
}
trap 'err "$LINENO"' err

if ! git status | grep 'On branch master'; then
    echo "[ERR] Must be on the master branch."
    exit 2
fi

git fetch origin
if ! git --no-pager diff HEAD..master; then
    echo "[ERR] Not up to date with origin/master."
    exit 3
fi


ver="$(poetry version -s)"
git tag "v${ver}"
git push origin "refs/tags/v${ver}"
