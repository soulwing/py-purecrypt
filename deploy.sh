#!/bin/bash
DIST=dist

if [ -z "$PY_PI_TOKEN" ]; then
  echo "PY_PI_TOKEN must be available in the environment" >&2
  exit 1
fi

python3 -m twine upload --username "__token__" --password "${PY_PI_TOKEN}" $DIST/*

