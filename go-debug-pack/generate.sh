#!/bin/sh
if test -z "$1"; then
  echo 'usage: generate.sh /root/of/codeql-go-repo/checkout'
  exit 1
fi

rm -rf source-and-sink-counts sources-and-sinks
find "${1}/ql/src/Security/" -name "*.ql" -type f -print0 \
  | xargs -0 -I {} python3 ../query-generator/generate 'go' '{}'
