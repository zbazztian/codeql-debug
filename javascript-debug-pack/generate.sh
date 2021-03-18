#!/bin/sh
rm -rf source-and-sink-counts sources-and-sinks
find ~/dev/src/ql/javascript/ql/src/Security/ -name "*.ql" -type f -print0 \
  | xargs -0 -I {} python3 ../query-generator/generate 'javascript' '{}'
