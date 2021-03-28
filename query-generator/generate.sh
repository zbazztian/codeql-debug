#!/bin/sh
if [ -z "$1" ] || [ -z "$2" ]; then
  echo 'usage: generate.sh language /directory/with/security/queries'
  exit 1
fi

stagedir="stage"
rm -rf source-and-sink-counts sources-and-sinks "$stagedir"
cp -R "${2}" "$stagedir"
find "$stagedir" -name "*.ql" -type f -print0 \
  | xargs -0 -I {} python3 ../query-generator/generate "$1" '{}'
rm -rf "$stagedir"
