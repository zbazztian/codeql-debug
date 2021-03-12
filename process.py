import sys
import glob
import os.path
import subprocess

def get(array, i, default):
  v = None
  if i < len(array):
    v = array[i]
  return v if v else default

here = os.path.dirname(sys.argv[0])
lang = sys.argv[1]
codeql = get(
  sys.argv,
  2,
  get(glob.glob('/opt/hostedtoolcache/CodeQL/*/x64/codeql/codeql'), 0, '')
)
dbpath = get(sys.argv, 3, '/home/runner/work/_temp/codeql_databases/' + lang)

if not os.path.isdir(dbpath):
  print('Given path is not a database: ' + dbpath)
  sys.exit(1)

if not os.path.isfile(codeql):
  print('Given path is not a CodeQL executable: ' + codeql)
  sys.exit(1)

print(codeql)
print(dbpath)
print(lang)

output = subprocess.run(
  [codeql, 'version'],
  capture_output=True,
  check=True
)
print(output.stdout.decode())

output = subprocess.run(
  [codeql, 'resolve', 'qlpacks'],
  capture_output=True,
  check=True
)
print(output.stdout.decode())

args = [codeql, 'database', 'analyze', '--output', 'results.csv', '--format', 'csv', dbpath, os.path.join(here, lang + '-debug-pack', 'xss-sources-and-sinks.ql')]
print(args)
output = subprocess.run(
  args,
  capture_output=True,
  check=True
)
print(output.stdout.decode())
