import sys
import glob
import os.path
import subprocess
import csv

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
repo_id = get(sys.argv, 4, None)
sha = get(sys.argv, 5, None)

if not os.path.isdir(dbpath):
  print('Given path is not a database: ' + dbpath)
  sys.exit(1)

if not os.path.isfile(codeql):
  print('Given path is not a CodeQL executable: ' + codeql)
  sys.exit(1)

print(codeql)
print(dbpath)
print(lang)
print(repo_id)
print(sha)

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

args = [
  codeql, 'database', 'analyze',
  '--output', 'results.csv',
  '--format', 'csv',
  '--no-group-results',
  dbpath,
  os.path.join(
    here,
    lang + '-debug-pack',
    'sources-and-sinks.qls'
  )
]
print(' '.join(args))
output = subprocess.run(
  args,
  capture_output=True,
  check=True
)
print(output.stdout.decode())


with open('results.html', 'w') as htmlf:
  htmlf.write('<html>\n')
  htmlf.write('<body>\n')
  with open('results.csv') as f:
    for row in csv.reader(f):
      startcol = int(row[6])
      endcol = int(row[8])
      htmlf.write(
        '{labels}: <a href="{serverurl}/{repo_id}/blob/{sha}{fname}/#L{startline}-L{endline}">click</a><br>\n'.format(
          labels='|'.join(row[3].split('\n')),
          serverurl='https://github.com/',
          repo_id=repo_id,
          sha=sha,
          fname=row[4],
          startline=row[5],
          endline=row[7]
        )
      )

  htmlf.write('</body>\n')
  htmlf.write('</html>\n')
