import sys
import glob
import os.path
import subprocess
import csv
import os

def get(array, i, default):
  v = None
  if i < len(array):
    v = array[i]
  return v if v else default

here = os.path.dirname(sys.argv[0])
lang = sys.argv[1]
runner_tool_cache = os.environ['RUNNER_TOOL_CACHE']
codeql = get(
  sys.argv,
  2,
  get(
    glob.glob(
      os.path.join(
        runner_tool_cache,
        'CodeQL',
        '*',
        'x64',
        'codeql',
        'codeql' + ('' if os.name == 'posix' else '.exe')
      )
    ),
    0,
    ''
  )
)
runner_temp = os.environ['RUNNER_TEMP']
dbpath = get(sys.argv, 3, os.path.join(runner_temp, 'codeql_databases', lang))
repo_id = get(sys.argv, 4, None)
sha = get(sys.argv, 5, None)
server_url = os.environ['GITHUB_SERVER_URL']

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
  '--output', 'codeql-debug-results.csv',
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

nodes = {}

with open('codeql-debug-results.csv', 'r') as f:
  for row in csv.reader(f):
    nodetype = row[3]
    fname = row[4]
    startline = row[5]
    startcol = row[6]
    endline = row[7]
    endcol = row[8]
    if nodetype not in nodes:
      nodes[nodetype] = []
    nodes[nodetype].append((fname, startline, endline))

debug_results_dir = 'codeql-debug-results'
os.makedirs(debug_results_dir)

with open(os.path.join(debug_results_dir, lang + '.html'), 'w') as f:
  f.write('<html>\n')
  f.write('<body>\n')
  f.write('<h1>Summary</h1>\n')
  f.write('<table>\n')
  f.write('<tr>\n')
  f.write('  <th align="left">Type</th>\n')
  f.write('  <th align="left">Count</th>\n')
  f.write('</tr>\n')

  sorted_nodes = sorted([n for n in nodes])

  for n in sorted_nodes:
    f.write('<tr>\n')
    f.write('  <td><a href="#{nodetype}">{nodetype}</a></td>\n'.format(nodetype=n))
    f.write('  <td>{count}</td>\n'.format(count=str(len(nodes[n]))))
    f.write('</tr>\n')

  f.write('</table>\n')
  f.write('<h1>Details</h1>\n')

  for n in sorted_nodes:
    f.write('<h2 id="{nodetype}">{nodetype}</h2>\n'.format(nodetype=n))
    for r in nodes[n]:
      f.write(
        '<a href="{serverurl}/{repo_id}/blob/{sha}{fname}/#L{startline}-L{endline}">click</a><br>\n'.format(
          serverurl=server_url,
          repo_id=repo_id,
          sha=sha,
          fname=r[0],
          startline=r[1],
          endline=r[2]
        )
      )

  f.write('</body>\n')
  f.write('</html>\n')
