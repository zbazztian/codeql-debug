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
codeql_executable = get(
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

def codeql(*args):
  args = [codeql_executable] + list(args)
  print(' '.join(args), flush=True)
  try:
    output = subprocess.run(
      args,
      capture_output=True,
      check=True
    )
    print(output.stdout.decode(), flush=True)
  except CalledProcessError as cpe:
    print('Command failed with exit code: ' + str(cpe.returncode))
    print('stdout:')
    print(cpe.output.decode())
    print('stderr:')
    print(cpe.stderr.decode(), flush=True)

if not os.path.isdir(dbpath):
  print('Given path is not a database: ' + dbpath)
  sys.exit(1)

if not os.path.isfile(codeql_executable):
  print('Given path is not a CodeQL executable: ' + codeql_executable)
  sys.exit(1)

print('codeql executable: ' + codeql_executable, flush=True)
print('codeql database: ' + dbpath, flush=True)
print('codeql language: ' + lang, flush=True)
print('repository id: ' + repo_id, flush=True)
print('sha: ' + sha, flush=True)

# run some diagnostic output
codeql('version')
codeql('resolve', 'qlpacks')

debug_results_dir = 'codeql-debug-results'
os.makedirs(debug_results_dir)
sources_and_sinks_csv = os.path.join(debug_results_dir, 'sources_and_sinks_' + lang + '.csv')
source_and_sink_counts_file = os.path.join(debug_results_dir, 'source_and_sink_counts_' + lang)
source_and_sink_counts_csv = source_and_sink_counts_file + '.csv'
source_and_sink_counts_bqrs = source_and_sink_counts_file + '.bqrs'

node_counts = {}

for qlf in glob.glob(os.path.join(
  here,
  lang + '-debug-pack',
  'source-and-sink-counts',
  '*.ql'
)):
  codeql(
    'query', 'run',
    '--output', source_and_sink_counts_bqrs,
    '-d', dbpath,
    qlf
  )
  codeql(
    'bqrs', 'decode',
    '--output', source_and_sink_counts_csv,
    source_and_sink_counts_bqrs
  )

  with open(source_and_sink_counts_csv, 'r') as f:
    for row in csv.reader(f):
      print('"' + str(row) + '"')
      nodetype = row[0]
      count = row[1]
      node_counts[nodetype] = node_counts.get(nodetype, 0) + count


codeql(
  'database', 'analyze',
  '--output', sources_and_sinks_csv,
  '--format', 'csv',
  '--no-group-results',
  dbpath,
  os.path.join(
    here,
    lang + '-debug-pack',
    'sources-and-sinks.qls'
  )
)

nodes = {}
sorted_node_types = sorted([n for n in node_counts])

with open(sources_and_sinks_csv, 'r') as f:
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

with open(os.path.join(debug_results_dir, lang + '.html'), 'w') as f:
  f.write('<html>\n')
  f.write('<body>\n')
  f.write('<h1>Summary</h1>\n')
  f.write('<table>\n')
  f.write('<tr>\n')
  f.write('  <th align="left">Type</th>\n')
  f.write('  <th align="left">Count</th>\n')
  f.write('</tr>\n')

  for n in sorted_node_types:
    f.write('<tr>\n')
    f.write('  <td><a href="#{nodetype}">{nodetype}</a></td>\n'.format(nodetype=n))
    f.write('  <td>{count}</td>\n'.format(count=str(len(node_counts[n]))))
    f.write('</tr>\n')

  f.write('</table>\n')
  f.write('<h1>Details</h1>\n')

  for n in sorted_node_types:
    f.write('<h2 id="{nodetype}">{nodetype}</h2>\n'.format(nodetype=n))
    for r in nodes.get(n, []):
      f.write(
        '<a href="{serverurl}/{repo_id}/blob/{sha}{fname}/#L{startline}-L{endline}">link</a><br>\n'.format(
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
