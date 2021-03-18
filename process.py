import sys
import glob
import os.path
import subprocess
import csv
import os
import shutil

def remove(fpath):
  if os.path.isfile(fpath):
    os.remove(fpath)

def get(array, i, default):
  v = None
  if i < len(array):
    v = array[i]
  return v if v else default

here = os.path.dirname(sys.argv[0])
lang = sys.argv[1]
repo_id = sys.argv[2]
sha = sys.argv[3]
codeql_executable = get(
  sys.argv,
  4,
  get(
    glob.glob(
      os.path.join(
        os.environ.get('RUNNER_TOOL_CACHE', ''),
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
dbpath = get(sys.argv, 5, os.path.join(os.environ.get('RUNNER_TEMP', ''), 'codeql_databases', lang))
server_url = get(sys.argv, 6, os.environ.get('GITHUB_SERVER_URL', 'https://github.com'))
ql_searchpath = get(sys.argv, 7, '')

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
print('repository sha: ' + sha, flush=True)
print('github server url: ' + server_url, flush=True)
print('ql search path: ' + ql_searchpath, flush=True)


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
  except subprocess.CalledProcessError as cpe:
    print('Command failed with exit code: ' + str(cpe.returncode))
    print('stdout:')
    print(cpe.output.decode())
    print('stderr:')
    print(cpe.stderr.decode(), flush=True)
    raise


# run some diagnostic output
codeql('version')
codeql('resolve', 'qlpacks')

debug_results_dir = 'codeql-debug-results'
shutil.rmtree(debug_results_dir, ignore_errors=True)
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
  '*',
  'query.ql'
)):
  codeql(
    'query', 'run',
    '--search-path', ql_searchpath,
    '--output', source_and_sink_counts_bqrs,
    '--threads', '0',
    '-d', dbpath,
    qlf
  )
  codeql(
    'bqrs', 'decode',
    '--format', 'csv',
    '--output', source_and_sink_counts_csv,
    source_and_sink_counts_bqrs
  )

  with open(source_and_sink_counts_csv, 'r') as f:
    reader = csv.reader(f)
    next(reader, None)  # skip headers
    for row in reader:
      nodetype = row[0]
      count = row[1]
      if nodetype in node_counts:
        raise Exception('Duplicated node type "' + nodetype + '"!')
      node_counts[nodetype] = count


codeql(
  'database', 'analyze',
  '--search-path', ql_searchpath,
  '--output', sources_and_sinks_csv,
  '--format', 'csv',
  '--threads', '0',
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
    f.write('  <td>{count}</td>\n'.format(count=str(node_counts[n])))
    f.write('</tr>\n')

  f.write('</table>\n')
  f.write('<h1>Details</h1>\n')

  for n in sorted_node_types:
    f.write('<h2 id="{nodetype}">{nodetype} (code-only results)</h2>\n'.format(nodetype=n))
    for r in nodes.get(n, []):
      f.write(
        '<a href="{serverurl}/{repo_id}/blob/{sha}{fname}/#L{startline}-L{endline}">{fname}:{startline}</a><br>\n'.format(
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


# clean up
remove(source_and_sink_counts_csv)
remove(source_and_sink_counts_bqrs)
remove(sources_and_sinks_csv)
