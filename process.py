import sys
import glob
from os.path import isfile, isdir, dirname, join, relpath, basename
import subprocess
import csv
import os
import shutil
import re
import hashlib
from distutils.dir_util import copy_tree
from datetime import datetime


def change_ext(extfrom, extto, path):
  return re.sub(re.escape(extfrom) + '$', extto, path)

def make_key(s):
  sha1 = hashlib.sha1()
  sha1.update(s.encode('utf-8'))
  return sha1.hexdigest()

def remove(fpath):
  if isfile(fpath):
    os.remove(fpath)

def get(array, i, default):
  v = None
  if i < len(array):
    v = array[i]
  return v if v else default

here = dirname(sys.argv[0])
lang = sys.argv[1]
repo_id = sys.argv[2]
sha = sys.argv[3]
codeql_executable = get(
  sys.argv,
  4,
  get(
    glob.glob(
      join(
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
dbpath = get(sys.argv, 5, join(os.environ.get('RUNNER_TEMP', ''), 'codeql_databases', lang))
server_url = get(sys.argv, 6, os.environ.get('GITHUB_SERVER_URL', 'https://github.com'))
ql_searchpath = get(sys.argv, 7, '')

if not isdir(dbpath):
  print('Given path is not a database: ' + dbpath)
  sys.exit(1)

if not isfile(codeql_executable):
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

# create output directories
outdir = 'codeql-debug-results'
shutil.rmtree(outdir, ignore_errors=True)
os.makedirs(outdir)
detail_dir = join(outdir, lang)
os.makedirs(detail_dir)

# copy log files from database
original_logdir = join(dbpath, "log")
logdir = join(detail_dir, "log")
if isdir(original_logdir):
  copy_tree(original_logdir, logdir)

# remove .log extensions from the copied files
for logf in glob.glob(join(logdir, '**', '*.log'), recursive=True):
  if isfile(logf):
    os.rename(logf, change_ext('.log', '', logf))

debug_pack = lang + '-debug-pack'
debug_pack_path = join(here, debug_pack)



def get_source_and_sink_counts():
  result = {}

  codeql(
    'database', 'run-queries',
    '--search-path', ql_searchpath,
    '--threads', '0',
    '--rerun',
    dbpath,
    join(
      debug_pack_path,
      'source-and-sink-counts.qls'
    )
  )

  for qlf in glob.glob(join(
    debug_pack_path,
    'source-and-sink-counts',
    '*',
    'query.ql'
  )):
    relqlf = relpath(qlf, here)
    bqrsf = join(
      dbpath,
      'results',
      change_ext('.ql', '.bqrs', relqlf)
    )
    csvf = change_ext('.bqrs', '.csv', bqrsf)
    codeql(
      'bqrs', 'decode',
      '--no-titles',
      '--format', 'csv',
      '--output', csvf,
      bqrsf
    )

    with open(csvf, 'r') as f:
      for row in csv.reader(f):
        nodetype = row[0]
        count = row[1]
        if nodetype in result:
          raise Exception('Duplicated node type "' + nodetype + '"!')
        result[nodetype] = count

    remove(csvf)

  return result


def get_sources_and_sinks():
  result = {}
  sources_and_sinks_csv = join(outdir, 'sources_and_sinks_' + lang + '.csv')
  codeql(
    'database', 'analyze',
    '--search-path', ql_searchpath,
    '--output', sources_and_sinks_csv,
    '--format', 'csv',
    '--threads', '0',
    '--rerun',
    '--no-group-results',
    dbpath,
    join(
      debug_pack_path,
      'sources-and-sinks.qls'
    )
  )

  with open(sources_and_sinks_csv, 'r') as f:
    for row in csv.reader(f):
      nodetype = row[3]
      fname = row[4]
      startline = row[5]
      startcol = row[6]
      endline = row[7]
      endcol = row[8]
      if nodetype not in result:
        result[nodetype] = []
      result[nodetype].append((fname, startline, endline))

  remove(sources_and_sinks_csv)
  return result


def get_analysis_runs():
  PATTERN_QUERY_EVAL_TIME = re.compile('execute queries> \[(\d+)/(\d+) eval (((\d+)h)?((\d+)m)?((\d+(\.\d+)?)s|(\d+)ms))] Evaluation done; writing results to (.*\.bqrs).')
  result = []
  for eq in glob.glob(join(logdir, 'execute-queries-*')):
    d = datetime.strptime(basename(eq).split('-')[2], '%Y%m%d.%H%M%S.%f')
    with open(eq) as f:
      qdurations = []
      for m in PATTERN_QUERY_EVAL_TIME.findall(f.read()):
        idx = m[0]
        num_queries = m[1]
        hours = int(m[4]) if m[4] else 0
        minutes = int(m[6]) if m[6] else 0
        seconds = float(m[8]) if m[8] else 0
        milliseconds = int(m[10]) if m[10] else 0
        query = change_ext('.bqrs', '.ql', m[11])
        pattern = m[2]
        duration = int(milliseconds + 1000 * (seconds + 60 * (minutes + 60 * hours)))
        qdurations.append((query, duration, pattern, idx))

      qdurations = sorted(qdurations, key=lambda e: e[1], reverse=True)
      result.append((eq, d, qdurations))

  return sorted(result, key=lambda e: e[1], reverse=True)


runs = get_analysis_runs()
node_counts = get_source_and_sink_counts()
nodes = get_sources_and_sinks()
sorted_node_types = sorted([n for n in node_counts])


with open(join(outdir, lang + '.html'), 'w') as f:
  f.write('<html>\n<body>\n')

  # sources and sinks
  f.write('<h1>Summary of Sources and Sinks</h1>\n')
  f.write('<table>\n')
  f.write('<tr>\n')
  f.write('  <th align="left">Type</th>\n')
  f.write('  <th align="left">Count</th>\n')
  f.write('</tr>\n')

  for n in sorted_node_types:
    detail_file = join(detail_dir, make_key(n) + '.html')

    f.write('<tr>\n')
    f.write('  <td><a href="{relpath}">{nodetype}</a></td>\n'.format(
      relpath=relpath(detail_file, outdir),
      nodetype=n
    ))
    f.write('  <td>{count}</td>\n'.format(count=str(node_counts[n])))
    f.write('</tr>\n')

    with open(detail_file, 'w') as df:
      df.write('<html>\n<body>\n')
      df.write('<h2>{nodetype} (code-only results)</h2>\n'.format(nodetype=n))
      for r in nodes.get(n, []):
        df.write(
          '<a href="{serverurl}/{repo_id}/blob/{sha}{fname}/#L{startline}-L{endline}">{fname}:{startline}</a><br>\n'.format(
            serverurl=server_url,
            repo_id=repo_id,
            sha=sha,
            fname=r[0],
            startline=r[1],
            endline=r[2]
          )
        )
      df.write('</body>\n</html>\n')

  f.write('</table>\n')

  # analysis runs
  f.write('<h1>Analyses</h1>\n')
  f.write('<ul>\n')
  for fname, date, qdurations in runs:
    duration_file = join(detail_dir, make_key(fname + str(date)) + '.html')

    f.write(
      '<li><b><a href="{duration_file}">{date}</a></b> (<a href="{log_file}">{logname}</a>)</li>\n'.format(
        duration_file=relpath(duration_file, outdir),
        date=str(date),
        log_file=relpath(fname, outdir),
        logname=relpath(fname, logdir)
      )
    )

    with open(duration_file, 'w') as df:
      df.write('<html>\n<body><ol>\n')
      for query, duration, pattern, idx in qdurations:
        df.write('<li>{query} (<b>duration: {duration}</b>) (<b>index: {index}</b>)</li>\n'.format(
          query=query,
          duration=pattern,
          index=idx
        ))
      df.write('</ol></body>\n</html>\n')

  f.write('</ul>\n')

  # log files
  f.write('<h1>Log Files</h1>\n')
  f.write('<table>\n')
  f.write('<tr>\n')
  f.write('  <th align="left">File</th>\n')
  f.write('</tr>\n')
  for logf in sorted(glob.glob(join(logdir, '**'), recursive=True)):
    if isfile(logf):
      rel_logf = relpath(logf, outdir)
      name = relpath(logf, logdir)

      f.write('<tr>\n')
      f.write('  <td><a href="{relpath}">{name}</a></td>\n'.format(
        relpath=rel_logf,
        name=name
      ))
      f.write('</tr>\n')

  f.write('</table>\n')
  f.write('</body>\n</html>\n')


