#!/usr/bin/env python3
# vi: set syntax=python:
import glob
import os

ss_qlheader ='''/**
 * @name Sources and Sinks {number}
 * @kind problem
 * @problem.severity recommendation
 * @id js/sources-and-sinks-{number}
 */
import javascript
'''

ssc_qlheader ='''/**
 * @name Source and Sink Counts {number}
 * @kind metric
 * @metricType sum
 * @problem.severity recommendation
 * @id js/source-and-sink-counts-{number}
 */
import javascript
'''


ss_qlbody ='''
from TaintTracking::Configuration c, DataFlow::Node n, string type
where c.isSource(n) and type = "Source" or c.isSink(n) and type = "Sink"
select n, c + type
'''

ssc_qlbody ='''
from TaintTracking::Configuration c, string type, int amount
where amount = strictcount(DataFlow::Node n | c.isSource(n)) and type = "Source"
   or amount = strictcount(DataFlow::Node n | c.isSink(n)) and type = "Sink"
select c + type, amount
'''

ss_prefix = 'sources-and-sinks'
ssc_prefix = 'source-and-sink-counts'

# delete existing files
for prefix in [ss_prefix, ssc_prefix]:
  for qlf in glob.glob(prefix + '/*.ql'):
    os.remove(qlf)

with open('input_modules', 'r') as inputfile:
  for i, l in enumerate(inputfile.readlines()):
    module = l.strip('\n')
    number = str(i)
    with open(ss_prefix + '/' + ss_prefix + '-' + number + '.ql', 'w') as qlfile:
      qlfile.write(ss_qlheader.format(number=number))
      qlfile.write('import ' + module + ' as CONFIG')
      qlfile.write(ss_qlbody)
    with open(ssc_prefix + '/' + ssc_prefix + '-' + number + '.ql', 'w') as qlfile:
      qlfile.write(ssc_qlheader.format(number=number))
      qlfile.write('import ' + module + ' as CONFIG')
      qlfile.write(ssc_qlbody)
