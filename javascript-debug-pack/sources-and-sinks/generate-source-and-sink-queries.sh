#!/usr/bin/env python3
# vi: set syntax=python:

qlheader ='''/**
 * @name Sources and Sinks {number}
 * @kind problem
 * @problem.severity recommendation
 * @id js/sources-and-sinks-{number}
 */
import javascript
'''

qlbody ='''
from TaintTracking::Configuration c, DataFlow::Node n, string type
where c.isSource(n) and type = "Source" or c.isSink(n) and type = "Sink"
select n, c + type
'''

with open('input_modules', 'r') as inputfile:
  for i, l in enumerate(inputfile.readlines()):
    module = l.strip('\n')
    number = str(i)
    with open('sources-and-sinks-' + number + '.ql', 'w') as qlfile:
      qlfile.write(qlheader.format(number=number))
      qlfile.write('import ' + module + ' as CONFIG')
      qlfile.write(qlbody)
