/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id js/shell-command-constructed-from-input-sources-and-sinks
 */


import javascript
import semmle.javascript.security.dataflow.UnsafeShellCommandConstruction::UnsafeShellCommandConstruction

from DataFlow::Node n, string type
where 
exists(
  Configuration c, string qid |
  qid = "js/shell-command-constructed-from-input: " and (
    c.isSource(n) and type = qid + c + "Source" or
    c.isSink(n) and type = qid + c + "Sink"
  )
)
select n, type
