/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id js/command-line-injection-sources-and-sinks
 */


import javascript
import semmle.javascript.security.dataflow.CommandInjection::CommandInjection

from DataFlow::Node n, string type
where 
exists(
  Configuration c, string qid |
  qid = "js/command-line-injection: " and (
    c.isSource(n) and type = qid + c + "Source" or
    c.isSink(n) and type = qid + c + "Sink"
  )
)
select n, type