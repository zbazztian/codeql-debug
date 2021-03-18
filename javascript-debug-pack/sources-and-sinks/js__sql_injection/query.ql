/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id js/sql-injection-sources-and-sinks
 */


import javascript
import semmle.javascript.security.dataflow.SqlInjection
import semmle.javascript.security.dataflow.NosqlInjection

from DataFlow::Node n, string type
where 
exists(
  DataFlow::Configuration c, string qid |
  qid = "js/sql-injection: " and (
    c.isSource(n) and type = qid + c + "Source" or
    c.isSink(n) and type = qid + c + "Sink"
  )
)
select n, type
