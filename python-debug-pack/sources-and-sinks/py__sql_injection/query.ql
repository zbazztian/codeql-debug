/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id py/sql-injection-sources-and-sinks
 */


import python
import semmle.python.security.dataflow.SqlInjection

from DataFlow::Node n, string type
where exists(string qid | qid = "py/sql-injection" and (
  exists(
    SQLInjectionConfiguration c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
