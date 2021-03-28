/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id java/sql-injection-sources-and-sinks
 */


import java
import semmle.code.java.dataflow.FlowSources
import SqlInjectionLib

from DataFlow::Node n, string type
where exists(string qid | qid = "java/sql-injection" and (
  exists(
    QueryInjectionFlowConfig c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
