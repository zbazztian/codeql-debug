/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id go/command-injection-sources-and-sinks
 */


import go
import semmle.go.security.CommandInjection

from DataFlow::Node n, string type
where 
exists(
  CommandInjection::DoubleDashSanitizingConfiguration c, string qid |
  qid = "go/command-injection: " and (
    c.isSource(n) and type = qid + c + "Source" or
    c.isSink(n) and type = qid + c + "Sink"
  )
)
or
exists(
  CommandInjection::Configuration c, string qid |
  qid = "go/command-injection: " and (
    c.isSource(n) and type = qid + c + "Source" or
    c.isSink(n) and type = qid + c + "Sink"
  )
)
select n, type
