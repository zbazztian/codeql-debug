/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id go/email-injection-sources-and-sinks
 */


import go
import DataFlow::PathGraph
import EmailInjection::EmailInjection

from DataFlow::Node n, string type
where 
exists(
  Configuration c |
  c.isSource(n) and type = c + "Source" or
  c.isSink(n) and type = c + "Sink"
)
select n, type
