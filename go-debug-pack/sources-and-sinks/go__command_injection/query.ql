/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id go/command-injection-sources-and-sinks
 */


import go
import semmle.go.security.CommandInjection
import DataFlow::PathGraph

from DataFlow::Node n, string type
where 
exists(
  CommandInjection::Configuration c |
  c.isSource(n) and type = c + "Source" or
  c.isSink(n) and type = c + "Sink"
)
or
exists(
  CommandInjection::DoubleDashSanitizingConfiguration c |
  c.isSource(n) and type = c + "Source" or
  c.isSink(n) and type = c + "Sink"
)
select n, type
