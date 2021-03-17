/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id go/unsafe-quoting-sources-and-sinks
 */


import go
import semmle.go.security.StringBreak
import DataFlow::PathGraph

from DataFlow::Node n, string type
where 
exists(
  StringBreak::Configuration c |
  c.isSource(n) and type = c + "Source" or
  c.isSink(n) and type = c + "Sink"
)
select n, type
