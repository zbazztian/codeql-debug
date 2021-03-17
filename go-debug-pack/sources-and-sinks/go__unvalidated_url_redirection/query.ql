/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id go/unvalidated-url-redirection-sources-and-sinks
 */


import go
import semmle.go.security.OpenUrlRedirect::OpenUrlRedirect
import semmle.go.security.SafeUrlFlow
import DataFlow::PathGraph

from DataFlow::Node n, string type
where 
exists(
  SafeUrlFlow::Configuration c |
  c.isSource(n) and type = c + "Source" or
  c.isSink(n) and type = c + "Sink"
)
or
exists(
  Configuration c |
  c.isSource(n) and type = c + "Source" or
  c.isSink(n) and type = c + "Sink"
)
select n, type
