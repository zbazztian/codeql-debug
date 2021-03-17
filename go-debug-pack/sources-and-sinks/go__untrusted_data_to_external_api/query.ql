/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id go/untrusted-data-to-external-api-sources-and-sinks
 */


import go
import semmle.go.security.ExternalAPIs
import DataFlow::PathGraph

from DataFlow::Node n, string type
where 
exists(
  UntrustedDataToExternalAPIConfig c |
  c.isSource(n) and type = c + "Source" or
  c.isSink(n) and type = c + "Sink"
)
select n, type
