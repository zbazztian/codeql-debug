/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id go/untrusted-data-to-unknown-external-api-sources-and-sinks
 */


import go
import semmle.go.security.ExternalAPIs

from DataFlow::Node n, string type
where exists(string qid | qid = "go/untrusted-data-to-unknown-external-api" and (
  exists(
    UntrustedDataToUnknownExternalAPIConfig c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
