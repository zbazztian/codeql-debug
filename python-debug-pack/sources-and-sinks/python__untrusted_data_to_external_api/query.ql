/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id python/untrusted-data-to-external-api-sources-and-sinks
 */


import python
import ExternalAPIs

from DataFlow::Node n, string type
where exists(string qid | qid = "python/untrusted-data-to-external-api" and (
  exists(
    UntrustedDataToExternalAPIConfig c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
