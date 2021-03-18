/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id go/stored-xss-sources-and-sinks
 */


import go
import semmle.go.security.StoredXss::StoredXss

from DataFlow::Node n, string type
where 
exists(
  Configuration c, string qid |
  qid = "go/stored-xss: " and (
    c.isSource(n) and type = qid + c + "Source" or
    c.isSink(n) and type = qid + c + "Sink"
  )
)
select n, type
