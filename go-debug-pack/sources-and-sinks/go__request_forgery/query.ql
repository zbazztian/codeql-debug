/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id go/request-forgery-sources-and-sinks
 */


import go
import semmle.go.security.RequestForgery::RequestForgery
import semmle.go.security.SafeUrlFlow

from DataFlow::Node n, string type
where 
exists(
  Configuration c, string qid |
  qid = "go/request-forgery: " and (
    c.isSource(n) and type = qid + c + "Source" or
    c.isSink(n) and type = qid + c + "Sink"
  )
)
or
exists(
  SafeUrlFlow::Configuration c, string qid |
  qid = "go/request-forgery: " and (
    c.isSource(n) and type = qid + c + "Source" or
    c.isSink(n) and type = qid + c + "Sink"
  )
)
select n, type
