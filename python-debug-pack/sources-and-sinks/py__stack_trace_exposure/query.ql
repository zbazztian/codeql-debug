/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id py/stack-trace-exposure-sources-and-sinks
 */


import python
import semmle.python.security.Paths
import semmle.python.security.Exceptions
import semmle.python.web.HttpResponse

class StackTraceExposureConfiguration extends TaintTracking::Configuration {
  StackTraceExposureConfiguration() { this = "Stack trace exposure configuration" }

  override predicate isSource(TaintTracking::Source source) { source instanceof ErrorInfoSource }

  override predicate isSink(TaintTracking::Sink sink) { sink instanceof HttpResponseTaintSink }
}

from DataFlow::Node n, string type
where exists(string qid | qid = "py/stack-trace-exposure" and (
  exists(
    StackTraceExposureConfiguration c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
