

import python
import semmle.python.security.Paths
import semmle.python.security.Exceptions
import semmle.python.web.HttpResponse

class StackTraceExposureConfiguration extends TaintTracking::Configuration {
  StackTraceExposureConfiguration() { this = "Stack trace exposure configuration" }

  override predicate isSource(TaintTracking::Source source) { source instanceof ErrorInfoSource }

  override predicate isSink(TaintTracking::Sink sink) { sink instanceof HttpResponseTaintSink }
}

from string type, int amount
where exists(string qid | qid = "py/stack-trace-exposure" and (
  exists(
    StackTraceExposureConfiguration c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
