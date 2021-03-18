/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id java/http-response-splitting-local-sources-and-sinks
 */


import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.ResponseSplitting


class ResponseSplittingLocalConfig extends TaintTracking::Configuration {
  ResponseSplittingLocalConfig() { this = "ResponseSplittingLocalConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof LocalUserInput }

  override predicate isSink(DataFlow::Node sink) { sink instanceof HeaderSplittingSink }

  override predicate isSanitizer(DataFlow::Node node) {
    node.getType() instanceof PrimitiveType or
    node.getType() instanceof BoxedType
  }
}

from DataFlow::Node n, string type
where exists(string qid | qid = "java/http-response-splitting-local" and (
  exists(
    ResponseSplittingLocalConfig c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
