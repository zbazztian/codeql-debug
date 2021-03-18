

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

from string type, int amount
where exists(string qid | qid = "java/http-response-splitting-local" and (
  exists(
    ResponseSplittingLocalConfig c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
