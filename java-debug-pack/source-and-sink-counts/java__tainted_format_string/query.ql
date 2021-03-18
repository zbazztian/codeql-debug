

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.StringFormat


class ExternallyControlledFormatStringConfig extends TaintTracking::Configuration {
  ExternallyControlledFormatStringConfig() { this = "ExternallyControlledFormatStringConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr() = any(StringFormat formatCall).getFormatArgument()
  }

  override predicate isSanitizer(DataFlow::Node node) {
    node.getType() instanceof NumericType or node.getType() instanceof BooleanType
  }
}

from string type, int amount
where exists(string qid | qid = "java/tainted-format-string" and (
  exists(
    ExternallyControlledFormatStringConfig c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
