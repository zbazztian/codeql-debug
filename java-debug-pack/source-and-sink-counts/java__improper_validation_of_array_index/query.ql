

import java
import ArraySizing
import semmle.code.java.dataflow.FlowSources


class Conf extends TaintTracking::Configuration {
  Conf() { this = "RemoteUserInputTocanThrowOutOfBoundsDueToEmptyArrayConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  override predicate isSink(DataFlow::Node sink) {
    any(CheckableArrayAccess caa).canThrowOutOfBounds(sink.asExpr())
  }

  override predicate isSanitizer(DataFlow::Node node) { node.getType() instanceof BooleanType }
}

from string type, int amount
where exists(string qid | qid = "java/improper-validation-of-array-index" and (
  exists(
    Conf c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
