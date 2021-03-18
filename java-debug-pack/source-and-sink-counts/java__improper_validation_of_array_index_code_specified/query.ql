

import java
import ArraySizing
import BoundingChecks


class BoundedFlowSourceConf extends DataFlow::Configuration {
  BoundedFlowSourceConf() { this = "BoundedFlowSource" }

  override predicate isSource(DataFlow::Node source) { source instanceof BoundedFlowSource }

  override predicate isSink(DataFlow::Node sink) {
    exists(CheckableArrayAccess arrayAccess | arrayAccess.canThrowOutOfBounds(sink.asExpr()))
  }
}

from string type, int amount
where exists(string qid | qid = "java/improper-validation-of-array-index-code-specified" and (
  exists(
    BoundedFlowSourceConf c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
