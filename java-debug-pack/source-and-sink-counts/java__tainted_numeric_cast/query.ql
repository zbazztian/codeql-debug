

import java
import semmle.code.java.dataflow.FlowSources
import NumericCastCommon


private class NumericCastFlowConfig extends TaintTracking::Configuration {
  NumericCastFlowConfig() { this = "NumericCastTainted::RemoteUserInputToNumericNarrowingCastExpr" }

  override predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }

  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr() = any(NumericNarrowingCastExpr cast).getExpr()
  }

  override predicate isSanitizer(DataFlow::Node node) {
    boundedRead(node.asExpr()) or
    castCheck(node.asExpr()) or
    node.getType() instanceof SmallType or
    smallExpr(node.asExpr()) or
    node.getEnclosingCallable() instanceof HashCodeMethod
  }
}

from string type, int amount
where exists(string qid | qid = "java/tainted-numeric-cast" and (
  exists(
    NumericCastFlowConfig c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
