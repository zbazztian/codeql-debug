/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id java/tainted-numeric-cast-local-sources-and-sinks
 */


import java
import semmle.code.java.dataflow.FlowSources
import NumericCastCommon


private class NumericCastFlowConfig extends TaintTracking::Configuration {
  NumericCastFlowConfig() {
    this = "NumericCastTaintedLocal::LocalUserInputToNumericNarrowingCastExpr"
  }

  override predicate isSource(DataFlow::Node src) { src instanceof LocalUserInput }

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

from DataFlow::Node n, string type
where exists(string qid | qid = "java/tainted-numeric-cast-local" and (
  exists(
    NumericCastFlowConfig c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
