

import java
import semmle.code.java.dataflow.FlowSources
import ArithmeticCommon


class ArithmeticTaintedLocalOverflowConfig extends TaintTracking::Configuration {
  ArithmeticTaintedLocalOverflowConfig() { this = "ArithmeticTaintedLocalOverflowConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof LocalUserInput }

  override predicate isSink(DataFlow::Node sink) { overflowSink(_, sink.asExpr()) }

  override predicate isSanitizer(DataFlow::Node n) { overflowBarrier(n) }
}

class ArithmeticTaintedLocalUnderflowConfig extends TaintTracking::Configuration {
  ArithmeticTaintedLocalUnderflowConfig() { this = "ArithmeticTaintedLocalUnderflowConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof LocalUserInput }

  override predicate isSink(DataFlow::Node sink) { underflowSink(_, sink.asExpr()) }

  override predicate isSanitizer(DataFlow::Node n) { underflowBarrier(n) }
}

from string type, int amount
where exists(string qid | qid = "java/tainted-arithmetic-local" and (
  exists(
    ArithmeticTaintedLocalOverflowConfig c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
  or
  exists(
    ArithmeticTaintedLocalUnderflowConfig c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
