/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id java/extreme-value-arithmetic-sources-and-sinks
 */


import java
import semmle.code.java.dataflow.DataFlow
import ArithmeticCommon


abstract class ExtremeValueField extends Field {
  ExtremeValueField() { getType() instanceof IntegralType }
}

class MinValueField extends ExtremeValueField {
  MinValueField() { this.getName() = "MIN_VALUE" }
}

class MaxValueField extends ExtremeValueField {
  MaxValueField() { this.getName() = "MAX_VALUE" }
}

class ExtremeSource extends VarAccess {
  ExtremeSource() { this.getVariable() instanceof ExtremeValueField }
}

class MaxValueFlowConfig extends DataFlow::Configuration {
  MaxValueFlowConfig() { this = "MaxValueFlowConfig" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr().(ExtremeSource).getVariable() instanceof MaxValueField
  }

  override predicate isSink(DataFlow::Node sink) { overflowSink(_, sink.asExpr()) }

  override predicate isBarrierIn(DataFlow::Node n) { isSource(n) }

  override predicate isBarrier(DataFlow::Node n) { overflowBarrier(n) }
}

class MinValueFlowConfig extends DataFlow::Configuration {
  MinValueFlowConfig() { this = "MinValueFlowConfig" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr().(ExtremeSource).getVariable() instanceof MinValueField
  }

  override predicate isSink(DataFlow::Node sink) { underflowSink(_, sink.asExpr()) }

  override predicate isBarrierIn(DataFlow::Node n) { isSource(n) }

  override predicate isBarrier(DataFlow::Node n) { underflowBarrier(n) }
}

predicate query(
  DataFlow::PathNode source, DataFlow::PathNode sink, ArithExpr exp, string effect, Type srctyp
) {
  (
    any(MaxValueFlowConfig c).hasFlowPath(source, sink) and
    overflowSink(exp, sink.getNode().asExpr()) and
    effect = "overflow"
    or
    any(MinValueFlowConfig c).hasFlowPath(source, sink) and
    underflowSink(exp, sink.getNode().asExpr()) and
    effect = "underflow"
  ) and
  srctyp = source.getNode().asExpr().getType()
}

from DataFlow::Node n, string type
where exists(string qid | qid = "java/extreme-value-arithmetic" and (
  exists(
    MaxValueFlowConfig c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
  or
  exists(
    MinValueFlowConfig c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
