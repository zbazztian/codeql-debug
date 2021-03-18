/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id java/tainted-arithmetic-sources-and-sinks
 */


import java
import semmle.code.java.dataflow.FlowSources
import ArithmeticCommon


class RemoteUserInputOverflowConfig extends TaintTracking::Configuration {
  RemoteUserInputOverflowConfig() { this = "ArithmeticTainted.ql:RemoteUserInputOverflowConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  override predicate isSink(DataFlow::Node sink) { overflowSink(_, sink.asExpr()) }

  override predicate isSanitizer(DataFlow::Node n) { overflowBarrier(n) }
}

class RemoteUserInputUnderflowConfig extends TaintTracking::Configuration {
  RemoteUserInputUnderflowConfig() { this = "ArithmeticTainted.ql:RemoteUserInputUnderflowConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  override predicate isSink(DataFlow::Node sink) { underflowSink(_, sink.asExpr()) }

  override predicate isSanitizer(DataFlow::Node n) { underflowBarrier(n) }
}

from DataFlow::Node n, string type
where exists(string qid | qid = "java/tainted-arithmetic" and (
  exists(
    RemoteUserInputUnderflowConfig c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
  or
  exists(
    RemoteUserInputOverflowConfig c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
