/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id java/tainted-arithmetic-local-sources-and-sinks
 */


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

from DataFlow::Node n, string type
where exists(string qid | qid = "java/tainted-arithmetic-local" and (
  exists(
    ArithmeticTaintedLocalOverflowConfig c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
  or
  exists(
    ArithmeticTaintedLocalUnderflowConfig c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
