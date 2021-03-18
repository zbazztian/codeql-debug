/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id java/improper-validation-of-array-construction-code-specified-sources-and-sinks
 */


import java
import ArraySizing


class BoundedFlowSourceConf extends DataFlow::Configuration {
  BoundedFlowSourceConf() { this = "BoundedFlowSource" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof BoundedFlowSource and

    not source.(BoundedFlowSource).lowerBound() > 0
  }

  override predicate isSink(DataFlow::Node sink) {
    any(CheckableArrayAccess caa).canThrowOutOfBoundsDueToEmptyArray(sink.asExpr(), _)
  }
}

from DataFlow::Node n, string type
where exists(string qid | qid = "java/improper-validation-of-array-construction-code-specified" and (
  exists(
    BoundedFlowSourceConf c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
