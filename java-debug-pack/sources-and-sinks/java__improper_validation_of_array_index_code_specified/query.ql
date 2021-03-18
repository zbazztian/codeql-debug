/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id java/improper-validation-of-array-index-code-specified-sources-and-sinks
 */


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

from DataFlow::Node n, string type
where exists(string qid | qid = "java/improper-validation-of-array-index-code-specified" and (
  exists(
    BoundedFlowSourceConf c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
