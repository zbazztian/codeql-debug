/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id java/improper-validation-of-array-index-sources-and-sinks
 */


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

from DataFlow::Node n, string type
where exists(string qid | qid = "java/improper-validation-of-array-index" and (
  exists(
    Conf c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
