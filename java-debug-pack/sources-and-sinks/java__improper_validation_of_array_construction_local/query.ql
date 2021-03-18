/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id java/improper-validation-of-array-construction-local-sources-and-sinks
 */


import java
import ArraySizing
import semmle.code.java.dataflow.FlowSources


class Conf extends TaintTracking::Configuration {
  Conf() { this = "LocalUserInputTocanThrowOutOfBoundsDueToEmptyArrayConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof LocalUserInput }

  override predicate isSink(DataFlow::Node sink) {
    any(CheckableArrayAccess caa).canThrowOutOfBoundsDueToEmptyArray(sink.asExpr(), _)
  }
}

from DataFlow::Node n, string type
where exists(string qid | qid = "java/improper-validation-of-array-construction-local" and (
  exists(
    Conf c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
