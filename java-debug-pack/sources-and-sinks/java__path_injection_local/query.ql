/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id java/path-injection-local-sources-and-sinks
 */


import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.PathCreation

import TaintedPathCommon

class TaintedPathLocalConfig extends TaintTracking::Configuration {
  TaintedPathLocalConfig() { this = "TaintedPathLocalConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof LocalUserInput }

  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr() = any(PathCreation p).getAnInput()
  }
}

from DataFlow::Node n, string type
where exists(string qid | qid = "java/path-injection-local" and (
  exists(
    TaintedPathLocalConfig c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
