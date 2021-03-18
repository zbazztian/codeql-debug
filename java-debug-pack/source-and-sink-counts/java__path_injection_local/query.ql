

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

from string type, int amount
where exists(string qid | qid = "java/path-injection-local" and (
  exists(
    TaintedPathLocalConfig c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
