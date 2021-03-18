

import semmle.code.java.Expr
import semmle.code.java.dataflow.FlowSources
import SqlInjectionLib


class LocalUserInputToQueryInjectionFlowConfig extends TaintTracking::Configuration {
  LocalUserInputToQueryInjectionFlowConfig() { this = "LocalUserInputToQueryInjectionFlowConfig" }

  override predicate isSource(DataFlow::Node src) { src instanceof LocalUserInput }

  override predicate isSink(DataFlow::Node sink) { sink instanceof QueryInjectionSink }

  override predicate isSanitizer(DataFlow::Node node) {
    node.getType() instanceof PrimitiveType or node.getType() instanceof BoxedType
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    any(AdditionalQueryInjectionTaintStep s).step(node1, node2)
  }
}

from string type, int amount
where exists(string qid | qid = "java/sql-injection-local" and (
  exists(
    LocalUserInputToQueryInjectionFlowConfig c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
