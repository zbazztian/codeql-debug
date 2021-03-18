/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id java/sql-injection-local-sources-and-sinks
 */


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

from DataFlow::Node n, string type
where exists(string qid | qid = "java/sql-injection-local" and (
  exists(
    LocalUserInputToQueryInjectionFlowConfig c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
