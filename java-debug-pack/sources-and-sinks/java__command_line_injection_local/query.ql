/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id java/command-line-injection-local-sources-and-sinks
 */


import semmle.code.java.Expr
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.ExternalProcess
import semmle.code.java.security.CommandArguments


class LocalUserInputToArgumentToExecFlowConfig extends TaintTracking::Configuration {
  LocalUserInputToArgumentToExecFlowConfig() { this = "LocalUserInputToArgumentToExecFlowConfig" }

  override predicate isSource(DataFlow::Node src) { src instanceof LocalUserInput }

  override predicate isSink(DataFlow::Node sink) { sink.asExpr() instanceof ArgumentToExec }

  override predicate isSanitizer(DataFlow::Node node) {
    node.getType() instanceof PrimitiveType
    or
    node.getType() instanceof BoxedType
    or
    isSafeCommandArgument(node.asExpr())
  }
}

from DataFlow::Node n, string type
where exists(string qid | qid = "java/command-line-injection-local" and (
  exists(
    LocalUserInputToArgumentToExecFlowConfig c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
