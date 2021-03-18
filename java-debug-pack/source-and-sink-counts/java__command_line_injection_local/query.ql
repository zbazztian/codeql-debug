

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

from string type, int amount
where exists(string qid | qid = "java/command-line-injection-local" and (
  exists(
    LocalUserInputToArgumentToExecFlowConfig c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
