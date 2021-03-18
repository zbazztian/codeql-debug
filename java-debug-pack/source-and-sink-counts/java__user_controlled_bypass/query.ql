

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.SensitiveActions
import semmle.code.java.controlflow.Dominance
import semmle.code.java.controlflow.Guards


/**
 * Calls to a sensitive method that are controlled by a condition
 * on the given expression.
 */
predicate conditionControlsMethod(MethodAccess m, Expr e) {
  exists(ConditionBlock cb, SensitiveExecutionMethod def, boolean cond |
    cb.controls(m.getBasicBlock(), cond) and
    def = m.getMethod() and
    not cb.controls(def.getAReference().getBasicBlock(), cond.booleanNot()) and
    e = cb.getCondition()
  )
}

class ConditionalBypassFlowConfig extends TaintTracking::Configuration {
  ConditionalBypassFlowConfig() { this = "ConditionalBypassFlowConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof UserInput }

  override predicate isSink(DataFlow::Node sink) { conditionControlsMethod(_, sink.asExpr()) }
}

from string type, int amount
where exists(string qid | qid = "java/user-controlled-bypass" and (
  exists(
    ConditionalBypassFlowConfig c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
