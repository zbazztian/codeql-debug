

import go
import semmle.go.security.InsecureFeatureFlag::InsecureFeatureFlag


/**
 * A flag indicating the program is in debug or development mode, or that stack
 * dumps have been specifically enabled.
 */
class DebugModeFlag extends FlagKind {
  DebugModeFlag() { this = "debugMode" }

  bindingset[result]
  override string getAFlagName() {
    result.regexpMatch("(?i).*(trace|debug|devel|(enable|disable|print)stack).*")
  }
}

/**
 * The function `runtime.Stack`, which emits a stack trace.
 */
class StackFunction extends Function {
  StackFunction() { this.hasQualifiedName("runtime", "Stack") }
}

/**
 * The function `runtime/debug.Stack`, which emits a stack trace.
 */
class DebugStackFunction extends Function {
  DebugStackFunction() { this.hasQualifiedName("runtime/debug", "Stack") }
}

/**
 * A taint-tracking configuration that looks for stack traces being written to
 * an HTTP response body without an intervening debug- or development-mode conditional.
 */
class StackTraceExposureConfig extends TaintTracking::Configuration {
  StackTraceExposureConfig() { this = "StackTraceExposureConfig" }

  override predicate isSource(DataFlow::Node node) {
    node.(DataFlow::PostUpdateNode).getPreUpdateNode() =
      any(StackFunction f).getACall().getArgument(0) or
    node = any(DebugStackFunction f).getACall().getResult()
  }

  override predicate isSink(DataFlow::Node node) { node instanceof HTTP::ResponseBody }

  override predicate isSanitizer(DataFlow::Node node) {



    exists(ControlFlow::ConditionGuardNode cgn |
      cgn.ensures(any(DebugModeFlag f).getAFlag().getANode(), _)
    |
      cgn.dominates(node.getBasicBlock())
    )
  }
}

from string type, int amount
where exists(string qid | qid = "go/stack-trace-exposure" and (
  exists(
    StackTraceExposureConfig c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
