/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id go/bad-redirect-check-sources-and-sinks
 */


import go
import semmle.go.security.OpenUrlRedirectCustomizations
import DataFlow::PathGraph

StringOps::HasPrefix checkForLeadingSlash(SsaWithFields v) {
  exists(DataFlow::Node substr |
    result.getBaseString() = v.getAUse() and result.getSubstring() = substr
  |
    substr.getStringValue() = "/"
  )
}

predicate isCheckedForSecondSlash(SsaWithFields v) {
  exists(StringOps::HasPrefix hp | hp.getBaseString() = v.getAUse() |
    hp.getSubstring().getStringValue() = "//"
  )
  or
  exists(DataFlow::EqualityTestNode eq, DataFlow::Node slash, DataFlow::ElementReadNode er |
    slash.getStringValue() = "/" and
    er.getBase() = v.getAUse() and
    er.getIndex().getIntValue() = 1 and
    eq.eq(_, er, slash)
  )
  or
  isCleaned(v.getAUse())
}

/**
 * Holds if `nd` is the result of a call to `path.Clean`, or flows into the first argument
 * of such a call, possibly inter-procedurally.
 */
predicate isCleaned(DataFlow::Node nd) {
  exists(Function clean | clean.hasQualifiedName("path", "Clean") |
    nd = clean.getACall()
    or
    nd = clean.getACall().getArgument(0)
  )
  or
  isCleaned(nd.getAPredecessor())
  or
  exists(FuncDef f, FunctionInput inp | nd = inp.getExitNode(f) |
    forex(DataFlow::CallNode call | call.getACallee() = f | isCleaned(inp.getEntryNode(call)))
  )
}

predicate isCheckedForSecondBackslash(SsaWithFields v) {
  exists(StringOps::HasPrefix hp | hp.getBaseString() = v.getAUse() |
    hp.getSubstring().getStringValue() = "/\\"
  )
  or
  exists(DataFlow::EqualityTestNode eq, DataFlow::Node slash, DataFlow::ElementReadNode er |
    slash.getStringValue() = "\\" and
    er.getBase() = v.getAUse() and
    er.getIndex().getIntValue() = 1 and
    eq.eq(_, er, slash)
  )
  or
  urlPath(v.getAUse())
}

/**
 * Holds if `nd` derives its value from the field `url.URL.Path`, possibly inter-procedurally.
 */
predicate urlPath(DataFlow::Node nd) {
  exists(Field f |
    f.hasQualifiedName("net/url", "URL", "Path") and
    nd = f.getARead()
  )
  or
  urlPath(nd.getAPredecessor())
  or
  exists(FuncDef f, FunctionInput inp | nd = inp.getExitNode(f) |
    forex(DataFlow::CallNode call | call.getACallee() = f | urlPath(inp.getEntryNode(call)))
  )
}

class Configuration extends TaintTracking::Configuration {
  Configuration() { this = "BadRedirectCheck" }

  override predicate isSource(DataFlow::Node source) { this.isSource(source, _) }

  /**
   * Holds if `source` is the first node that flows into a use of a variable that is checked by a
   * bad redirect check `check`..
   */
  predicate isSource(DataFlow::Node source, DataFlow::Node check) {
    exists(SsaWithFields v |
      DataFlow::localFlow(source, v.getAUse()) and
      not exists(source.getAPredecessor()) and
      isBadRedirectCheckOrWrapper(check, v)
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(Write w | w.writesField(succ, _, pred))
  }

  override predicate isSanitizerOut(DataFlow::Node node) {
    exists(StringOps::Concatenation conc, int i, int j | i < j |
      node = conc.getOperand(j) and
      exists(conc.getOperand(i))
    )
    or
    exists(DataFlow::CallNode call, int i | call.getTarget().hasQualifiedName("path", "Join") |
      i > 0 and node = call.getArgument(i)
    )
  }

  override predicate isSink(DataFlow::Node sink) { sink instanceof OpenUrlRedirect::Sink }
}

/**
 * Holds there is a check `check` that is a bad redirect check, and `v` is either
 * checked directly by `check` or checked by a function that contains `check`.
 */
predicate isBadRedirectCheckOrWrapper(DataFlow::Node check, SsaWithFields v) {
  isBadRedirectCheck(check, v)
  or
  exists(DataFlow::CallNode call, FuncDef f, FunctionInput input |
    call = f.getACall() and
    input.getEntryNode(call) = v.getAUse() and
    isBadRedirectCheckWrapper(check, f, input)
  )
}

/**
 * Holds if `check` checks that `v` has a leading slash, but not whether it has another slash or a
 * backslash in its second position.
 */
predicate isBadRedirectCheck(DataFlow::Node check, SsaWithFields v) {
  check = checkForLeadingSlash(v) and
  not (
    isCheckedForSecondSlash(v.similar()) and
    isCheckedForSecondBackslash(v.similar())
  )
}

/**
 * Holds if `f` contains a bad redirect check `check`, that checks the parameter `input`.
 */
predicate isBadRedirectCheckWrapper(DataFlow::Node check, FuncDef f, FunctionInput input) {
  exists(SsaWithFields v |
    v.getAUse().getAPredecessor*() = input.getExitNode(f) and
    isBadRedirectCheck(check, v)
  )
}

from DataFlow::Node n, string type
where 
exists(
  Configuration c |
  c.isSource(n) and type = c + "Source" or
  c.isSink(n) and type = c + "Sink"
)
select n, type
