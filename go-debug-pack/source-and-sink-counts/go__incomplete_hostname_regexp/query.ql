

import go


/**
 * Holds if `pattern` is a regular expression pattern for URLs with a host matched by `hostPart`,
 * and `pattern` contains a subtle mistake that allows it to match unexpected hosts.
 */
bindingset[pattern]
predicate isIncompleteHostNameRegexpPattern(string pattern, string hostPart) {
  hostPart =
    pattern
        .regexpCapture("(?i).*?" +

            "(?<!\\\\)[.]" +


            "(([():|?a-z0-9-]+(\\\\)?[.])?" + commonTLD() + ")" + ".*", 1)
}

/** Holds if `b` sets the HTTP status code (represented by a pseudo-header named  `status`) */
predicate writesHttpError(ReachableBasicBlock b) {
  forex(HTTP::HeaderWrite hw |
    hw.getHeaderName() = "status" and hw.asInstruction().getBasicBlock() = b
  |
    exists(string code | code.matches("4__") or code.matches("5__") |
      hw.definesHeader("status", code)
    )
  )
}

/** Holds if starting from `block` a status code representing an error is certainly set. */
predicate onlyErrors(BasicBlock block) {
  writesHttpError(block)
  or
  forex(ReachableBasicBlock pred | pred = block.getAPredecessor() | onlyErrors(pred))
}

/** Gets a node that refers to a handler that is considered to return an HTTP error. */
DataFlow::Node getASafeHandler() {
  exists(Variable v |
    v.hasQualifiedName(ElazarlGoproxy::packagePath(), ["AlwaysReject", "RejectConnect"])
  |
    result = v.getARead()
  )
  or
  exists(Function f |
    onlyErrors(f.getFuncDecl().(ControlFlow::Root).getExitNode().getBasicBlock())
  |
    result = f.getARead()
  )
}

/** Holds if `regexp` is used in a check before `handler` is called. */
predicate regexpGuardsHandler(RegexpPattern regexp, HTTP::RequestHandler handler) {
  handler.guardedBy(DataFlow::exprNode(regexp.getAUse().asExpr().getParent*()))
}

/** Holds if `regexp` guards an HTTP error write. */
predicate regexpGuardsError(RegexpPattern regexp) {
  exists(ControlFlow::ConditionGuardNode cond, RegexpMatchFunction match, DataFlow::CallNode call |
    call.getTarget() = match and
    match.getRegexp(call) = regexp
  |
    cond.ensures(match.getResult().getNode(call).getASuccessor*(), true) and
    cond.dominates(any(ReachableBasicBlock b | writesHttpError(b)))
  )
}

class Config extends DataFlow::Configuration {
  Config() { this = "IncompleteHostNameRegexp::Config" }

  predicate isSource(DataFlow::Node source, string hostPart) {
    exists(Expr e |
      e = source.asExpr() and
      isIncompleteHostNameRegexpPattern(e.getStringValue(), hostPart)
    |
      e instanceof StringLit
      or
      e instanceof AddExpr and
      not isIncompleteHostNameRegexpPattern(e.(AddExpr).getAnOperand().getStringValue(), _)
    )
  }

  override predicate isSource(DataFlow::Node source) { isSource(source, _) }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof RegexpPattern and
    forall(HTTP::RequestHandler handler | regexpGuardsHandler(sink, handler) |
      not handler = getASafeHandler()
    ) and
    not regexpGuardsError(sink)
  }
}

from string type, int amount
where exists(string qid | qid = "go/incomplete-hostname-regexp" and (
  exists(
    Config c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
