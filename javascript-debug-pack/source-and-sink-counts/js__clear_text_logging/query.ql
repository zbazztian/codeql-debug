

import javascript
import semmle.javascript.security.dataflow.CleartextLogging::CleartextLogging


/**
 * Holds if `tl` is used in a browser environment.
 */
predicate inBrowserEnvironment(TopLevel tl) {
  tl instanceof InlineScript
  or
  tl instanceof CodeInAttribute
  or
  exists(GlobalVarAccess e | e.getTopLevel() = tl | e.getName() = "window")
  or
  exists(Module m | inBrowserEnvironment(m) |
    tl = m.getAnImportedModule() or
    m = tl.(Module).getAnImportedModule()
  )
}

from string type, int amount
where exists(string qid | qid = "js/clear-text-logging" and (
  exists(
    Configuration c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
