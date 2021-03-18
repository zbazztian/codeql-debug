/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id js/clear-text-logging-sources-and-sinks
 */


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

from DataFlow::Node n, string type
where exists(string qid | qid = "js/clear-text-logging" and (
  exists(
    Configuration c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
