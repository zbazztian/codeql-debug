/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id js/code-injection-sources-and-sinks
 */


import javascript
import semmle.javascript.security.dataflow.CodeInjection::CodeInjection

from DataFlow::Node n, string type
where exists(string qid | qid = "js/code-injection" and (
  exists(
    Configuration c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
