/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id py/code-injection-sources-and-sinks
 */


import python
import semmle.python.security.dataflow.CodeInjection

from DataFlow::Node n, string type
where exists(string qid | qid = "py/code-injection" and (
  exists(
    CodeInjectionConfiguration c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
