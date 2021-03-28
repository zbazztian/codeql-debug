/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id py/command-line-injection-sources-and-sinks
 */


import python
import semmle.python.security.dataflow.CommandInjection

from DataFlow::Node n, string type
where exists(string qid | qid = "py/command-line-injection" and (
  exists(
    CommandInjectionConfiguration c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
