/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id py/reflective-xss-sources-and-sinks
 */


import python
import semmle.python.security.dataflow.ReflectedXSS

from DataFlow::Node n, string type
where exists(string qid | qid = "py/reflective-xss" and (
  exists(
    ReflectedXssConfiguration c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
