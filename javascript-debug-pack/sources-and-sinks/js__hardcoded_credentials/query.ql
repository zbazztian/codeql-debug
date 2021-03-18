/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id js/hardcoded-credentials-sources-and-sinks
 */


import javascript
private import semmle.javascript.security.dataflow.HardcodedCredentials::HardcodedCredentials

from DataFlow::Node n, string type
where exists(string qid | qid = "js/hardcoded-credentials" and (
  exists(
    Configuration c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
