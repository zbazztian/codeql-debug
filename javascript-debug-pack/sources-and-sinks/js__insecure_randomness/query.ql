/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id js/insecure-randomness-sources-and-sinks
 */


import javascript
import semmle.javascript.security.dataflow.InsecureRandomness::InsecureRandomness

from DataFlow::Node n, string type
where 
exists(
  Configuration c, string qid |
  qid = "js/insecure-randomness: " and (
    c.isSource(n) and type = qid + c + "Source" or
    c.isSink(n) and type = qid + c + "Sink"
  )
)
select n, type
