/**
 * @name Sources and Sinks 36
 * @kind problem
 * @problem.severity recommendation
 * @id js/sources-and-sinks-36
 */
import javascript
import semmle.javascript.security.dataflow.XpathInjection::XpathInjection as CONFIG
from TaintTracking::Configuration c, DataFlow::Node n, string type
where c.isSource(n) and type = "Source" or c.isSink(n) and type = "Sink"
select n, c + type