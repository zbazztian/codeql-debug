/**
 * @name Sources and Sinks 34
 * @kind problem
 * @problem.severity recommendation
 * @id js/sources-and-sinks-34
 */
import javascript
import semmle.javascript.security.dataflow.Xxe::Xxe as CONFIG
from TaintTracking::Configuration c, DataFlow::Node n, string type
where c.isSource(n) and type = "Source" or c.isSink(n) and type = "Sink"
select n, c + type
