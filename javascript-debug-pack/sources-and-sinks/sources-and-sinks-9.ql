/**
 * @name Sources and Sinks 9
 * @kind problem
 * @problem.severity recommendation
 * @id js/sources-and-sinks-9
 */
import javascript
import semmle.javascript.security.dataflow.IndirectCommandInjection::IndirectCommandInjection as CONFIG
from TaintTracking::Configuration c, DataFlow::Node n, string type
where c.isSource(n) and type = "Source" or c.isSink(n) and type = "Sink"
select n, c + type
