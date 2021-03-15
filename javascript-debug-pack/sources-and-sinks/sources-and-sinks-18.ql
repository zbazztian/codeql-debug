/**
 * @name Sources and Sinks 18
 * @kind problem
 * @problem.severity recommendation
 * @id js/sources-and-sinks-18
 */
import semmle.javascript.security.dataflow.LogInjection::LogInjection as CONFIG
from TaintTracking::Configuration c, DataFlow::Node n, string type
where c.isSource(n) and type = "Source" or c.isSink(n) and type = "Sink"
select n, c + type
