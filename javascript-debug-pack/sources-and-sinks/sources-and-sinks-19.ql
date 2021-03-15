/**
 * @name Sources and Sinks 19
 * @kind problem
 * @problem.severity recommendation
 * @id js/sources-and-sinks-19
 */
import semmle.javascript.security.dataflow.TaintedFormatString::TaintedFormatString as CONFIG
from TaintTracking::Configuration c, DataFlow::Node n, string type
where c.isSource(n) and type = "Source" or c.isSink(n) and type = "Sink"
select n, c + type
