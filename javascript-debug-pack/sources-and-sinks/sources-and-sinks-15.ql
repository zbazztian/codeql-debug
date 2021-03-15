/**
 * @name Sources and Sinks 15
 * @kind problem
 * @problem.severity recommendation
 * @id js/sources-and-sinks-15
 */
import semmle.javascript.security.dataflow.ImproperCodeSanitization::ImproperCodeSanitization as CONFIG
from TaintTracking::Configuration c, DataFlow::Node n, string type
where c.isSource(n) and type = "Source" or c.isSink(n) and type = "Sink"
select n, c + type
