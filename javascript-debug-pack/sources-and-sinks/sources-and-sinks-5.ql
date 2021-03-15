/**
 * @name Sources and Sinks 5
 * @kind problem
 * @problem.severity recommendation
 * @id js/sources-and-sinks-5
 */
import semmle.javascript.security.dataflow.XssThroughDom::XssThroughDom as CONFIG
from TaintTracking::Configuration c, DataFlow::Node n, string type
where c.isSource(n) and type = "Source" or c.isSink(n) and type = "Sink"
select n, c + type
