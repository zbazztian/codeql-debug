/**
 * @name Source and Sink Counts 22
 * @kind metric
 * @metricType sum
 * @problem.severity recommendation
 * @id js/source-and-sink-counts-22
 */
import javascript
import semmle.javascript.security.dataflow.StackTraceExposure::StackTraceExposure as CONFIG
from TaintTracking::Configuration c, string type, int amount
where amount = strictcount(DataFlow::Node n | c.isSource(n)) and type = "Source"
   or amount = strictcount(DataFlow::Node n | c.isSink(n)) and type = "Sink"
select c + type, amount
