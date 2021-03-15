/**
 * @name Source and Sink Counts 23
 * @kind metric
 * @metricType sum
 * @problem.severity recommendation
 * @id js/source-and-sink-counts-23
 */
import javascript
import semmle.javascript.security.dataflow.BuildArtifactLeak::BuildArtifactLeak as CONFIG
from TaintTracking::Configuration c, string type, int amount
where amount = strictcount(DataFlow::Node n | c.isSource(n)) and type = "Source"
   or amount = strictcount(DataFlow::Node n | c.isSink(n)) and type = "Sink"
select c + type, amount
