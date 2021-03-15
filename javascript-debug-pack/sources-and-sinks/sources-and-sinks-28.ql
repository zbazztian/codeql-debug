/**
 * @name Sources and Sinks 28
 * @kind problem
 * @problem.severity recommendation
 * @id js/sources-and-sinks-28
 */
import semmle.javascript.security.dataflow.CorsMisconfigurationForCredentials::CorsMisconfigurationForCredentials as CONFIG
from TaintTracking::Configuration c, DataFlow::Node n, string type
where c.isSource(n) and type = "Source" or c.isSink(n) and type = "Sink"
select n, c + type
