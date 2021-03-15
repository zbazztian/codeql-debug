/**
 * @name Sources and Sinks 10
 * @kind problem
 * @problem.severity recommendation
 * @id js/sources-and-sinks-10
 */
import javascript
import semmle.javascript.security.dataflow.ShellCommandInjectionFromEnvironment::ShellCommandInjectionFromEnvironment as CONFIG
from TaintTracking::Configuration c, DataFlow::Node n, string type
where c.isSource(n) and type = "Source" or c.isSink(n) and type = "Sink"
select n, c + type
