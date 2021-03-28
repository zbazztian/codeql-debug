/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id java/command-line-injection-sources-and-sinks
 */


import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.ExternalProcess
import ExecCommon

from DataFlow::Node n, string type
where exists(string qid | qid = "java/command-line-injection" and (
  exists(
    RemoteUserInputToArgumentToExecFlowConfig c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
