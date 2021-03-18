/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id java/tainted-format-string-local-sources-and-sinks
 */


import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.StringFormat


class ExternallyControlledFormatStringLocalConfig extends TaintTracking::Configuration {
  ExternallyControlledFormatStringLocalConfig() {
    this = "ExternallyControlledFormatStringLocalConfig"
  }

  override predicate isSource(DataFlow::Node source) { source instanceof LocalUserInput }

  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr() = any(StringFormat formatCall).getFormatArgument()
  }
}

from DataFlow::Node n, string type
where exists(string qid | qid = "java/tainted-format-string-local" and (
  exists(
    ExternallyControlledFormatStringLocalConfig c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
