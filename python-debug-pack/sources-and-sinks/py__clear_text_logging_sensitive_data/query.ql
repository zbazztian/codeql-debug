/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id py/clear-text-logging-sensitive-data-sources-and-sinks
 */


import python
import semmle.python.security.Paths
import semmle.python.dataflow.TaintTracking
import semmle.python.security.SensitiveData
import semmle.python.security.ClearText

class CleartextLoggingConfiguration extends TaintTracking::Configuration {
  CleartextLoggingConfiguration() { this = "ClearTextLogging" }

  override predicate isSource(DataFlow::Node src, TaintKind kind) {
    src.asCfgNode().(SensitiveData::Source).isSourceOf(kind)
  }

  override predicate isSink(DataFlow::Node sink, TaintKind kind) {
    sink.asCfgNode() instanceof ClearTextLogging::Sink and
    kind instanceof SensitiveData
  }
}

from DataFlow::Node n, string type
where exists(string qid | qid = "py/clear-text-logging-sensitive-data" and (
  exists(
    CleartextLoggingConfiguration c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
