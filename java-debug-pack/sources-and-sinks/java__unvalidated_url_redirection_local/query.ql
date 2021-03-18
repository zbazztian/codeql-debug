/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id java/unvalidated-url-redirection-local-sources-and-sinks
 */


import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.UrlRedirect


class UrlRedirectLocalConfig extends TaintTracking::Configuration {
  UrlRedirectLocalConfig() { this = "UrlRedirectLocalConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof LocalUserInput }

  override predicate isSink(DataFlow::Node sink) { sink instanceof UrlRedirectSink }
}

from DataFlow::Node n, string type
where exists(string qid | qid = "java/unvalidated-url-redirection-local" and (
  exists(
    UrlRedirectLocalConfig c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
