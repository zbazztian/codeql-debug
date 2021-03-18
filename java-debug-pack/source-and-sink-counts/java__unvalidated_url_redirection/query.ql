

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.UrlRedirect


class UrlRedirectConfig extends TaintTracking::Configuration {
  UrlRedirectConfig() { this = "UrlRedirectConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof UrlRedirectSink }
}

from string type, int amount
where exists(string qid | qid = "java/unvalidated-url-redirection" and (
  exists(
    UrlRedirectConfig c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
