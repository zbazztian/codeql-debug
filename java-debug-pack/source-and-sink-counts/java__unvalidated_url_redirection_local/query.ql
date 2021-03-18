

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.UrlRedirect


class UrlRedirectLocalConfig extends TaintTracking::Configuration {
  UrlRedirectLocalConfig() { this = "UrlRedirectLocalConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof LocalUserInput }

  override predicate isSink(DataFlow::Node sink) { sink instanceof UrlRedirectSink }
}

from string type, int amount
where exists(string qid | qid = "java/unvalidated-url-redirection-local" and (
  exists(
    UrlRedirectLocalConfig c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
