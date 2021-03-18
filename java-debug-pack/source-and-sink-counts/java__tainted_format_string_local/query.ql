

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

from string type, int amount
where exists(string qid | qid = "java/tainted-format-string-local" and (
  exists(
    ExternallyControlledFormatStringLocalConfig c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
