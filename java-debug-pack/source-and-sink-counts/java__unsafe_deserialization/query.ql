

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.UnsafeDeserializationQuery


class UnsafeDeserializationConfig extends TaintTracking::Configuration {
  UnsafeDeserializationConfig() { this = "UnsafeDeserializationConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof UnsafeDeserializationSink }
}

from string type, int amount
where exists(string qid | qid = "java/unsafe-deserialization" and (
  exists(
    UnsafeDeserializationConfig c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
