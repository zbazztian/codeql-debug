

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.ExternalProcess
import ExecCommon

from string type, int amount
where exists(string qid | qid = "java/command-line-injection" and (
  exists(
    RemoteUserInputToArgumentToExecFlowConfig c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
