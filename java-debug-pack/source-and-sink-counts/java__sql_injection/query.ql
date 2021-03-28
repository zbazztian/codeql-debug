

import java
import semmle.code.java.dataflow.FlowSources
import SqlInjectionLib

from string type, int amount
where exists(string qid | qid = "java/sql-injection" and (
  exists(
    QueryInjectionFlowConfig c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
