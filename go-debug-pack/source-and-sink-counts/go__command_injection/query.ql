

import go
import semmle.go.security.CommandInjection

from string type, int amount
where 
exists(
  CommandInjection::DoubleDashSanitizingConfiguration c, string qid |
  qid = "go/command-injection: " and (
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + c + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n)) and type = qid + c + "Sink"
  )
)
or
exists(
  CommandInjection::Configuration c, string qid |
  qid = "go/command-injection: " and (
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + c + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n)) and type = qid + c + "Sink"
  )
)
select type, amount
