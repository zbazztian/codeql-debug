

import go
import semmle.go.security.StoredCommand

from string type, int amount
where 
exists(
  StoredCommand::Configuration c, string qid |
  qid = "go/stored-command: " and (
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + c + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n)) and type = qid + c + "Sink"
  )
)
select type, amount
