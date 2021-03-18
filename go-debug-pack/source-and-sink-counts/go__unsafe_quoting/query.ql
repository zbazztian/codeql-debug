

import go
import semmle.go.security.StringBreak

from string type, int amount
where 
exists(
  StringBreak::Configuration c, string qid |
  qid = "go/unsafe-quoting: " and (
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + c + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n)) and type = qid + c + "Sink"
  )
)
select type, amount
