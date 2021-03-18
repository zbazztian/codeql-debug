

import go
import semmle.go.security.SqlInjection

from string type, int amount
where 
exists(
  SqlInjection::Configuration c, string qid |
  qid = "go/sql-injection: " and (
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + c + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n)) and type = qid + c + "Sink"
  )
)
select type, amount
