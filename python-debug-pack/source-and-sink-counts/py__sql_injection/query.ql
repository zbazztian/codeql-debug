

import python
import semmle.python.security.dataflow.SqlInjection

from string type, int amount
where exists(string qid | qid = "py/sql-injection" and (
  exists(
    SQLInjectionConfiguration c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
