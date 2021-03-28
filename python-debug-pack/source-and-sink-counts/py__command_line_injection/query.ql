

import python
import semmle.python.security.dataflow.CommandInjection

from string type, int amount
where exists(string qid | qid = "py/command-line-injection" and (
  exists(
    CommandInjectionConfiguration c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
