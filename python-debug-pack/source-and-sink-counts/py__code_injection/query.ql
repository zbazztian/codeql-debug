

import python
import semmle.python.security.dataflow.CodeInjection

from string type, int amount
where exists(string qid | qid = "py/code-injection" and (
  exists(
    CodeInjectionConfiguration c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
