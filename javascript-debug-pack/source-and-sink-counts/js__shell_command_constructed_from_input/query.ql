

import javascript
import semmle.javascript.security.dataflow.UnsafeShellCommandConstruction::UnsafeShellCommandConstruction

from string type, int amount
where 
exists(
  Configuration c, string qid |
  qid = "js/shell-command-constructed-from-input: " and (
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + c + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n)) and type = qid + c + "Sink"
  )
)
select type, amount
