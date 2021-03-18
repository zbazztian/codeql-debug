

import javascript
import semmle.javascript.security.dataflow.PostMessageStar::PostMessageStar

from string type, int amount
where 
exists(
  Configuration c, string qid |
  qid = "js/cross-window-information-leak: " and (
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + c + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n)) and type = qid + c + "Sink"
  )
)
select type, amount
