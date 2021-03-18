

import javascript
import semmle.javascript.security.dataflow.ClientSideUrlRedirect::ClientSideUrlRedirect

from string type, int amount
where 
exists(
  Configuration c, string qid |
  qid = "js/client-side-unvalidated-url-redirection: " and (
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + c + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n)) and type = qid + c + "Sink"
  )
)
select type, amount
