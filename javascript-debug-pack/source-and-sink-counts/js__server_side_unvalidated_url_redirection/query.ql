

import javascript
import semmle.javascript.security.dataflow.ServerSideUrlRedirect::ServerSideUrlRedirect

from string type, int amount
where exists(string qid | qid = "js/server-side-unvalidated-url-redirection" and (
  exists(
    Configuration c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
