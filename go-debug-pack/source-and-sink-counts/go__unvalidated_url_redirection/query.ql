

import go
import semmle.go.security.OpenUrlRedirect::OpenUrlRedirect
import semmle.go.security.SafeUrlFlow

from string type, int amount
where 
exists(
  SafeUrlFlow::Configuration c, string qid |
  qid = "go/unvalidated-url-redirection: " and (
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + c + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n)) and type = qid + c + "Sink"
  )
)
or
exists(
  Configuration c, string qid |
  qid = "go/unvalidated-url-redirection: " and (
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + c + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n)) and type = qid + c + "Sink"
  )
)
select type, amount
