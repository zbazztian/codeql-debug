

import go
import semmle.go.security.RequestForgery::RequestForgery
import semmle.go.security.SafeUrlFlow

from string type, int amount
where 
exists(
  Configuration c, string qid |
  qid = "go/request-forgery: " and (
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + c + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n)) and type = qid + c + "Sink"
  )
)
or
exists(
  SafeUrlFlow::Configuration c, string qid |
  qid = "go/request-forgery: " and (
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + c + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n)) and type = qid + c + "Sink"
  )
)
select type, amount
