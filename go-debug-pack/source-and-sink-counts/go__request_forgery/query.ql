

import go
import semmle.go.security.RequestForgery::RequestForgery
import semmle.go.security.SafeUrlFlow
import DataFlow::PathGraph

from string type, int amount
where 
exists(
  SafeUrlFlow::Configuration c |
  amount = count(DataFlow::Node n | c.isSource(n)) and type = c + "Source" or
  amount = count(DataFlow::Node n | c.isSink(n)) and type = c + "Sink"
)
or
exists(
  Configuration c |
  amount = count(DataFlow::Node n | c.isSource(n)) and type = c + "Source" or
  amount = count(DataFlow::Node n | c.isSink(n)) and type = c + "Sink"
)
select type, amount
