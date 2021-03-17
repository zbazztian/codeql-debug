

import go
import semmle.go.security.OpenUrlRedirect::OpenUrlRedirect
import semmle.go.security.SafeUrlFlow

from string type, int amount
where 
exists(
  Configuration c |
  amount = count(DataFlow::Node n | c.isSource(n)) and type = c + "Source" or
  amount = count(DataFlow::Node n | c.isSink(n)) and type = c + "Sink"
)
or
exists(
  SafeUrlFlow::Configuration c |
  amount = count(DataFlow::Node n | c.isSource(n)) and type = c + "Source" or
  amount = count(DataFlow::Node n | c.isSink(n)) and type = c + "Sink"
)
select type, amount
