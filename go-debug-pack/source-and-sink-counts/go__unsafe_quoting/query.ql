

import go
import semmle.go.security.StringBreak
import DataFlow::PathGraph

from string type, int amount
where 
exists(
  StringBreak::Configuration c |
  amount = count(DataFlow::Node n | c.isSource(n)) and type = c + "Source" or
  amount = count(DataFlow::Node n | c.isSink(n)) and type = c + "Sink"
)
select type, amount
