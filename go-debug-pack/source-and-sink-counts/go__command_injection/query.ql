

import go
import semmle.go.security.CommandInjection
import DataFlow::PathGraph

from string type, int amount
where 
exists(
  CommandInjection::Configuration c |
  amount = count(DataFlow::Node n | c.isSource(n)) and type = c + "Source" or
  amount = count(DataFlow::Node n | c.isSink(n)) and type = c + "Sink"
)
or
exists(
  CommandInjection::DoubleDashSanitizingConfiguration c |
  amount = count(DataFlow::Node n | c.isSource(n)) and type = c + "Source" or
  amount = count(DataFlow::Node n | c.isSink(n)) and type = c + "Sink"
)
select type, amount
