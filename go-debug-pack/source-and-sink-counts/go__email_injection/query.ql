

import go
import DataFlow::PathGraph
import EmailInjection::EmailInjection

from string type, int amount
where 
exists(
  Configuration c |
  amount = count(DataFlow::Node n | c.isSource(n)) and type = c + "Source" or
  amount = count(DataFlow::Node n | c.isSink(n)) and type = c + "Sink"
)
select type, amount
