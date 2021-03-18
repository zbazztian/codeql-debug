

import go

import semmle.go.security.AllocationSizeOverflow

from string type, int amount
where 
exists(
  AllocationSizeOverflow::Configuration c, string qid |
  qid = "go/allocation-size-overflow: " and (
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + c + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n)) and type = qid + c + "Sink"
  )
)
select type, amount
