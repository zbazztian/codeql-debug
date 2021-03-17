

import go
import DataFlow::PathGraph
import semmle.go.security.UnsafeUnzipSymlink::UnsafeUnzipSymlink

from string type, int amount
where 
exists(
  SymlinkConfiguration c |
  amount = count(DataFlow::Node n | c.isSource(n)) and type = c + "Source" or
  amount = count(DataFlow::Node n | c.isSink(n)) and type = c + "Sink"
)
select type, amount
