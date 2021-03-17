

import go
import semmle.go.security.XPathInjection::XPathInjection


/** Holds if `node` is either a string or a byte slice */
predicate isStringOrByte(DataFlow::PathNode node) {
  exists(Type t | t = node.getNode().getType().getUnderlyingType() |
    t instanceof StringType or t instanceof ByteSliceType
  )
}

from string type, int amount
where 
exists(
  Configuration c |
  amount = count(DataFlow::Node n | c.isSource(n)) and type = c + "Source" or
  amount = count(DataFlow::Node n | c.isSink(n)) and type = c + "Sink"
)
select type, amount
