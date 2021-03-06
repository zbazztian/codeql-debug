

import go
import semmle.go.security.XPathInjection::XPathInjection


/** Holds if `node` is either a string or a byte slice */
predicate isStringOrByte(DataFlow::PathNode node) {
  exists(Type t | t = node.getNode().getType().getUnderlyingType() |
    t instanceof StringType or t instanceof ByteSliceType
  )
}

from string type, int amount
where exists(string qid | qid = "go/xml/xpath-injection" and (
  exists(
    Configuration c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
