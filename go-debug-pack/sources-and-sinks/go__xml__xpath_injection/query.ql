/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id go/xml/xpath-injection-sources-and-sinks
 */


import go
import semmle.go.security.XPathInjection::XPathInjection


/** Holds if `node` is either a string or a byte slice */
predicate isStringOrByte(DataFlow::PathNode node) {
  exists(Type t | t = node.getNode().getType().getUnderlyingType() |
    t instanceof StringType or t instanceof ByteSliceType
  )
}

from DataFlow::Node n, string type
where 
exists(
  Configuration c |
  c.isSource(n) and type = c + "Source" or
  c.isSink(n) and type = c + "Sink"
)
select n, type
