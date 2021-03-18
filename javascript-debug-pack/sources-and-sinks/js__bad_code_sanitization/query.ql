/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id js/bad-code-sanitization-sources-and-sinks
 */


import javascript
import semmle.javascript.security.dataflow.ImproperCodeSanitization::ImproperCodeSanitization

private import semmle.javascript.heuristics.HeuristicSinks
private import semmle.javascript.security.dataflow.CodeInjectionCustomizations

/**
 * Gets a type-tracked instance of `RemoteFlowSource` using type-tracker `t`.
 */
private DataFlow::Node remoteFlow(DataFlow::TypeTracker t) {
  t.start() and
  result instanceof RemoteFlowSource
  or
  exists(DataFlow::TypeTracker t2, DataFlow::Node prev | prev = remoteFlow(t2) |
    t2 = t.smallstep(prev, result)
    or
    any(TaintTracking::AdditionalTaintStep dts).step(prev, result) and
    t = t2
  )
}

/**
 * Gets a type-tracked reference to a `RemoteFlowSource`.
 */
private DataFlow::Node remoteFlow() { result = remoteFlow(DataFlow::TypeTracker::end()) }

/**
 * Gets a type-back-tracked instance of a code injection sink using type-tracker `t`.
 */
private DataFlow::Node endsInCodeInjectionSink(DataFlow::TypeBackTracker t) {
  t.start() and
  (
    result instanceof CodeInjection::Sink
    or
    result instanceof HeuristicCodeInjectionSink and
    not result instanceof StringOps::ConcatenationRoot // the heuristic CodeInjection sink looks for string-concats, we are not interrested in those here.
  )
  or
  exists(DataFlow::TypeBackTracker t2 | t = t2.smallstep(result, endsInCodeInjectionSink(t2)))
}

/**
 * Gets a reference to to a data-flow node that ends in a code injection sink.
 */
private DataFlow::Node endsInCodeInjectionSink() {
  result = endsInCodeInjectionSink(DataFlow::TypeBackTracker::end())
}

from DataFlow::Node n, string type
where 
exists(
  Configuration c, string qid |
  qid = "js/bad-code-sanitization: " and (
    c.isSource(n) and type = qid + c + "Source" or
    c.isSink(n) and type = qid + c + "Sink"
  )
)
select n, type
