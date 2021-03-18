/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id java/uncontrolled-arithmetic-sources-and-sinks
 */


import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.SecurityTests
import ArithmeticCommon


class TaintSource extends DataFlow::ExprNode {
  TaintSource() {

    exists(Method def |
      def = this.getExpr().(MethodAccess).getMethod() and
      (



        def.getName() = "nextInt" or
        def.getName() = "nextLong"
      ) and
      def.getNumberOfParameters() = 0 and
      def.getDeclaringType().hasQualifiedName("java.util", "Random")
    )
    or

    exists(MethodAccess m, Method def |
      m.getAnArgument() = this.getExpr() and
      m.getMethod() = def and
      def.getName() = "nextBytes" and
      def.getNumberOfParameters() = 1 and
      def.getDeclaringType().hasQualifiedName("java.util", "Random")
    )
  }
}

class ArithmeticUncontrolledOverflowConfig extends TaintTracking::Configuration {
  ArithmeticUncontrolledOverflowConfig() { this = "ArithmeticUncontrolledOverflowConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof TaintSource }

  override predicate isSink(DataFlow::Node sink) { overflowSink(_, sink.asExpr()) }

  override predicate isSanitizer(DataFlow::Node n) { overflowBarrier(n) }
}

class ArithmeticUncontrolledUnderflowConfig extends TaintTracking::Configuration {
  ArithmeticUncontrolledUnderflowConfig() { this = "ArithmeticUncontrolledUnderflowConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof TaintSource }

  override predicate isSink(DataFlow::Node sink) { underflowSink(_, sink.asExpr()) }

  override predicate isSanitizer(DataFlow::Node n) { underflowBarrier(n) }
}

from DataFlow::Node n, string type
where exists(string qid | qid = "java/uncontrolled-arithmetic" and (
  exists(
    ArithmeticUncontrolledUnderflowConfig c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
  or
  exists(
    ArithmeticUncontrolledOverflowConfig c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
