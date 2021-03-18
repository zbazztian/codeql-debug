

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

from string type, int amount
where exists(string qid | qid = "java/uncontrolled-arithmetic" and (
  exists(
    ArithmeticUncontrolledUnderflowConfig c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
  or
  exists(
    ArithmeticUncontrolledOverflowConfig c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
