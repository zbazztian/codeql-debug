/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id java/potentially-weak-cryptographic-algorithm-sources-and-sinks
 */


import java
import semmle.code.java.security.Encryption
import semmle.code.java.dataflow.TaintTracking
import DataFlow
import semmle.code.java.dispatch.VirtualDispatch


private class ShortStringLiteral extends StringLiteral {
  ShortStringLiteral() { getLiteral().length() < 100 }
}

class InsecureAlgoLiteral extends ShortStringLiteral {
  InsecureAlgoLiteral() {

    getValue().length() > 1 and
    exists(string s | s = getLiteral() |
      not s.regexpMatch(getSecureAlgorithmRegex()) and

      not s.regexpMatch(getInsecureAlgorithmRegex())
    )
  }
}

predicate objectToString(MethodAccess ma) {
  exists(Method m |
    m = ma.getMethod() and
    m.hasName("toString") and
    m.getDeclaringType() instanceof TypeObject and
    variableTrack(ma.getQualifier()).getType().getErasure() instanceof TypeObject
  )
}

class StringContainer extends RefType {
  StringContainer() {
    this instanceof TypeString or
    this.hasQualifiedName("java.lang", "StringBuilder") or
    this.hasQualifiedName("java.lang", "StringBuffer") or
    this.hasQualifiedName("java.util", "StringTokenizer") or
    this.(Array).getComponentType() instanceof StringContainer
  }
}

class InsecureCryptoConfiguration extends TaintTracking::Configuration {
  InsecureCryptoConfiguration() { this = "InsecureCryptoConfiguration" }

  override predicate isSource(Node n) { n.asExpr() instanceof InsecureAlgoLiteral }

  override predicate isSink(Node n) { exists(CryptoAlgoSpec c | n.asExpr() = c.getAlgoSpec()) }

  override predicate isSanitizer(Node n) {
    objectToString(n.asExpr()) or
    not n.getType().getErasure() instanceof StringContainer
  }
}

from DataFlow::Node n, string type
where exists(string qid | qid = "java/potentially-weak-cryptographic-algorithm" and (
  exists(
    InsecureCryptoConfiguration c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
