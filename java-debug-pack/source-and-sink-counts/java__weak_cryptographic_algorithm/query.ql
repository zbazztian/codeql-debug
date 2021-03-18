

import java
import semmle.code.java.security.Encryption
import semmle.code.java.dataflow.TaintTracking
import DataFlow


private class ShortStringLiteral extends StringLiteral {
  ShortStringLiteral() { getLiteral().length() < 100 }
}

class BrokenAlgoLiteral extends ShortStringLiteral {
  BrokenAlgoLiteral() {
    getValue().regexpMatch(getInsecureAlgorithmRegex()) and

    not getValue().regexpMatch(".*\\p{IsLowercase} des \\p{IsLetter}.*")
  }
}

class InsecureCryptoConfiguration extends TaintTracking::Configuration {
  InsecureCryptoConfiguration() { this = "BrokenCryptoAlgortihm::InsecureCryptoConfiguration" }

  override predicate isSource(Node n) { n.asExpr() instanceof BrokenAlgoLiteral }

  override predicate isSink(Node n) { exists(CryptoAlgoSpec c | n.asExpr() = c.getAlgoSpec()) }

  override predicate isSanitizer(DataFlow::Node node) {
    node.getType() instanceof PrimitiveType or node.getType() instanceof BoxedType
  }
}

from string type, int amount
where exists(string qid | qid = "java/weak-cryptographic-algorithm" and (
  exists(
    InsecureCryptoConfiguration c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
