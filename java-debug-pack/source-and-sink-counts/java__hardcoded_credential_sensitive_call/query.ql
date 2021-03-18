

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.DataFlow2
import HardcodedCredentials


class HardcodedCredentialSourceCallConfiguration extends DataFlow::Configuration {
  HardcodedCredentialSourceCallConfiguration() {
    this = "HardcodedCredentialSourceCallConfiguration"
  }

  override predicate isSource(DataFlow::Node n) { n.asExpr() instanceof HardcodedExpr }

  override predicate isSink(DataFlow::Node n) { n.asExpr() instanceof FinalCredentialsSourceSink }
}

class HardcodedCredentialSourceCallConfiguration2 extends DataFlow2::Configuration {
  HardcodedCredentialSourceCallConfiguration2() {
    this = "HardcodedCredentialSourceCallConfiguration2"
  }

  override predicate isSource(DataFlow::Node n) { n.asExpr() instanceof CredentialsSourceSink }

  override predicate isSink(DataFlow::Node n) { n.asExpr() instanceof CredentialsSink }
}

class FinalCredentialsSourceSink extends CredentialsSourceSink {
  FinalCredentialsSourceSink() {
    not exists(HardcodedCredentialSourceCallConfiguration2 conf, CredentialsSink other |
      this != other
    |
      conf.hasFlow(DataFlow::exprNode(this), DataFlow::exprNode(other))
    )
  }
}

from string type, int amount
where exists(string qid | qid = "java/hardcoded-credential-sensitive-call" and (
  exists(
    HardcodedCredentialSourceCallConfiguration c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
  or
  exists(
    HardcodedCredentialSourceCallConfiguration2 c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
