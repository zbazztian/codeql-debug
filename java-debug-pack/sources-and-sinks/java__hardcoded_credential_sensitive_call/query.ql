/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id java/hardcoded-credential-sensitive-call-sources-and-sinks
 */


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

from DataFlow::Node n, string type
where exists(string qid | qid = "java/hardcoded-credential-sensitive-call" and (
  exists(
    HardcodedCredentialSourceCallConfiguration c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
  or
  exists(
    HardcodedCredentialSourceCallConfiguration2 c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
