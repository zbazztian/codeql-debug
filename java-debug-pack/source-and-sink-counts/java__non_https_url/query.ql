

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.Networking


class HTTPString extends StringLiteral {
  HTTPString() {

    exists(string s | this.getRepresentedString() = s |
      (

        s = "http"
        or

        s.matches("http://%")
      ) and
      not s.matches("%/localhost%")
    )
  }
}

class URLOpenMethod extends Method {
  URLOpenMethod() {
    this.getDeclaringType().getQualifiedName() = "java.net.URL" and
    (
      this.getName() = "openConnection" or
      this.getName() = "openStream"
    )
  }
}

class HTTPStringToURLOpenMethodFlowConfig extends TaintTracking::Configuration {
  HTTPStringToURLOpenMethodFlowConfig() { this = "HttpsUrls::HTTPStringToURLOpenMethodFlowConfig" }

  override predicate isSource(DataFlow::Node src) { src.asExpr() instanceof HTTPString }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess m |
      sink.asExpr() = m.getQualifier() and m.getMethod() instanceof URLOpenMethod
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(UrlConstructorCall u |
      node1.asExpr() = u.getProtocolArg() and
      node2.asExpr() = u
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    node.getType() instanceof PrimitiveType or node.getType() instanceof BoxedType
  }
}

from string type, int amount
where exists(string qid | qid = "java/non-https-url" and (
  exists(
    HTTPStringToURLOpenMethodFlowConfig c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
