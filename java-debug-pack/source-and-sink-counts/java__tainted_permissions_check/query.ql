

import java
import semmle.code.java.dataflow.FlowSources


class TypeShiroSubject extends RefType {
  TypeShiroSubject() { this.getQualifiedName() = "org.apache.shiro.subject.Subject" }
}

class TypeShiroWCPermission extends RefType {
  TypeShiroWCPermission() {
    this.getQualifiedName() = "org.apache.shiro.authz.permission.WildcardPermission"
  }
}

abstract class PermissionsConstruction extends Top {
  abstract Expr getInput();
}

class PermissionsCheckMethodAccess extends MethodAccess, PermissionsConstruction {
  PermissionsCheckMethodAccess() {
    exists(Method m | m = this.getMethod() |
      m.getDeclaringType() instanceof TypeShiroSubject and
      m.getName() = "isPermitted"
      or
      m.getName().toLowerCase().matches("%permitted%") and
      m.getNumberOfParameters() = 1
    )
  }

  override Expr getInput() { result = getArgument(0) }
}

class WCPermissionConstruction extends ClassInstanceExpr, PermissionsConstruction {
  WCPermissionConstruction() {
    this.getConstructor().getDeclaringType() instanceof TypeShiroWCPermission
  }

  override Expr getInput() { result = getArgument(0) }
}

class TaintedPermissionsCheckFlowConfig extends TaintTracking::Configuration {
  TaintedPermissionsCheckFlowConfig() { this = "TaintedPermissionsCheckFlowConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof UserInput }

  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr() = any(PermissionsConstruction p).getInput()
  }
}

from string type, int amount
where exists(string qid | qid = "java/tainted-permissions-check" and (
  exists(
    TaintedPermissionsCheckFlowConfig c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
