/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id java/unsafe-hostname-verification-sources-and-sinks
 */


import java
import semmle.code.java.controlflow.Guards
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.Encryption


/**
 * Holds if `m` always returns `true` ignoring any exceptional flow.
 */
private predicate alwaysReturnsTrue(HostnameVerifierVerify m) {
  forex(ReturnStmt rs | rs.getEnclosingCallable() = m |
    rs.getResult().(CompileTimeConstantExpr).getBooleanValue() = true
  )
}

/**
 * A class that overrides the `javax.net.ssl.HostnameVerifier.verify` method and **always** returns `true` (though it could also exit due to an uncaught exception), thus
 * accepting any certificate despite a hostname mismatch.
 */
class TrustAllHostnameVerifier extends RefType {
  TrustAllHostnameVerifier() {
    this.getASupertype*() instanceof HostnameVerifier and
    exists(HostnameVerifierVerify m |
      m.getDeclaringType() = this and
      alwaysReturnsTrue(m)
    )
  }
}

/**
 * A configuration to model the flow of a `TrustAllHostnameVerifier` to a `set(Default)HostnameVerifier` call.
 */
class TrustAllHostnameVerifierConfiguration extends DataFlow::Configuration {
  TrustAllHostnameVerifierConfiguration() { this = "TrustAllHostnameVerifierConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr().(ClassInstanceExpr).getConstructedType() instanceof TrustAllHostnameVerifier
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma, Method m |
      (m instanceof SetDefaultHostnameVerifierMethod or m instanceof SetHostnameVerifierMethod) and
      ma.getMethod() = m
    |
      ma.getArgument(0) = sink.asExpr()
    )
  }

  override predicate isBarrier(DataFlow::Node barrier) {

    barrier
        .getEnclosingCallable()
        .getName()
        /*
         * Regex: (_)* :
         * some methods have underscores.
         * Regex: (no|ignore|disable)(strictssl|ssl|verify|verification|hostname)
         * noStrictSSL ignoreSsl
         * Regex: (set)?(accept|trust|ignore|allow)(all|every|any)
         * acceptAll trustAll ignoreAll setTrustAnyHttps
         * Regex: (use|do|enable)insecure
         * useInsecureSSL
         * Regex: (set|do|use)?no.*(check|validation|verify|verification)
         * setNoCertificateCheck
         * Regex: disable
         * disableChecks
         */

        .regexpMatch("^(?i)(_)*((no|ignore|disable)(strictssl|ssl|verify|verification|hostname)" +
            "|(set)?(accept|trust|ignore|allow)(all|every|any)" +
            "|(use|do|enable)insecure|(set|do|use)?no.*(check|validation|verify|verification)|disable).*$")
  }
}

bindingset[result]
private string getAFlagName() {
  result
      .regexpMatch("(?i).*(secure|disable|selfCert|selfSign|validat|verif|trust|ignore|nocertificatecheck).*")
}

/**
 * A flag has to either be of type `String`, `boolean` or `Boolean`.
 */
private class FlagType extends Type {
  FlagType() {
    this instanceof TypeString
    or
    this instanceof BooleanType
  }
}

private predicate isEqualsIgnoreCaseMethodAccess(MethodAccess ma) {
  ma.getMethod().hasName("equalsIgnoreCase") and
  ma.getMethod().getDeclaringType() instanceof TypeString
}

/** Holds if `source` should is considered a flag. */
private predicate isFlag(DataFlow::Node source) {
  exists(VarAccess v | v.getVariable().getName() = getAFlagName() |
    source.asExpr() = v and v.getType() instanceof FlagType
  )
  or
  exists(StringLiteral s | s.getRepresentedString() = getAFlagName() | source.asExpr() = s)
  or
  exists(MethodAccess ma | ma.getMethod().getName() = getAFlagName() |
    source.asExpr() = ma and
    ma.getType() instanceof FlagType and
    not isEqualsIgnoreCaseMethodAccess(ma)
  )
}

/** Holds if there is flow from `node1` to `node2` either due to local flow or due to custom flow steps. */
private predicate flagFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
  DataFlow::localFlowStep(node1, node2)
  or
  exists(MethodAccess ma | ma.getMethod() = any(EnvReadMethod m) |
    ma = node2.asExpr() and ma.getAnArgument() = node1.asExpr()
  )
  or
  exists(MethodAccess ma |
    ma.getMethod().hasName("parseBoolean") and
    ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Boolean")
  |
    ma = node2.asExpr() and ma.getAnArgument() = node1.asExpr()
  )
}

/** Gets a guard that depends on a flag. */
private Guard getAGuard() {
  exists(DataFlow::Node source, DataFlow::Node sink |
    isFlag(source) and
    flagFlowStep*(source, sink) and
    sink.asExpr() = result
  )
}

/** Holds if `node` is guarded by a flag that suggests an intentionally insecure feature. */
private predicate isNodeGuardedByFlag(DataFlow::Node node) {
  exists(Guard g | g.controls(node.asExpr().getBasicBlock(), _) | g = getAGuard())
}

from DataFlow::Node n, string type
where exists(string qid | qid = "java/unsafe-hostname-verification" and (
  exists(
    TrustAllHostnameVerifierConfiguration c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
