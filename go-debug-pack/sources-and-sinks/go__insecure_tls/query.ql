/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id go/insecure-tls-sources-and-sinks
 */


import go

import semmle.go.security.InsecureFeatureFlag::InsecureFeatureFlag

/**
 * Holds if it is insecure to assign TLS version `val` named `name` to `tls.Config` field `fieldName`.
 */
predicate isInsecureTlsVersion(int val, string name, string fieldName) {
  (fieldName = "MinVersion" or fieldName = "MaxVersion") and
  (

    val = 768 and name = "VersionSSL30"
    or

    val = 769 and name = "VersionTLS10"
    or

    val = 770 and name = "VersionTLS11"
    or


    val = 0 and name = "" and fieldName = "MinVersion"
  )
}

/**
 * Returns integers that may represent a secure TLS version.
 */
int getASecureTlsVersion() {
  result in [771, 772] // TLS 1.2 and 1.3 respectively
}

/**
 * Returns integers that may represent a TLS version.
 *
 * Integer values corresponding to versions are defined at https://golang.org/pkg/crypto/tls/#pkg-constants
 * Zero means the default version; at the time of writing, TLS 1.0.
 */
int getATlsVersion() { result = getASecureTlsVersion() or isInsecureTlsVersion(result, _, _) }

/**
 * Flow of TLS versions into a `tls.Config` struct, to the `MinVersion` and `MaxVersion` fields.
 */
class TlsVersionFlowConfig extends TaintTracking::Configuration {
  TlsVersionFlowConfig() { this = "TlsVersionFlowConfig" }

  /**
   * Holds if `source` is a TLS version source yielding value `val`.
   */
  predicate isSource(DataFlow::Node source, int val) {
    val = source.getIntValue() and
    val = getATlsVersion() and
    not DataFlow::isReturnedWithError(source)
  }

  /**
   * Holds if `fieldWrite` writes `sink` to `base`.`fld`, where `fld` is a TLS version field.
   */
  predicate isSink(DataFlow::Node sink, Field fld, DataFlow::Node base, Write fieldWrite) {
    fld.hasQualifiedName("crypto/tls", "Config", ["MinVersion", "MaxVersion"]) and
    fieldWrite.writesField(base, fld, sink)
  }

  override predicate isSource(DataFlow::Node source) { isSource(source, _) }

  override predicate isSink(DataFlow::Node sink) { isSink(sink, _, _, _) }
}

/**
 * Holds if `config` exhibits a secure TLS version flowing from `source` to `sink`, which flows into `fld`.
 */
predicate secureTlsVersionFlow(
  TlsVersionFlowConfig config, DataFlow::PathNode source, DataFlow::PathNode sink, Field fld
) {
  exists(int version |
    config.hasFlowPath(source, sink) and
    config.isSource(source.getNode(), version) and
    not isInsecureTlsVersion(version, _, fld.getName())
  )
}

/**
 * Holds if a secure TLS version reaches `sink`, which flows into `fld`.
 */
predicate secureTlsVersionFlowsToSink(DataFlow::PathNode sink, Field fld) {
  secureTlsVersionFlow(_, _, sink, fld)
}

/**
 * Holds if a secure TLS version may reach `accessPath`.`fld`
 */
predicate secureTlsVersionFlowsToField(SsaWithFields accessPath, Field fld) {
  exists(
    TlsVersionFlowConfig config, DataFlow::PathNode source, DataFlow::PathNode sink,
    DataFlow::Node base
  |
    secureTlsVersionFlow(config, source, sink, fld) and
    config.isSink(sink.getNode(), fld, base, _) and
    accessPath.getAUse() = base
  )
}

/**
 * Returns `node` or an implicit-deref node referring to it
 */
DataFlow::Node nodeOrDeref(DataFlow::Node node) {
  result = node or
  result.asInstruction() = IR::implicitDerefInstruction(node.asExpr())
}

/**
 * Holds if an insecure TLS version flows from `source` to `sink`, which is in turn written
 * to a field of `base`. `message` describes the specific problem found.
 */
predicate isInsecureTlsVersionFlow(
  DataFlow::PathNode source, DataFlow::PathNode sink, string message, DataFlow::Node base
) {
  exists(TlsVersionFlowConfig cfg, int version, Field fld |
    cfg.hasFlowPath(source, sink) and
    cfg.isSource(source.getNode(), version) and
    cfg.isSink(sink.getNode(), fld, base, _) and
    isInsecureTlsVersion(version, _, fld.getName()) and



    not secureTlsVersionFlowsToSink(sink, fld) and
    not exists(SsaWithFields insecureAccessPath, SsaWithFields secureAccessPath |
      nodeOrDeref(insecureAccessPath.getAUse()) = base and
      secureAccessPath = insecureAccessPath.similar()
    |
      secureTlsVersionFlowsToField(secureAccessPath, fld)
    )
  |
    version = 0 and
    message = "Using lowest TLS version for " + fld + "."
    or
    version != 0 and
    exists(string name | isInsecureTlsVersion(version, name, _) |
      message = "Using insecure TLS version " + name + " for " + fld + "."
    )
  )
}

/**
 * Flow of unsecure TLS cipher suites into a `tls.Config` struct,
 * to the `CipherSuites` field.
 */
class TlsInsecureCipherSuitesFlowConfig extends TaintTracking::Configuration {
  TlsInsecureCipherSuitesFlowConfig() { this = "TlsInsecureCipherSuitesFlowConfig" }

  /**
   * Holds if `source` reads an insecure TLS cipher suite named `suiteName`.
   */
  predicate isSourceValueEntity(DataFlow::Node source, string suiteName) {
    exists(DataFlow::ValueEntity val |
      val.hasQualifiedName("crypto/tls", suiteName) and
      suiteName =
        [
          "TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA256",
          "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
          "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
        ]
    |
      source = val.getARead()
    )
  }

  /**
   * Holds if `source` represents the result of `tls.InsecureCipherSuites()`.
   */
  predicate isSourceInsecureCipherSuites(DataFlow::Node source) {
    exists(Function insecureCipherSuites |
      insecureCipherSuites.hasQualifiedName("crypto/tls", "InsecureCipherSuites")
    |
      source = insecureCipherSuites.getACall().getResult()
    )
  }

  override predicate isSource(DataFlow::Node source) {
    isSourceInsecureCipherSuites(source)
    or
    isSourceValueEntity(source, _)
  }

  /**
   * Holds if `fieldWrite` writes `sink` to `base`.`fld`, and `fld` is `tls.Config.CipherSuites`.
   */
  predicate isSink(DataFlow::Node sink, Field fld, DataFlow::Node base, Write fieldWrite) {
    fld.hasQualifiedName("crypto/tls", "Config", "CipherSuites") and
    fieldWrite.writesField(base, fld, sink)
  }

  override predicate isSink(DataFlow::Node sink) { isSink(sink, _, _, _) }

  /**
   * Declare sinks as out-sanitizers in order to avoid producing superfluous paths where a cipher
   * is written to CipherSuites, then the list is further extended with either safe or tainted
   * suites.
   */
  override predicate isSanitizerOut(DataFlow::Node node) {
    super.isSanitizerOut(node) or isSink(node)
  }
}

/**
 * Holds if an insecure TLS cipher suite flows from `source` to `sink`, where `sink`
 * is written to the CipherSuites list of a `tls.Config` instance. `message` describes
 * the exact problem found.
 */
predicate isInsecureTlsCipherFlow(DataFlow::PathNode source, DataFlow::PathNode sink, string message) {
  exists(TlsInsecureCipherSuitesFlowConfig cfg | cfg.hasFlowPath(source, sink) |
    exists(string name | cfg.isSourceValueEntity(source.getNode(), name) |
      message = "Use of an insecure cipher suite: " + name + "."
    )
    or
    cfg.isSourceInsecureCipherSuites(source.getNode()) and
    message = "Use of an insecure cipher suite."
  )
}

/**
 * Flags suggesting support for an old or legacy TLS version.
 *
 * We accept 'intermediate' because it appears to be common for TLS users
 * to define three profiles: modern, intermediate, legacy/old, perhaps based
 * on https://wiki.mozilla.org/Security/Server_Side_TLS (though note the
 * 'intermediate' used there would now pass muster according to this query)
 */
class LegacyTlsVersionFlag extends FlagKind {
  LegacyTlsVersionFlag() { this = "legacyTlsVersion" }

  bindingset[result]
  override string getAFlagName() { result.regexpMatch("(?i).*(old|intermediate|legacy).*") }
}

/**
 * Gets a control-flow node that represents a (likely) flag controlling TLS version selection.
 */
ControlFlow::ConditionGuardNode getALegacyTlsVersionCheck() {
  result.ensures(any(LegacyTlsVersionFlag f).getAFlag().getANode(), _)
}

/**
 * Returns flag kinds relevant to this query: a generic security feature flag, or one
 * specifically controlling TLS version selection.
 */
FlagKind securityOrTlsVersionFlag() {
  result = any(SecurityFeatureFlag f) or
  result = any(LegacyTlsVersionFlag f)
}

from DataFlow::Node n, string type
where exists(string qid | qid = "go/insecure-tls" and (
  exists(
    TlsInsecureCipherSuitesFlowConfig c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
  or
  exists(
    TlsVersionFlowConfig c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
