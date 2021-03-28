/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id py/weak-cryptographic-algorithm-sources-and-sinks
 */


import python
import semmle.python.security.Paths
import semmle.python.security.SensitiveData
import semmle.python.security.Crypto

class BrokenCryptoConfiguration extends TaintTracking::Configuration {
  BrokenCryptoConfiguration() { this = "Broken crypto configuration" }

  override predicate isSource(TaintTracking::Source source) {
    source instanceof SensitiveDataSource
  }

  override predicate isSink(TaintTracking::Sink sink) { sink instanceof WeakCryptoSink }
}

from DataFlow::Node n, string type
where exists(string qid | qid = "py/weak-cryptographic-algorithm" and (
  exists(
    BrokenCryptoConfiguration c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
