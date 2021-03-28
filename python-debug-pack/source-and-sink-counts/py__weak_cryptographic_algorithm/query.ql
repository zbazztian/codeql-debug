

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

from string type, int amount
where exists(string qid | qid = "py/weak-cryptographic-algorithm" and (
  exists(
    BrokenCryptoConfiguration c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
