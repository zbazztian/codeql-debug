

import python
import semmle.python.security.Paths
import semmle.python.dataflow.TaintTracking
import semmle.python.security.SensitiveData
import semmle.python.security.ClearText

class CleartextStorageConfiguration extends TaintTracking::Configuration {
  CleartextStorageConfiguration() { this = "ClearTextStorage" }

  override predicate isSource(DataFlow::Node src, TaintKind kind) {
    src.asCfgNode().(SensitiveData::Source).isSourceOf(kind)
  }

  override predicate isSink(DataFlow::Node sink, TaintKind kind) {
    sink.asCfgNode() instanceof ClearTextStorage::Sink and
    kind instanceof SensitiveData
  }
}

from string type, int amount
where exists(string qid | qid = "py/clear-text-storage-sensitive-data" and (
  exists(
    CleartextStorageConfiguration c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
