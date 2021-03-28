

import python
import semmle.python.security.Paths
import semmle.python.dataflow.TaintTracking
import semmle.python.security.strings.Basic

/** A TaintKind to represent open tarfile objects. That is, the result of calling `tarfile.open(...)` */
class OpenTarFile extends TaintKind {
  OpenTarFile() { this = "tarfile.open" }

  override TaintKind getTaintOfMethodResult(string name) {
    name = "getmember" and result instanceof TarFileInfo
    or
    name = "getmembers" and result.(SequenceKind).getItem() instanceof TarFileInfo
  }

  override ClassValue getType() { result = Value::named("tarfile.TarFile") }

  override TaintKind getTaintForIteration() { result instanceof TarFileInfo }
}

/** The source of open tarfile objects. That is, any call to `tarfile.open(...)` */
class TarfileOpen extends TaintSource {
  TarfileOpen() {
    Value::named("tarfile.open").getACall() = this and
    /*
     * If argument refers to a string object, then it's a hardcoded path and
     * this tarfile is safe.
     */

    not this.(CallNode).getAnArg().pointsTo(any(StringValue str)) and
    /* Ignore opens within the tarfile module itself */
    not this.(ControlFlowNode).getLocation().getFile().getBaseName() = "tarfile.py"
  }

  override predicate isSourceOf(TaintKind kind) { kind instanceof OpenTarFile }
}

class TarFileInfo extends TaintKind {
  TarFileInfo() { this = "tarfile.entry" }

  override TaintKind getTaintOfMethodResult(string name) { name = "next" and result = this }

  override TaintKind getTaintOfAttribute(string name) {
    name = "name" and result instanceof TarFileInfo
  }
}

/*
 * For efficiency we don't want to track the flow of taint
 * around the tarfile module.
 */

class ExcludeTarFilePy extends Sanitizer {
  ExcludeTarFilePy() { this = "Tar sanitizer" }

  override predicate sanitizingNode(TaintKind taint, ControlFlowNode node) {
    node.getLocation().getFile().getBaseName() = "tarfile.py" and
    (
      taint instanceof OpenTarFile
      or
      taint instanceof TarFileInfo
      or
      taint.(SequenceKind).getItem() instanceof TarFileInfo
    )
  }
}

/* Any call to an extractall method */
class ExtractAllSink extends TaintSink {
  CallNode call;

  ExtractAllSink() {
    this = call.getFunction().(AttrNode).getObject("extractall") and
    count(call.getAnArg()) = 0
  }

  override predicate sinks(TaintKind kind) { kind instanceof OpenTarFile }
}

/* Argument to extract method */
class ExtractSink extends TaintSink {
  CallNode call;

  ExtractSink() {
    call.getFunction().(AttrNode).getName() = "extract" and
    this = call.getArg(0)
  }

  override predicate sinks(TaintKind kind) { kind instanceof TarFileInfo }
}

/* Members argument to extract method */
class ExtractMembersSink extends TaintSink {
  CallNode call;

  ExtractMembersSink() {
    call.getFunction().(AttrNode).getName() = "extractall" and
    (this = call.getArg(0) or this = call.getArgByName("members"))
  }

  override predicate sinks(TaintKind kind) {
    kind.(SequenceKind).getItem() instanceof TarFileInfo
    or
    kind instanceof OpenTarFile
  }
}

class TarFileInfoSanitizer extends Sanitizer {
  TarFileInfoSanitizer() { this = "TarInfo sanitizer" }

  /** The test `if <path_sanitizing_test>:` clears taint on its `false` edge. */
  override predicate sanitizingEdge(TaintKind taint, PyEdgeRefinement test) {
    taint instanceof TarFileInfo and
    clears_taint_on_false_edge(test.getTest(), test.getSense())
  }

  private predicate clears_taint_on_false_edge(ControlFlowNode test, boolean sense) {
    path_sanitizing_test(test) and
    sense = false
    or

    test.(UnaryExprNode).getNode().getOp() instanceof Not and
    clears_taint_on_false_edge(test.(UnaryExprNode).getOperand(), sense.booleanNot())
  }
}

private predicate path_sanitizing_test(ControlFlowNode test) {
  /* Assume that any test with "path" in it is a sanitizer */
  test.getAChild+().(AttrNode).getName().matches("%path")
  or
  test.getAChild+().(NameNode).getId().matches("%path")
}

class TarSlipConfiguration extends TaintTracking::Configuration {
  TarSlipConfiguration() { this = "TarSlip configuration" }

  override predicate isSource(TaintTracking::Source source) { source instanceof TarfileOpen }

  override predicate isSink(TaintTracking::Sink sink) {
    sink instanceof ExtractSink or
    sink instanceof ExtractAllSink or
    sink instanceof ExtractMembersSink
  }

  override predicate isSanitizer(Sanitizer sanitizer) {
    sanitizer instanceof TarFileInfoSanitizer
    or
    sanitizer instanceof ExcludeTarFilePy
  }

  override predicate isBarrier(DataFlow::Node node) {

    exists(ParameterDefinition def |
      node.asVariable().getDefinition() = def
      or
      node.asCfgNode() = def.getDefiningNode()
    |
      def.getScope() = Value::named("tarfile.open").(CallableValue).getScope()
      or
      def.isSelf() and def.getScope().getEnclosingModule().getName() = "tarfile"
    )
  }
}

from string type, int amount
where exists(string qid | qid = "py/tarslip" and (
  exists(
    TarSlipConfiguration c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
