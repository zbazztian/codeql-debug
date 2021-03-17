/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id go/suspicious-character-in-regex-sources-and-sinks
 */


import go
import DataFlow::PathGraph

/**
 * Holds if `source` corresponds to a string literal that contains an escaped `character`.
 *
 * `character` must be `"a"` or `"b"`, the only interesting escapes for this query.
 */
predicate containsEscapedCharacter(DataFlow::Node source, string character) {
  character in ["a", "b"] and
  exists(StringLit s | s = source.asExpr() |
    exists(s.getText().regexpFind("(?<=(^|[^\\\\])\\\\(\\\\{2}){0,10})" + character, _, _)) and
    not s.isRaw()
  )
}

/** A dataflow configuration that traces strings containing suspicious escape sequences to a use as a regular expression. */
class Config extends DataFlow::Configuration {
  Config() { this = "SuspiciousRegexpEscape" }

  predicate isSource(DataFlow::Node source, string report) {
    containsEscapedCharacter(source, "a") and
    report =
      "the bell character \\a; did you mean \\\\a, the Vim alphabetic character class (use [[:alpha:]] instead) or \\\\A, the beginning of text?"
    or
    containsEscapedCharacter(source, "b") and
    report = "a literal backspace \\b; did you mean \\\\b, a word boundary?"
  }

  override predicate isSource(DataFlow::Node source) { isSource(source, _) }

  override predicate isSink(DataFlow::Node sink) { sink instanceof RegexpPattern }
}

from DataFlow::Node n, string type
where 
exists(
  Config c |
  c.isSource(n) and type = c + "Source" or
  c.isSink(n) and type = c + "Sink"
)
select n, type
