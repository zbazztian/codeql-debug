/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id js/incomplete-html-attribute-sanitization-sources-and-sinks
 */


import javascript

import semmle.javascript.security.dataflow.IncompleteHtmlAttributeSanitization::IncompleteHtmlAttributeSanitization
import semmle.javascript.security.IncompleteBlacklistSanitizer

/**
 * Gets a pretty string of the dangerous characters for `sink`.
 */
string prettyPrintDangerousCharaters(Sink sink) {
  result =
    strictconcat(string s |
      s = describeCharacters(sink.getADangerousCharacter())
    |
      s, ", " order by s
    ).regexpReplaceAll(",(?=[^,]+$)", " or")
}

from DataFlow::Node n, string type
where 
exists(
  Configuration c, string qid |
  qid = "js/incomplete-html-attribute-sanitization: " and (
    c.isSource(n) and type = qid + c + "Source" or
    c.isSink(n) and type = qid + c + "Sink"
  )
)
select n, type
