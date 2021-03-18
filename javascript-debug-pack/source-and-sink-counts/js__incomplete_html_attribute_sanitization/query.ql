

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

from string type, int amount
where exists(string qid | qid = "js/incomplete-html-attribute-sanitization" and (
  exists(
    Configuration c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
