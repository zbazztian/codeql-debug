

import go
import semmle.go.security.ExternalAPIs

from string type, int amount
where exists(string qid | qid = "go/untrusted-data-to-unknown-external-api" and (
  exists(
    UntrustedDataToUnknownExternalAPIConfig c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
