

import python
import ExternalAPIs

from string type, int amount
where exists(string qid | qid = "python/untrusted-data-to-external-api" and (
  exists(
    UntrustedDataToExternalAPIConfig c |
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + " | " + c + " | " + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n))   and type = qid + " | " + c + " | " + "Sink"
  )
))
select type, amount
