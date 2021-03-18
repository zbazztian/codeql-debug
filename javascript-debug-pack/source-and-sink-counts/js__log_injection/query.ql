

import javascript

import semmle.javascript.security.dataflow.LogInjection::LogInjection

from string type, int amount
where 
exists(
  LogInjectionConfiguration c, string qid |
  qid = "js/log-injection: " and (
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + c + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n)) and type = qid + c + "Sink"
  )
)
select type, amount
