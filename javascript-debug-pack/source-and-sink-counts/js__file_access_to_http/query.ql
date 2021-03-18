

import javascript
import semmle.javascript.security.dataflow.FileAccessToHttp::FileAccessToHttp

from string type, int amount
where 
exists(
  Configuration c, string qid |
  qid = "js/file-access-to-http: " and (
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + c + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n)) and type = qid + c + "Sink"
  )
)
select type, amount
