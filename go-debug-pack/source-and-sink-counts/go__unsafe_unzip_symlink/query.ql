

import go

import semmle.go.security.UnsafeUnzipSymlink::UnsafeUnzipSymlink

from string type, int amount
where 
exists(
  SymlinkConfiguration c, string qid |
  qid = "go/unsafe-unzip-symlink: " and (
    amount = count(DataFlow::Node n | c.isSource(n)) and type = qid + c + "Source" or
    amount = count(DataFlow::Node n | c.isSink(n)) and type = qid + c + "Sink"
  )
)
select type, amount
