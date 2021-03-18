/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id java/ldap-injection-sources-and-sinks
 */


import java
import semmle.code.java.dataflow.FlowSources
import LdapInjectionLib

from DataFlow::Node n, string type
where exists(string qid | qid = "java/ldap-injection" and (
  exists(
    LdapInjectionFlowConfig c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
