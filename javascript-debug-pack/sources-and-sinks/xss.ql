/**
 * @name Sources
 * @kind problem
 * @problem.severity warning
 * @id js/xss-sources-and-sinks
 */

import javascript
import semmle.javascript.security.dataflow.DomBasedXss::DomBasedXss as DBXSS
import semmle.javascript.security.dataflow.ExceptionXss::ExceptionXss as EXSS
import semmle.javascript.security.dataflow.ReflectedXss::ReflectedXss as RXSS
import semmle.javascript.security.dataflow.StoredXss::StoredXss as SXSS
import semmle.javascript.security.dataflow.UnsafeJQueryPlugin::UnsafeJQueryPlugin as UJQP
import semmle.javascript.security.dataflow.XssThroughDom::XssThroughDom as XSSTD
// import semmle.javascript.security.dataflow.SqlInjection::SqlInjection as SQLI
// import semmle.javascript.security.dataflow.NosqlInjection::NosqlInjection as NSQLI
// import semmle.javascript.security.dataflow.CommandInjection::CommandInjection as CMDI
// import semmle.javascript.security.dataflow.IndirectCommandInjection::IndirectCommandInjection as ICI
// import semmle.javascript.security.dataflow.ShellCommandInjectionFromEnvironment::ShellCommandInjectionFromEnvironment as SCIFE
// import semmle.javascript.security.dataflow.UnsafeShellCommandConstruction::UnsafeShellCommandConstruction as USCC
// import semmle.javascript.security.dataflow.TaintedPath::TaintedPath as TP
// import semmle.javascript.security.dataflow.ZipSlip::ZipSlip as ZS
// import semmle.javascript.security.dataflow.CodeInjection::CodeInjection as CI
// import semmle.javascript.security.dataflow.ImproperCodeSanitization::ImproperCodeSanitization as ICS
// import semmle.javascript.security.dataflow.UnsafeDynamicMethodAccess::UnsafeDynamicMethodAccess as UDMA
// import semmle.javascript.security.dataflow.IncompleteHtmlAttributeSanitization::IncompleteHtmlAttributeSanitization as IHAS
// import semmle.javascript.security.dataflow.LogInjection::LogInjection as LI
// import semmle.javascript.security.dataflow.TaintedFormatString::TaintedFormatString as TFS
// import semmle.javascript.security.dataflow.FileAccessToHttp::FileAccessToHttp as FATH
// import semmle.javascript.security.dataflow.PostMessageStar::PostMessageStar as PMS
// import semmle.javascript.security.dataflow.StackTraceExposure::StackTraceExposure as STE
// import semmle.javascript.security.dataflow.BuildArtifactLeak::BuildArtifactLeak as BAL
// import semmle.javascript.security.dataflow.CleartextLogging::CleartextLogging as CTL
// import semmle.javascript.security.dataflow.CleartextStorage::CleartextStorage as CTS
// import semmle.javascript.security.dataflow.BrokenCryptoAlgorithm::BrokenCryptoAlgorithm as BCA
// import semmle.javascript.security.dataflow.InsecureRandomness::InsecureRandomness as IR
// import semmle.javascript.security.dataflow.CorsMisconfigurationForCredentials::CorsMisconfigurationForCredentials as CMFC
// import semmle.javascript.security.dataflow.RemotePropertyInjection::RemotePropertyInjection as RPI
// import semmle.javascript.security.dataflow.UnsafeDeserialization::UnsafeDeserialization as UD
// import semmle.javascript.security.dataflow.HardcodedDataInterpretedAsCode::HardcodedDataInterpretedAsCode as HDIAC
// import semmle.javascript.security.dataflow.ClientSideUrlRedirect::ClientSideUrlRedirect as CSUR
// import semmle.javascript.security.dataflow.ServerSideUrlRedirect::ServerSideUrlRedirect as SSUR
// import semmle.javascript.security.dataflow.Xxe::Xxe as XXE

// import semmle.javascript.security.dataflow.HostHeaderPoisoningInEmailGeneration::HostHeaderPoisoningInEmailGeneration as HHPIEG
// import semmle.javascript.security.dataflow.XpathInjection::XpathInjection as XPI
// import semmle.javascript.security.dataflow.RegExpInjection::RegExpInjection as REI
// import semmle.javascript.security.dataflow.UnvalidatedDynamicMethodCall::UnvalidatedDynamicMethodCall as UDMC
// import semmle.javascript.security.dataflow.XmlBomb::XmlBomb as XMLB
// import semmle.javascript.security.dataflow.HardcodedCredentials::HardcodedCredentials as HC

// import semmle.javascript.security.dataflow.ConditionalBypass::ConditionalBypass as CB
// import semmle.javascript.security.dataflow.InsecureDownload::InsecureDownload as ID
// import semmle.javascript.security.dataflow.LoopBoundInjection::LoopBoundInjection as LBI
// import semmle.javascript.security.dataflow.TypeConfusionThroughParameterTampering::TypeConfusionThroughParameterTampering as TCTPT
// import semmle.javascript.security.dataflow.HttpToFileAccess::HttpToFileAccess as HTTPTFA
// import semmle.javascript.security.dataflow.PrototypePollutingAssignment::PrototypePollutingAssignment as PPA
// import semmle.javascript.security.dataflow.PrototypePollution::PrototypePollution as PP
// import semmle.javascript.security.dataflow.InsufficientPasswordHash::InsufficientPasswordHash as IPH
// import semmle.javascript.security.dataflow.RequestForgery::RequestForgery as RF


/*
 * from DataFlow::Node n, string type, string sourceOrSink, TaintTracking::Configuration cfg
 * where
 *  (
 *    (
 *      cfg instanceof DBXSS::HtmlInjectionConfiguration or
 *      cfg instanceof DBXSS::JQueryHtmlOrSelectorInjectionConfiguration or
 *      cfg instanceof EXSS::Configuration or
 *      cfg instanceof RXSS::Configuration or
 *      cfg instanceof SXSS::Configuration or
 *      cfg instanceof UJQP::Configuration or
 *      cfg instanceof XSSTD::Configuration
 *    ) and
 *    type = "XSS (CWE-079)"
 *    or
 *    (
 *      cfg instanceof SQLI::Configuration or
 *      cfg instanceof NSQLI::Configuration
 *    ) and
 *    type = "SQL Injection (CWE-089)"
 *    or
 *    (
 *      cfg instanceof CMDI::Configuration or
 *      cfg instanceof ICI::Configuration or
 *      cfg instanceof SCIFE::Configuration or
 *      cfg instanceof USCC::Configuration
 *    ) and
 *    type = "Command Injection (CWE-078)"
 *    or
 *    (cfg instanceof TP::Configuration or cfg instanceof ZS::Configuration) and
 *    type = "Tainted Path (CWE-022)"
 *    or
 *    (
 *      cfg instanceof CI::Configuration or
 *      cfg instanceof ICS::Configuration or
 *      cfg instanceof UDMA::Configuration
 *    ) and
 *    type = "Code Injection (CWE-094)"
 *    or
 *    cfg instanceof IHAS::Configuration and type = "Incomplete Sanitization (CWE-116)"
 *    or
 *    cfg instanceof LI::LogInjectionConfiguration and type = "Log Injection (CWE-117)"
 *    or
 *    cfg instanceof TFS::Configuration and type = "Tainted Format String (CWE-134)"
 *    or
 *    cfg instanceof FATH::Configuration and type = "File Access To HTTP (CWE-200)"
 *    or
 *    cfg instanceof PMS::Configuration and type = "Post Message Star (CWE-201)"
 *    or
 *    cfg instanceof STE::Configuration and type = "Stack Trace Exposure (CWE-209)"
 *  ) and
 *  (
 *    cfg.isSource(n) and sourceOrSink = "Source"
 *    or
 *    cfg.isSink(n) and sourceOrSink = "Sink"
 *  )
 * select n, sourceOrSink + " of type " + type
 */

from TaintTracking::Configuration c, DataFlow::Node n, string type
where c.isSource(n) and type = "Source" or c.isSink(n) and type = "Sink"
select n, type + " of " + c
