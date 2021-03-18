/**
 * @name Sources and Sinks
 * @description Prints sources and sinks of various DataFlow and TaintTracking Configurations
 * @kind problem
 * @problem.severity recommendation
 * @id java/insecure-bean-validation-sources-and-sinks
 */


import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources


/**
 * A message interpolator Type that perform Expression Language (EL) evaluations
 */
class ELMessageInterpolatorType extends RefType {
  ELMessageInterpolatorType() {
    this.getASourceSupertype*()
        .hasQualifiedName("org.hibernate.validator.messageinterpolation",
          ["ResourceBundleMessageInterpolator", "ValueFormatterMessageInterpolator"])
  }
}

/**
 * A method call that sets the application's default message interpolator.
 */
class SetMessageInterpolatorCall extends MethodAccess {
  SetMessageInterpolatorCall() {
    exists(Method m, RefType t |
      this.getMethod() = m and
      m.getDeclaringType().getASourceSupertype*() = t and
      (
        t.hasQualifiedName("javax.validation", ["Configuration", "ValidatorContext"]) and
        m.getName() = "messageInterpolator"
        or
        t.hasQualifiedName("org.springframework.validation.beanvalidation",
          ["CustomValidatorBean", "LocalValidatorFactoryBean"]) and
        m.getName() = "setMessageInterpolator"
      )
    )
  }

  /**
   * The message interpolator is likely to be safe, because it does not process Java Expression Language expressions.
   */
  predicate isSafe() { not this.getAnArgument().getType() instanceof ELMessageInterpolatorType }
}

/**
 * A method named `buildConstraintViolationWithTemplate` declared on a subtype
 * of `javax.validation.ConstraintValidatorContext`.
 */
class BuildConstraintViolationWithTemplateMethod extends Method {
  BuildConstraintViolationWithTemplateMethod() {
    this.getDeclaringType()
        .getASupertype*()
        .hasQualifiedName("javax.validation", "ConstraintValidatorContext") and
    this.hasName("buildConstraintViolationWithTemplate")
  }
}

/**
 * Taint tracking BeanValidationConfiguration describing the flow of data from user input
 * to the argument of a method that builds constraint error messages.
 */
class BeanValidationConfig extends TaintTracking::Configuration {
  BeanValidationConfig() { this = "BeanValidationConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod() instanceof BuildConstraintViolationWithTemplateMethod and
      sink.asExpr() = ma.getArgument(0)
    )
  }
}

from DataFlow::Node n, string type
where exists(string qid | qid = "java/insecure-bean-validation" and (
  exists(
    BeanValidationConfig c |
    c.isSource(n) and type = qid + " | " + c + " | " + "Source" or
    c.isSink(n)   and type = qid + " | " + c + " | " + "Sink"
  )
))
select n, type
