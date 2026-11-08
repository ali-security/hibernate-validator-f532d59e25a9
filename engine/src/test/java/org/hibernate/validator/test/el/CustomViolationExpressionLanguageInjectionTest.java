/*
 * Hibernate Validator, declare and validate application constraints
 *
 * License: Apache License, Version 2.0
 * See the license.txt file in the root directory or <http://www.apache.org/licenses/LICENSE-2.0>.
 */
package org.hibernate.validator.test.el;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;
import static org.hibernate.validator.testutil.ConstraintViolationAssert.assertThat;
import static org.hibernate.validator.testutil.ConstraintViolationAssert.violationOf;
import static org.testng.Assert.assertEquals;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import javax.validation.Constraint;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import javax.validation.Payload;
import javax.validation.Validator;
import javax.validation.constraintvalidation.SupportedValidationTarget;
import javax.validation.constraintvalidation.ValidationTarget;

import org.hibernate.validator.HibernateValidatorConfiguration;
import org.hibernate.validator.constraintvalidation.HibernateConstraintValidatorContext;
import org.hibernate.validator.messageinterpolation.ExpressionLanguageFeatureLevel;
import org.hibernate.validator.testutil.TestForIssue;
import org.hibernate.validator.testutils.ValidatorUtil;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Exploit-style tests for Expression Language injection through custom violation message templates built from
 * user input (CVE-2025-35036): by default, such templates must never be evaluated by the Expression Language engine.
 */
@TestForIssue(jiraKey = "HV-1816")
public class CustomViolationExpressionLanguageInjectionTest {

	/**
	 * Malicious user input executing a method with a side effect on the validated bean.
	 */
	private static final String BEAN_METHOD_PAYLOAD = "${validatedValue.trigger()}";

	/**
	 * Malicious user input executing a method with a side effect on one of the validated parameters.
	 */
	private static final String PARAMETER_METHOD_PAYLOAD = "${validatedValue[1].trigger()}";

	private Validator validator;

	@BeforeMethod
	public void setUp() {
		validator = ValidatorUtil.getValidator();
		Account.TRIGGER_COUNT.set( 0 );
	}

	@Test
	public void plain_context_concatenation_is_not_evaluated() {
		assertNotEvaluated( new PlainAccount() );
	}

	@Test
	public void property_node_concatenation_is_not_evaluated() {
		assertNotEvaluated( new PropertyNodeAccount() );
	}

	@Test
	public void iterable_index_concatenation_is_not_evaluated() {
		assertNotEvaluated( new IterableIndexAccount() );
	}

	@Test
	public void iterable_key_concatenation_is_not_evaluated() {
		assertNotEvaluated( new IterableKeyAccount() );
	}

	@Test
	public void bean_node_concatenation_is_not_evaluated() {
		assertNotEvaluated( new BeanNodeAccount() );
	}

	@Test
	public void container_element_node_concatenation_is_not_evaluated() {
		assertNotEvaluated( new ContainerElementAccount() );
	}

	@Test
	public void unwrapped_hibernate_context_concatenation_is_not_evaluated() {
		assertNotEvaluated( new UnwrappedHibernateContextAccount() );
	}

	@Test
	public void concatenation_with_expression_variables_is_not_evaluated() {
		assertNotEvaluated( new ExpressionVariableAccount() );
	}

	@Test
	public void cross_parameter_concatenation_is_not_evaluated() throws Exception {
		assertThat( validator.forExecutables().validateParameters(
				new AccountService(),
				AccountService.class.getMethod( "transfer", String.class, Account.class ),
				new Object[] { PARAMETER_METHOD_PAYLOAD, new Account() }
		) ).containsOnlyViolations(
				violationOf( RecklessCrossParameterConcatenation.class ).withMessage( "Invalid input: " + PARAMETER_METHOD_PAYLOAD )
		);
		assertEquals( Account.TRIGGER_COUNT.get(), 0, "Method injected via the custom violation template has been executed" );
	}

	@Test
	public void enabled_expression_language_does_not_execute_injected_methods_by_default() {
		assertNotEvaluated( new EnabledExpressionLanguageAccount() );
	}

	@Test
	public void enabled_expression_language_with_bean_properties_does_not_execute_injected_methods() {
		assertNotEvaluated( new EnabledBeanPropertiesAccount() );
	}

	@Test
	public void custom_violation_feature_level_variables_does_not_execute_injected_methods() {
		Validator variablesValidator = ValidatorUtil.getConfiguration()
				.customViolationExpressionLanguageFeatureLevel( ExpressionLanguageFeatureLevel.VARIABLES )
				.buildValidatorFactory()
				.getValidator();

		assertNotEvaluated( variablesValidator, new PlainAccount() );
	}

	@Test
	public void custom_violation_feature_level_property_does_not_execute_injected_methods() {
		Validator variablesValidator = ValidatorUtil.getConfiguration()
				.addProperty( HibernateValidatorConfiguration.CUSTOM_VIOLATION_EXPRESSION_LANGUAGE_FEATURE_LEVEL, "variables" )
				.buildValidatorFactory()
				.getValidator();

		assertNotEvaluated( variablesValidator, new PlainAccount() );
	}

	@Test
	public void constraint_message_does_not_execute_methods_by_default() {
		assertThat( validator.validate( new ConstraintMessageAccount() ) ).containsOnlyViolations(
				violationOf( MethodInConstraintMessage.class ).withMessage( "Invalid input: " + BEAN_METHOD_PAYLOAD )
		);
		assertEquals( Account.TRIGGER_COUNT.get(), 0, "Method referenced in the constraint message has been executed" );
	}

	private void assertNotEvaluated(Account account) {
		assertNotEvaluated( validator, account );
	}

	private void assertNotEvaluated(Validator validator, Account account) {
		account.userInput = BEAN_METHOD_PAYLOAD;

		assertThat( validator.validate( account ) ).containsOnlyViolations(
				violationOf( RecklessConcatenation.class ).withMessage( "Invalid input: " + BEAN_METHOD_PAYLOAD )
		);
		assertEquals( Account.TRIGGER_COUNT.get(), 0, "Method injected via the custom violation template has been executed" );
	}

	public enum Vector {
		PLAIN,
		PROPERTY_NODE,
		ITERABLE_INDEX,
		ITERABLE_KEY,
		BEAN_NODE,
		CONTAINER_ELEMENT,
		UNWRAPPED_HIBERNATE_CONTEXT,
		EXPRESSION_VARIABLE,
		ENABLED_EXPRESSION_LANGUAGE,
		ENABLED_BEAN_PROPERTIES
	}

	@Target({ TYPE })
	@Retention(RUNTIME)
	@Documented
	@Constraint(validatedBy = { RecklessConcatenationValidator.class })
	public @interface RecklessConcatenation {

		String message() default "-";

		Class<?>[] groups() default { };

		Class<? extends Payload>[] payload() default { };

		Vector value();
	}

	public static class RecklessConcatenationValidator implements ConstraintValidator<RecklessConcatenation, Account> {

		private Vector vector;

		@Override
		public void initialize(RecklessConcatenation constraintAnnotation) {
			this.vector = constraintAnnotation.value();
		}

		@Override
		public boolean isValid(Account account, ConstraintValidatorContext context) {
			context.disableDefaultConstraintViolation();

			// THIS IS UNSAFE: the user input is concatenated to the message template
			String template = "Invalid input: " + account.userInput;

			switch ( vector ) {
				case PLAIN:
					context.buildConstraintViolationWithTemplate( template )
							.addConstraintViolation();
					break;
				case PROPERTY_NODE:
					context.buildConstraintViolationWithTemplate( template )
							.addPropertyNode( "userInput" )
							.addConstraintViolation();
					break;
				case ITERABLE_INDEX:
					context.buildConstraintViolationWithTemplate( template )
							.addPropertyNode( "userInput" )
							.inIterable().atIndex( 0 )
							.addConstraintViolation();
					break;
				case ITERABLE_KEY:
					context.buildConstraintViolationWithTemplate( template )
							.addPropertyNode( "userInput" )
							.inIterable().atKey( "key" )
							.addConstraintViolation();
					break;
				case BEAN_NODE:
					context.buildConstraintViolationWithTemplate( template )
							.addPropertyNode( "userInput" )
							.addBeanNode()
							.addConstraintViolation();
					break;
				case CONTAINER_ELEMENT:
					context.buildConstraintViolationWithTemplate( template )
							.addPropertyNode( "userInput" )
							.addContainerElementNode( "<list element>", List.class, 0 )
							.inIterable().atIndex( 0 )
							.addConstraintViolation();
					break;
				case UNWRAPPED_HIBERNATE_CONTEXT:
					context.unwrap( HibernateConstraintValidatorContext.class )
							.buildConstraintViolationWithTemplate( template )
							.addConstraintViolation();
					break;
				case EXPRESSION_VARIABLE:
					context.unwrap( HibernateConstraintValidatorContext.class )
							.addExpressionVariable( "userInput", account.userInput )
							.buildConstraintViolationWithTemplate( template )
							.addConstraintViolation();
					break;
				case ENABLED_EXPRESSION_LANGUAGE:
					context.unwrap( HibernateConstraintValidatorContext.class )
							.buildConstraintViolationWithTemplate( template )
							.enableExpressionLanguage()
							.addConstraintViolation();
					break;
				case ENABLED_BEAN_PROPERTIES:
					context.unwrap( HibernateConstraintValidatorContext.class )
							.buildConstraintViolationWithTemplate( template )
							.enableExpressionLanguage( ExpressionLanguageFeatureLevel.BEAN_PROPERTIES )
							.addConstraintViolation();
					break;
				default:
					throw new IllegalStateException( "Unknown vector " + vector );
			}

			return false;
		}
	}

	@Target({ TYPE })
	@Retention(RUNTIME)
	@Documented
	@Constraint(validatedBy = { MethodInConstraintMessageValidator.class })
	public @interface MethodInConstraintMessage {

		String message() default "Invalid input: " + BEAN_METHOD_PAYLOAD;

		Class<?>[] groups() default { };

		Class<? extends Payload>[] payload() default { };
	}

	public static class MethodInConstraintMessageValidator implements ConstraintValidator<MethodInConstraintMessage, Account> {

		@Override
		public boolean isValid(Account account, ConstraintValidatorContext context) {
			return false;
		}
	}

	@Target({ METHOD })
	@Retention(RUNTIME)
	@Documented
	@Constraint(validatedBy = { RecklessCrossParameterConcatenationValidator.class })
	public @interface RecklessCrossParameterConcatenation {

		String message() default "-";

		Class<?>[] groups() default { };

		Class<? extends Payload>[] payload() default { };
	}

	@SupportedValidationTarget(ValidationTarget.PARAMETERS)
	public static class RecklessCrossParameterConcatenationValidator implements ConstraintValidator<RecklessCrossParameterConcatenation, Object[]> {

		@Override
		public boolean isValid(Object[] parameters, ConstraintValidatorContext context) {
			context.disableDefaultConstraintViolation();

			// THIS IS UNSAFE: the user input is concatenated to the message template
			context.buildConstraintViolationWithTemplate( "Invalid input: " + parameters[0] )
					.addParameterNode( 0 )
					.addConstraintViolation();

			return false;
		}
	}

	public static class Account {

		static final AtomicInteger TRIGGER_COUNT = new AtomicInteger();

		public String userInput;

		public String trigger() {
			TRIGGER_COUNT.incrementAndGet();
			return "pwned";
		}
	}

	@RecklessConcatenation(Vector.PLAIN)
	public static class PlainAccount extends Account {
	}

	@RecklessConcatenation(Vector.PROPERTY_NODE)
	public static class PropertyNodeAccount extends Account {
	}

	@RecklessConcatenation(Vector.ITERABLE_INDEX)
	public static class IterableIndexAccount extends Account {
	}

	@RecklessConcatenation(Vector.ITERABLE_KEY)
	public static class IterableKeyAccount extends Account {
	}

	@RecklessConcatenation(Vector.BEAN_NODE)
	public static class BeanNodeAccount extends Account {
	}

	@RecklessConcatenation(Vector.CONTAINER_ELEMENT)
	public static class ContainerElementAccount extends Account {
	}

	@RecklessConcatenation(Vector.UNWRAPPED_HIBERNATE_CONTEXT)
	public static class UnwrappedHibernateContextAccount extends Account {
	}

	@RecklessConcatenation(Vector.EXPRESSION_VARIABLE)
	public static class ExpressionVariableAccount extends Account {
	}

	@RecklessConcatenation(Vector.ENABLED_EXPRESSION_LANGUAGE)
	public static class EnabledExpressionLanguageAccount extends Account {
	}

	@RecklessConcatenation(Vector.ENABLED_BEAN_PROPERTIES)
	public static class EnabledBeanPropertiesAccount extends Account {
	}

	@MethodInConstraintMessage
	public static class ConstraintMessageAccount extends Account {
	}

	public static class AccountService {

		@RecklessCrossParameterConcatenation
		public void transfer(String userInput, Account account) {
		}
	}
}
