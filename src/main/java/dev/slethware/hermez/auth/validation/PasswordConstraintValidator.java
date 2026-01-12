package dev.slethware.hermez.auth.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.passay.*;

import java.util.Arrays;
import java.util.Properties;

public class PasswordConstraintValidator implements ConstraintValidator<ValidPassword, String> {

    @Override
    public void initialize(ValidPassword constraintAnnotation) {
    }

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null) {
            return false;
        }

        Properties props = new Properties();
        props.setProperty("TOO_SHORT", "Must be at least %1$s characters long");
        props.setProperty("TOO_LONG", "Must be no more than %2$s characters long");
        props.setProperty("INSUFFICIENT_UPPERCASE", "Must contain at least %1$s uppercase letter");
        props.setProperty("INSUFFICIENT_LOWERCASE", "Must contain at least %1$s lowercase letter");
        props.setProperty("INSUFFICIENT_DIGIT", "Must contain at least %1$s number");
        props.setProperty("INSUFFICIENT_SPECIAL", "Must contain at least %1$s special character (!@#$%%^&*)");
        props.setProperty("ILLEGAL_WHITESPACE", "Must not contain spaces");

        MessageResolver resolver = new PropertiesMessageResolver(props);

        PasswordValidator validator = new PasswordValidator(resolver, Arrays.asList(
                new LengthRule(8, 30),
                new CharacterRule(EnglishCharacterData.UpperCase, 1),
                new CharacterRule(EnglishCharacterData.LowerCase, 1),
                new CharacterRule(EnglishCharacterData.Digit, 1),
                new CharacterRule(EnglishCharacterData.Special, 1),
                new WhitespaceRule()
        ));

        RuleResult result = validator.validate(new PasswordData(password));

        if (result.isValid()) {
            return true;
        }

        context.disableDefaultConstraintViolation();
        String messageTemplate = String.join(", ", validator.getMessages(result));
        context.buildConstraintViolationWithTemplate(messageTemplate)
                .addConstraintViolation();

        return false;
    }
}