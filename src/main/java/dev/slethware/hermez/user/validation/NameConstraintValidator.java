package dev.slethware.hermez.user.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class NameConstraintValidator implements ConstraintValidator<ValidName, String> {

    @Override
    public void initialize(ValidName constraintAnnotation) {
    }

    @Override
    public boolean isValid(String name, ConstraintValidatorContext context) {
        if (name == null || name.isBlank()) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("Name is required")
                    .addConstraintViolation();
            return false;
        }

        String trimmedName = name.trim();

        // Check minimum length
        if (trimmedName.length() < 3) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("Name must be at least 3 characters long")
                    .addConstraintViolation();
            return false;
        }

        // Check for numbers
        if (trimmedName.matches(".*\\d.*")) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("Name must not contain numbers")
                    .addConstraintViolation();
            return false;
        }

        return true;
    }
}