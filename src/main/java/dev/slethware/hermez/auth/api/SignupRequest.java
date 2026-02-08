package dev.slethware.hermez.auth.api;

import dev.slethware.hermez.auth.validation.ValidPassword;
import dev.slethware.hermez.user.validation.ValidName;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record SignupRequest(

        @ValidName
        String name,

        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid")
        String email,

        @NotBlank(message = "Password is required")
        @ValidPassword
        String password
) {}