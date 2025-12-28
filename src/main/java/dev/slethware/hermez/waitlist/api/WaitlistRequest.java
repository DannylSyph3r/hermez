package dev.slethware.hermez.waitlist.api;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record WaitlistRequest(

        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid")
        String email
) {}