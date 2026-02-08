package dev.slethware.hermez.user.api;

import dev.slethware.hermez.auth.validation.ValidPassword;
import jakarta.validation.constraints.NotBlank;

public record ChangePasswordRequest(

        @NotBlank(message = "Current password is required")
        String currentPassword,

        @NotBlank(message = "New password is required")
        @ValidPassword
        String newPassword,

        @NotBlank(message = "Password confirmation is required")
        String confirmPassword
) {}