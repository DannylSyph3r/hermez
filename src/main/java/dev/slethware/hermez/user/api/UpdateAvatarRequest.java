package dev.slethware.hermez.user.api;

import jakarta.validation.constraints.NotBlank;

public record UpdateAvatarRequest(
        @NotBlank(message = "Avatar URL is required")
        String avatarUrl
) {}