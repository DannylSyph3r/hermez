package dev.slethware.hermez.user.api;

import dev.slethware.hermez.user.validation.ValidName;

public record UpdateNameRequest(
        @ValidName
        String name
) {}