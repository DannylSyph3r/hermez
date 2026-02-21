package dev.slethware.hermez.apikey.api;

import java.util.UUID;

public record ApiKeyValidationResponse(
        UUID userId,
        String email,
        String tier,
        boolean valid
) {}