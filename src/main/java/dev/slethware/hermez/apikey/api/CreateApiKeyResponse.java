package dev.slethware.hermez.apikey.api;

import java.time.Instant;
import java.util.UUID;

public record CreateApiKeyResponse(
        UUID id,
        String name,
        String key,
        String keyPreview,
        Instant createdAt,
        String message
) {}