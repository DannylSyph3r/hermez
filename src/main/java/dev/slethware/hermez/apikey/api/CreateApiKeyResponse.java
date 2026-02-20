package dev.slethware.hermez.apikey.api;

import java.time.LocalDateTime;
import java.util.UUID;

public record CreateApiKeyResponse(
        UUID id,
        String name,
        String key,
        String keyPreview,
        LocalDateTime createdAt,
        String message
) {}