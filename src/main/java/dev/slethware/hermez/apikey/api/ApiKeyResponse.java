package dev.slethware.hermez.apikey.api;

import dev.slethware.hermez.apikey.ApiKey;

import java.time.Instant;
import java.util.UUID;

public record ApiKeyResponse(
        UUID id,
        String name,
        String keyPreview,
        Instant createdAt,
        Instant lastUsedAt
) {
    public static ApiKeyResponse from(ApiKey apiKey) {
        return new ApiKeyResponse(
                apiKey.getId(),
                apiKey.getName(),
                apiKey.getKeyPreview(),
                apiKey.getCreatedAt(),
                apiKey.getLastUsedAt()
        );
    }
}