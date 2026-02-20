package dev.slethware.hermez.apikey;

import dev.slethware.hermez.apikey.api.ApiKeyListResponse;
import dev.slethware.hermez.apikey.api.CreateApiKeyResponse;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface ApiKeyService {
    Mono<CreateApiKeyResponse> generateApiKey(UUID userId, String name);
    Mono<ApiKeyListResponse> listApiKeys(UUID userId);
    Mono<Void> revokeApiKey(UUID keyId, UUID userId);
    Mono<ApiKeyPrincipal> validateApiKey(String rawKey);
}