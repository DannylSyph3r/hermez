package dev.slethware.hermez.apikey.api;

import dev.slethware.hermez.apikey.ApiKeyService;
import dev.slethware.hermez.common.models.response.ApiResponse;
import dev.slethware.hermez.common.util.ApiResponseUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/api-keys")
@RequiredArgsConstructor
@Tag(name = "API Keys", description = "API key management for CLI authentication")
public class ApiKeyController {

    private final ApiKeyService apiKeyService;

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Generate API key", description = "Creates a new API key. The full key is returned only once.")
    public Mono<ApiResponse<CreateApiKeyResponse>> generateApiKey(
            @Valid @RequestBody CreateApiKeyRequest request,
            Authentication authentication
    ) {
        UUID userId = UUID.fromString(authentication.getName());
        return apiKeyService.generateApiKey(userId, request.name())
                .map(response -> ApiResponseUtil.created("API key created successfully", response));
    }

    @GetMapping
    @Operation(summary = "List API keys", description = "Returns all active API keys for the authenticated user. Key values are never returned.")
    public Mono<ApiResponse<ApiKeyListResponse>> listApiKeys(Authentication authentication) {
        UUID userId = UUID.fromString(authentication.getName());
        return apiKeyService.listApiKeys(userId)
                .map(response -> ApiResponseUtil.successFull("API keys retrieved successfully", response));
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Revoke API key", description = "Permanently revokes an API key. Immediately invalidates any active sessions using this key.")
    public Mono<ApiResponse<Void>> revokeApiKey(
            @PathVariable UUID id,
            Authentication authentication
    ) {
        UUID userId = UUID.fromString(authentication.getName());
        return apiKeyService.revokeApiKey(id, userId)
                .then(Mono.just(ApiResponseUtil.successFullVoid("API key revoked successfully")));
    }

    @GetMapping("/validate")
    @Operation(summary = "Validate API key", description = "Confirms the API key is valid and returns the associated user info. Used by the CLI on startup.")
    public Mono<ApiResponse<ApiKeyValidationResponse>> validateApiKey(Authentication authentication) {
        UUID userId = UUID.fromString(authentication.getName());
        String tier = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(a -> a.startsWith("TIER_"))
                .map(a -> a.substring(5).toLowerCase())
                .findFirst()
                .orElse("chelys");

        return Mono.just(ApiResponseUtil.successFull(
                "API key is valid",
                new ApiKeyValidationResponse(userId, tier, true)
        ));
    }
}