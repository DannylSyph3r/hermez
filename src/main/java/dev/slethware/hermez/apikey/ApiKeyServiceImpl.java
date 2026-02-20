package dev.slethware.hermez.apikey;

import dev.slethware.hermez.apikey.api.ApiKeyListResponse;
import dev.slethware.hermez.apikey.api.ApiKeyResponse;
import dev.slethware.hermez.apikey.api.CreateApiKeyResponse;
import dev.slethware.hermez.exception.ConflictException;
import dev.slethware.hermez.exception.ForbiddenException;
import dev.slethware.hermez.exception.ResourceNotFoundException;
import dev.slethware.hermez.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class ApiKeyServiceImpl implements ApiKeyService {

    private static final String API_KEY_PREFIX  = "hk_live_";
    private static final String REDIS_PREFIX    = "apikey:";
    private static final Duration CACHE_TTL     = Duration.ofMinutes(15);
    private static final int MAX_KEYS_PER_USER  = 10;

    private final ApiKeyRepository apiKeyRepository;
    private final UserRepository userRepository;
    private final ReactiveRedisTemplate<String, String> redisTemplate;

    @Override
    public Mono<CreateApiKeyResponse> generateApiKey(UUID userId, String name) {
        return apiKeyRepository.countByUserIdAndRevokedAtIsNull(userId)
                .flatMap(count -> {
                    if (count >= MAX_KEYS_PER_USER) {
                        return Mono.error(new ForbiddenException(
                                "API key limit reached. Maximum " + MAX_KEYS_PER_USER + " active keys allowed."));
                    }

                    String rawKey    = generateRawKey();
                    String keyHash   = hashKey(rawKey);
                    String keyPreview = buildPreview(rawKey);

                    ApiKey apiKey = ApiKey.builder()
                            .userId(userId)
                            .name(name)
                            .keyHash(keyHash)
                            .keyPreview(keyPreview)
                            .createdAt(LocalDateTime.now())
                            .build();

                    return apiKeyRepository.save(apiKey)
                            .map(saved -> new CreateApiKeyResponse(
                                    saved.getId(),
                                    saved.getName(),
                                    rawKey,
                                    saved.getKeyPreview(),
                                    saved.getCreatedAt(),
                                    "Store this key securely — it will not be shown again."
                            ));
                });
    }

    @Override
    public Mono<ApiKeyListResponse> listApiKeys(UUID userId) {
        return apiKeyRepository.findByUserIdAndRevokedAtIsNull(userId)
                .map(ApiKeyResponse::from)
                .collectList()
                .map(ApiKeyListResponse::new);
    }

    @Override
    public Mono<Void> revokeApiKey(UUID keyId, UUID userId) {
        return apiKeyRepository.findById(keyId)
                .switchIfEmpty(Mono.error(new ResourceNotFoundException("API key not found")))
                .flatMap(apiKey -> {
                    if (!userId.equals(apiKey.getUserId())) {
                        return Mono.error(new ForbiddenException("Access denied"));
                    }
                    if (apiKey.getRevokedAt() != null) {
                        return Mono.error(new ConflictException("API key is already revoked"));
                    }
                    apiKey.setRevokedAt(LocalDateTime.now());
                    return apiKeyRepository.save(apiKey)
                            .then(redisTemplate.delete(REDIS_PREFIX + apiKey.getKeyHash()))
                            .doOnSuccess(v -> log.info("API key revoked and cache invalidated: keyId={}", keyId))
                            .then();
                });
    }

    @Override
    public Mono<ApiKeyPrincipal> validateApiKey(String rawKey) {
        if (!rawKey.startsWith("hk_")) {
            return Mono.empty();
        }

        String hash     = hashKey(rawKey);
        String cacheKey = REDIS_PREFIX + hash;

        return redisTemplate.opsForValue().get(cacheKey)
                .flatMap(cached -> {
                    String[] parts = cached.split(":", 2);
                    return Mono.just(new ApiKeyPrincipal(UUID.fromString(parts[0]), parts[1]));
                })
                .onErrorResume(e -> {
                    log.warn("Redis unavailable for API key lookup, falling back to DB: {}", e.getMessage());
                    return Mono.empty();
                })
                .switchIfEmpty(lookupFromDb(hash, cacheKey));
    }

    private Mono<ApiKeyPrincipal> lookupFromDb(String hash, String cacheKey) {
        return apiKeyRepository.findByKeyHash(hash)
                .filter(apiKey -> apiKey.getRevokedAt() == null)
                .flatMap(apiKey -> userRepository.findById(apiKey.getUserId())
                        .map(user -> {
                            ApiKeyPrincipal principal = new ApiKeyPrincipal(user.getId(), user.getTier());
                            cacheAndUpdateAsync(cacheKey, apiKey, user.getId(), user.getTier());
                            return principal;
                        })
                );
    }

    private void cacheAndUpdateAsync(String cacheKey, ApiKey apiKey, UUID userId, String tier) {
        redisTemplate.opsForValue()
                .set(cacheKey, userId + ":" + tier, CACHE_TTL)
                .doOnError(e -> log.warn("Failed to cache API key principal for keyId={}: {}", apiKey.getId(), e.getMessage()))
                .onErrorComplete()
                .subscribe();

        apiKey.setLastUsedAt(LocalDateTime.now());
        apiKeyRepository.save(apiKey)
                .publishOn(Schedulers.boundedElastic())
                .doOnError(e -> log.warn("Failed to update last_used_at for keyId={}: {}", apiKey.getId(), e.getMessage()))
                .onErrorComplete()
                .subscribe();
    }

    private String generateRawKey() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return API_KEY_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String buildPreview(String rawKey) {
        return rawKey.substring(0, 6) + "..." + rawKey.substring(rawKey.length() - 6);
    }

    private String hashKey(String key) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(key.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
}