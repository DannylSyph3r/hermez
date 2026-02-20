package dev.slethware.hermez.auth;

import dev.slethware.hermez.apikey.ApiKeyPrincipal;
import dev.slethware.hermez.apikey.ApiKeyService;
import dev.slethware.hermez.auth.config.AuthProperties;
import dev.slethware.hermez.user.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    private final SecretKey jwtSecretKey;
    private final AuthProperties authProperties;
    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final ApiKeyService apiKeyService;

    private static final String REFRESH_TOKEN_PREFIX = "refresh_token:user:";
    private static final String TOKEN_TYPE_ACCESS = "access";

    @Override
    public String generateAccessToken(User user) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + authProperties.getJwt().getAccessTokenExpiration());

        return Jwts.builder()
                .subject(user.getId().toString())
                .claim("tier", user.getTier())
                .claim("type", TOKEN_TYPE_ACCESS)
                .issuedAt(now)
                .expiration(expiry)
                .signWith(jwtSecretKey)
                .compact();
    }

    @Override
    public Mono<String> generateRefreshToken(User user) {
        String rawToken = generateSecureToken();
        String hashedToken = hashToken(rawToken);

        String redisKey = REFRESH_TOKEN_PREFIX + user.getId().toString();
        Duration ttl = Duration.ofMillis(authProperties.getJwt().getRefreshTokenExpiration());

        return redisTemplate.opsForValue()
                .set(redisKey, hashedToken, ttl)
                .thenReturn(rawToken);
    }

    @Override
    public Mono<UUID> validateAccessToken(String token) {
        if (token.startsWith("hk_")) {
            return apiKeyService.validateApiKey(token)
                    .map(ApiKeyPrincipal::userId);
        }
        return Mono.fromCallable(() -> {
            Claims claims = Jwts.parser()
                    .verifyWith(jwtSecretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            String type = claims.get("type", String.class);
            if (!TOKEN_TYPE_ACCESS.equals(type)) {
                throw new JwtException("Invalid token type");
            }
            return UUID.fromString(claims.getSubject());
        }).onErrorResume(e -> {
            log.debug("Token validation failed: {}", e.getMessage());
            return Mono.empty();
        });
    }

    @Override
    public Mono<String> resolveTier(String token) {
        if (token.startsWith("hk_")) {
            return apiKeyService.validateApiKey(token)
                    .map(ApiKeyPrincipal::tier);
        }
        return Mono.justOrEmpty(extractTier(token));
    }

    @Override
    public Mono<UUID> validateRefreshToken(String refreshToken) {
        String hashedToken = hashToken(refreshToken);

        return redisTemplate.keys(REFRESH_TOKEN_PREFIX + "*")
                .flatMap(key -> redisTemplate.opsForValue().get(key)
                        .filter(storedHash -> storedHash.equals(hashedToken))
                        .map(hash -> {
                            String userIdStr = key.replace(REFRESH_TOKEN_PREFIX, "");
                            return UUID.fromString(userIdStr);
                        }))
                .next();
    }

    @Override
    public Mono<Void> invalidateRefreshToken(UUID userId) {
        String redisKey = REFRESH_TOKEN_PREFIX + userId.toString();
        return redisTemplate.delete(redisKey).then();
    }

    @Override
    public String extractTier(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(jwtSecretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return claims.get("tier", String.class);
        } catch (Exception e) {
            return null;
        }
    }

    private String generateSecureToken() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
}