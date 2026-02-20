package dev.slethware.hermez.auth;

import dev.slethware.hermez.user.User;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface TokenService {

    String generateAccessToken(User user);
    Mono<String> generateRefreshToken(User user);
    Mono<UUID> validateAccessToken(String token);
    Mono<UUID> validateRefreshToken(String refreshToken);
    Mono<Void> invalidateRefreshToken(UUID userId);
    String extractTier(String token);
    Mono<String> resolveTier(String token);
}