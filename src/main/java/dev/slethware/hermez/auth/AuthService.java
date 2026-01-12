package dev.slethware.hermez.auth;

import dev.slethware.hermez.auth.api.AuthResponse;
import dev.slethware.hermez.auth.api.LoginRequest;
import dev.slethware.hermez.auth.api.RefreshTokenRequest;
import dev.slethware.hermez.auth.api.SignupRequest;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface AuthService {

    Mono<Void> register(SignupRequest request);
    Mono<AuthResponse> login(LoginRequest request);
    Mono<AuthResponse> refreshToken(RefreshTokenRequest request);
    Mono<Void> logout(UUID userId);
    Mono<Void> verifyEmail(String token);
    Mono<Void> resendVerificationEmail(String email);
}