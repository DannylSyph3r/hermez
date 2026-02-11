package dev.slethware.hermez.auth;

import dev.slethware.hermez.auth.api.AuthResponse;
import dev.slethware.hermez.auth.api.LoginRequest;
import dev.slethware.hermez.auth.api.RefreshTokenRequest;
import dev.slethware.hermez.auth.api.SignupRequest;
import dev.slethware.hermez.auth.api.ForgotPasswordRequest;
import dev.slethware.hermez.auth.api.ResetPasswordRequest;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface AuthService {

    Mono<Void> register(SignupRequest request, ServerHttpRequest httpRequest);
    Mono<AuthResponse> login(LoginRequest request);
    Mono<AuthResponse> refreshToken(RefreshTokenRequest request);
    Mono<Void> logout(UUID userId);
    Mono<Void> verifyEmail(String token);
    Mono<Void> resendVerificationEmail(String email, ServerHttpRequest httpRequest);
    Mono<String> initiateGoogleOAuth();
    Mono<AuthResponse> handleGoogleCallback(String code);
    Mono<String> initiateGitHubOAuth();
    Mono<AuthResponse> handleGitHubCallback(String code);
    Mono<Void> forgotPassword(ForgotPasswordRequest request, ServerHttpRequest httpRequest);
    Mono<Void> validateResetToken(String email, String token);
    Mono<Void> resetPassword(ResetPasswordRequest request);
    Mono<String> initiateGoogleOAuthLink();
    Mono<Void> handleGoogleLinkCallback(String code, String state, ServerHttpRequest httpRequest, ServerHttpResponse response);
    Mono<String> initiateGitHubOAuthLink();
    Mono<Void> handleGitHubLinkCallback(String code, String state, ServerHttpRequest httpRequest, ServerHttpResponse response);
}