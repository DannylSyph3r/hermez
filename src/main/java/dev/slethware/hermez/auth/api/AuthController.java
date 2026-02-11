package dev.slethware.hermez.auth.api;

import dev.slethware.hermez.auth.AuthService;
import dev.slethware.hermez.common.models.response.ApiResponse;
import dev.slethware.hermez.common.util.ApiResponseUtil;
import dev.slethware.hermez.common.util.FrontendUrlResolver;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.Map;
import java.util.UUID;

import static reactor.netty.http.HttpConnectionLiveness.log;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Authentication and authorization endpoints")
public class AuthController {

    private final AuthService authService;
    private final FrontendUrlResolver frontendUrlResolver;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.OK)
    @Operation(summary = "Register a new user", description = "Creates a new user account and sends verification email")
    public Mono<ApiResponse<Void>> register(
            @Valid @RequestBody SignupRequest request,
            ServerHttpRequest httpRequest
    ) {
        return authService.register(request, httpRequest)
                .then(Mono.just(ApiResponseUtil.successFullVoid("Registration successful. Please check your email to verify your account.")));
    }

    @PostMapping("/login")
    @ResponseStatus(HttpStatus.OK)
    @Operation(summary = "User login", description = "Authenticates user and returns tokens")
    public Mono<ApiResponse<AuthResponse>> login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request)
                .map(response -> ApiResponseUtil.successFull("Login successful", response));
    }

    @PostMapping("/refresh")
    @ResponseStatus(HttpStatus.OK)
    @Operation(summary = "Refresh tokens", description = "Exchanges refresh token for new access and refresh tokens")
    public Mono<ApiResponse<AuthResponse>> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return authService.refreshToken(request)
                .map(response -> ApiResponseUtil.successFull("Token refreshed successfully", response));
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.OK)
    @Operation(summary = "Logout user", description = "Invalidates refresh token")
    public Mono<ApiResponse<Void>> logout(Principal principal) {
        UUID userId = UUID.fromString(principal.getName());
        return authService.logout(userId)
                .then(Mono.just(ApiResponseUtil.successFullVoid("Logout successful")));
    }

    @GetMapping("/verify-email")
    @ResponseStatus(HttpStatus.OK)
    @Operation(summary = "Verify email", description = "Verifies user email with token from email link")
    public Mono<ApiResponse<Void>> verifyEmail(@RequestParam String token) {
        return authService.verifyEmail(token)
                .then(Mono.just(ApiResponseUtil.successFullVoid("Email verified successfully")));
    }

    @PostMapping("/resend-verification")
    @ResponseStatus(HttpStatus.OK)
    @Operation(summary = "Resend verification email", description = "Sends a new verification email")
    public Mono<ApiResponse<Void>> resendVerification(@RequestParam String email, ServerHttpRequest httpRequest
    ) {
        return authService.resendVerificationEmail(email, httpRequest)
                .then(Mono.just(ApiResponseUtil.successFullVoid("If the email exists and is unverified, a verification email has been sent")));
    }

    @PostMapping("/forgot-password")
    @ResponseStatus(HttpStatus.OK)
    @Operation(summary = "Request password reset", description = "Sends a password reset link to the user's email if the account exists")
    public Mono<ApiResponse<Void>> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request, ServerHttpRequest httpRequest
    ) {
        return authService.forgotPassword(request, httpRequest)
                .then(Mono.just(ApiResponseUtil.successFullVoid("If your email is registered, you will receive a password reset link")));
    }

    @GetMapping("/validate-reset-token")
    @ResponseStatus(HttpStatus.OK)
    @Operation(summary = "Validate password reset token", description = "Checks if the provided password reset token is valid and not expired")
    public Mono<ApiResponse<Void>> validateResetToken(
            @RequestParam String email,
            @RequestParam String token
    ) {
        return authService.validateResetToken(email, token)
                .then(Mono.just(ApiResponseUtil.successFullVoid("Token is valid")));
    }

    @PostMapping("/reset-password")
    @ResponseStatus(HttpStatus.OK)
    @Operation(summary = "Reset user password", description = "Resets the password for a user using a valid reset token")
    public Mono<ApiResponse<Void>> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        return authService.resetPassword(request)
                .then(Mono.just(ApiResponseUtil.successFullVoid("Password has been reset successfully")));
    }

    @GetMapping("/oauth/google")
    @Operation(summary = "Initiate Google OAuth", description = "Redirects to Google OAuth consent screen. Use ?mode=link for linking to existing account.")
    public Mono<Void> initiateGoogleOAuth(
            @RequestParam(required = false) String mode,
            ServerHttpResponse response
    ) {
        if ("link".equals(mode)) {
            return authService.initiateGoogleOAuthLink()
                    .flatMap(authorizationUrl -> {
                        response.setStatusCode(HttpStatus.FOUND);
                        response.getHeaders().setLocation(URI.create(authorizationUrl));
                        return response.setComplete();
                    });
        }

        return authService.initiateGoogleOAuth()
                .flatMap(authorizationUrl -> {
                    response.setStatusCode(HttpStatus.FOUND);
                    response.getHeaders().setLocation(URI.create(authorizationUrl));
                    return response.setComplete();
                });
    }

    @GetMapping("/oauth/google/callback")
    @Operation(summary = "Google OAuth callback", description = "Handles OAuth callback from Google and redirects to frontend")
    public Mono<Void> handleGoogleCallback(
            @RequestParam String code,
            @RequestParam(required = false) String state,
            ServerHttpRequest httpRequest,
            ServerHttpResponse response
    ) {
        // Check if this is a link callback
        if (state != null && state.contains("action:link")) {
            return authService.handleGoogleLinkCallback(code, state, httpRequest, response);
        }

        // Regular login/signup flow
        return authService.handleGoogleCallback(code)
                .flatMap(authResponse -> redirectToFrontend(authResponse, httpRequest, response))
                .onErrorResume(error -> redirectToLoginWithError(error, httpRequest, response));
    }

    @GetMapping("/oauth/github")
    @Operation(summary = "Initiate GitHub OAuth", description = "Redirects to GitHub OAuth consent screen. Use ?mode=link for linking to existing account.")
    public Mono<Void> initiateGitHubOAuth(
            @RequestParam(required = false) String mode,
            ServerHttpResponse response
    ) {
        if ("link".equals(mode)) {
            return authService.initiateGitHubOAuthLink()
                    .flatMap(authorizationUrl -> {
                        response.setStatusCode(HttpStatus.FOUND);
                        response.getHeaders().setLocation(URI.create(authorizationUrl));
                        return response.setComplete();
                    });
        }

        return authService.initiateGitHubOAuth()
                .flatMap(authorizationUrl -> {
                    response.setStatusCode(HttpStatus.FOUND);
                    response.getHeaders().setLocation(URI.create(authorizationUrl));
                    return response.setComplete();
                });
    }

    @GetMapping("/oauth/github/callback")
    @Operation(summary = "GitHub OAuth callback", description = "Handles OAuth callback from GitHub and redirects to frontend")
    public Mono<Void> handleGitHubCallback(
            @RequestParam String code,
            @RequestParam(required = false) String state,
            ServerHttpRequest httpRequest,
            ServerHttpResponse response
    ) {
        // Check if this is a link callback
        if (state != null && state.contains("action:link")) {
            return authService.handleGitHubLinkCallback(code, state, httpRequest, response);
        }

        // Regular login/signup flow
        return authService.handleGitHubCallback(code)
                .flatMap(authResponse -> redirectToFrontend(authResponse, httpRequest, response))
                .onErrorResume(error -> redirectToLoginWithError(error, httpRequest, response));
    }

    @GetMapping("/oauth/google/link")
    @Operation(summary = "Get Google OAuth link URL", description = "Returns authorization URL for linking Google account. Requires authentication.")
    public Mono<ApiResponse<Map<String, String>>> getGoogleOAuthLinkUrl() {
        return authService.initiateGoogleOAuthLink()
                .map(authorizationUrl -> ApiResponseUtil.successFull(
                        "Google OAuth URL generated",
                        Map.of("authorizationUrl", authorizationUrl)
                ));
    }

    @GetMapping("/oauth/github/link")
    @Operation(summary = "Get GitHub OAuth link URL", description = "Returns authorization URL for linking GitHub account. Requires authentication.")
    public Mono<ApiResponse<Map<String, String>>> getGitHubOAuthLinkUrl() {
        return authService.initiateGitHubOAuthLink()
                .map(authorizationUrl -> ApiResponseUtil.successFull(
                        "GitHub OAuth URL generated",
                        Map.of("authorizationUrl", authorizationUrl)
                ));
    }

    private Mono<Void> redirectToFrontend(
            AuthResponse authResponse,
            ServerHttpRequest httpRequest,
            ServerHttpResponse response
    ) {
        String frontendUrl = frontendUrlResolver.getFrontendUrl(httpRequest);
        String redirectUrl = String.format(
                "%s/callback?accessToken=%s&refreshToken=%s&expiresIn=%d",
                frontendUrl,
                authResponse.accessToken(),
                authResponse.refreshToken(),
                authResponse.expiresIn()
        );

        log.debug("Redirecting to frontend callback with tokens");
        response.setStatusCode(HttpStatus.FOUND);
        response.getHeaders().setLocation(URI.create(redirectUrl));
        return response.setComplete();
    }

    private Mono<Void> redirectToLoginWithError(
            Throwable error,
            ServerHttpRequest httpRequest,
            ServerHttpResponse response
    ) {
        String frontendUrl = frontendUrlResolver.getFrontendUrl(httpRequest);
        String errorMessage = error.getMessage() != null ? error.getMessage() : "Authentication failed";
        String redirectUrl = String.format(
                "%s/login?error=oauth_failed&message=%s",
                frontendUrl,
                URLEncoder.encode(errorMessage, StandardCharsets.UTF_8)
        );

        log.warn("OAuth authentication failed, redirecting to login: {}", errorMessage);
        response.setStatusCode(HttpStatus.FOUND);
        response.getHeaders().setLocation(URI.create(redirectUrl));
        return response.setComplete();
    }
}