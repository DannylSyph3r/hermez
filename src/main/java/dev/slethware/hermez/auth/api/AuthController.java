package dev.slethware.hermez.auth.api;

import dev.slethware.hermez.auth.AuthService;
import dev.slethware.hermez.common.models.response.ApiResponse;
import dev.slethware.hermez.common.util.ApiResponseUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.security.Principal;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Authentication and authorization endpoints")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Register a new user", description = "Creates a new user account and sends verification email")
    public Mono<ApiResponse<AuthResponse>> register(@Valid @RequestBody SignupRequest request) {
        return authService.register(request)
                .map(response -> ApiResponseUtil.created("Registration successful. Please verify your email.", response));
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
    public Mono<ApiResponse<Void>> resendVerification(@RequestParam String email) {
        return authService.resendVerificationEmail(email)
                .then(Mono.just(ApiResponseUtil.successFullVoid("If the email exists and is unverified, a verification email has been sent")));
    }
}