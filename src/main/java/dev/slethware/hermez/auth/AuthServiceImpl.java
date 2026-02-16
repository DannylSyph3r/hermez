package dev.slethware.hermez.auth;

import dev.slethware.hermez.auth.api.*;
import dev.slethware.hermez.auth.config.AuthProperties;
import dev.slethware.hermez.auth.config.OAuthProperties;
import dev.slethware.hermez.auth.oauth.OAuth2Handler;
import dev.slethware.hermez.common.util.FrontendUrlResolver;
import dev.slethware.hermez.email.EmailService;
import dev.slethware.hermez.exception.BadRequestException;
import dev.slethware.hermez.exception.ForbiddenException;
import dev.slethware.hermez.exception.TooManyRequestsException;
import dev.slethware.hermez.exception.UnauthorizedException;
import dev.slethware.hermez.user.User;
import dev.slethware.hermez.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final AuthProperties authProperties;
    private final OAuth2Handler oauth2Handler;
    private final OAuthProperties oauthProperties;
    private final FrontendUrlResolver frontendUrlResolver;

    private static final String VERIFICATION_TOKEN_PREFIX = "email_verification:";
    private static final String VERIFICATION_USER_PREFIX = "email_verification:user:";
    private static final String RESET_TOKEN_PREFIX = "password_reset:";
    private static final String RESET_USER_PREFIX = "password_reset:user:";
    private static final String RATE_LIMIT_PREFIX = "ratelimit:login:";
    private static final String LOCKOUT_PREFIX = "lockout:login:";
    private static final String OAUTH_LINK_TOKEN_PREFIX = "oauth_link:";

    @Override
    public Mono<Void> register(SignupRequest request, ServerHttpRequest httpRequest) {
        String normalizedEmail = request.email().toLowerCase().trim();
        log.info("Processing registration for email: {}", normalizedEmail);

        String loginUrl = frontendUrlResolver.getLoginUrl(httpRequest);

        return userRepository.existsByEmail(normalizedEmail)
                .flatMap(exists -> {
                    if (exists) {
                        log.info("Registration attempt for existing email: {}", normalizedEmail);
                        return emailService.sendAccountExistsEmail(normalizedEmail, loginUrl);
                    }

                    User newUser = new User();
                    newUser.setName(request.name());
                    newUser.setEmail(normalizedEmail);
                    newUser.setPasswordHash(passwordEncoder.encode(request.password()));
                    newUser.setTier("chelys");
                    newUser.setEmailVerified(false);

                    return userRepository.save(newUser)
                            .flatMap(savedUser -> sendVerificationEmail(savedUser, httpRequest)
                                    .doOnSuccess(v -> log.info("User registered successfully: {}", savedUser.getEmail()))
                            );
                })
                .then();
    }

    @Override
    public Mono<AuthResponse> login(LoginRequest request) {
        String normalizedEmail = request.email().toLowerCase().trim();
        log.info("Processing login for email: {}", normalizedEmail);

        return checkRateLimit(normalizedEmail)
                .then(userRepository.findByEmail(normalizedEmail))
                .switchIfEmpty(Mono.defer(() ->
                        incrementFailedAttempts(normalizedEmail)
                                .then(Mono.error(new UnauthorizedException("Invalid email or password")))
                ))
                .flatMap(user -> {
                    // Check if user is soft deleted
                    if (user.getDeletedAt() != null) {
                        return incrementFailedAttempts(normalizedEmail)
                                .then(Mono.error(new UnauthorizedException("Invalid email or password")));
                    }

                    if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
                        return incrementFailedAttempts(normalizedEmail)
                                .then(Mono.error(new UnauthorizedException("Invalid email or password")));
                    }

                    if (!user.isEmailVerified()) {
                        return Mono.error(new ForbiddenException("Please verify your email"));
                    }

                    return clearRateLimit(normalizedEmail)
                            .then(userRepository.updateLastLoginAt(user.getId(), LocalDateTime.now()))
                            .then(generateAuthResponse(user));
                });
    }

    @Override
    public Mono<String> initiateGoogleOAuth() {
        String authorizationUrl = oauthProperties.getGoogle().getAuthorizationUri() +
                "?client_id=" + oauthProperties.getGoogle().getClientId() +
                "&redirect_uri=" + oauthProperties.getGoogle().getRedirectUri() +
                "&response_type=code" +
                "&scope=openid%20email%20profile";

        log.info("Initiating Google OAuth flow");
        return Mono.just(authorizationUrl);
    }

    @Override
    public Mono<AuthResponse> handleGoogleCallback(String code) {
        if (code == null || code.isBlank()) {
            return Mono.error(new BadRequestException("Authorization code is required"));
        }

        return oauth2Handler.handleGoogleCallback(code)
                .flatMap(this::generateAuthResponse);
    }

    @Override
    public Mono<String> initiateGitHubOAuth() {
        String authorizationUrl = oauthProperties.getGithub().getAuthorizationUri() +
                "?client_id=" + oauthProperties.getGithub().getClientId() +
                "&redirect_uri=" + oauthProperties.getGithub().getRedirectUri() +
                "&scope=user:email";

        log.info("Initiating GitHub OAuth flow");
        return Mono.just(authorizationUrl);
    }

    @Override
    public Mono<AuthResponse> handleGitHubCallback(String code) {
        if (code == null || code.isBlank()) {
            return Mono.error(new BadRequestException("Authorization code is required"));
        }

        return oauth2Handler.handleGitHubCallback(code)
                .flatMap(this::generateAuthResponse);
    }

    @Override
    public Mono<AuthResponse> refreshToken(RefreshTokenRequest request) {
        log.info("Processing token refresh");

        return tokenService.validateRefreshToken(request.refreshToken())
                .switchIfEmpty(Mono.error(new UnauthorizedException("Invalid refresh token")))
                .flatMap(userId -> userRepository.findById(userId)
                        .switchIfEmpty(Mono.error(new UnauthorizedException("User not found"))))
                .flatMap(user -> tokenService.invalidateRefreshToken(user.getId())
                        .then(generateAuthResponse(user)));
    }

    @Override
    public Mono<Void> logout(UUID userId) {
        log.info("Processing logout for user: {}", userId);
        return tokenService.invalidateRefreshToken(userId);
    }

    @Override
    public Mono<Void> verifyEmail(String token) {
        String tokenKey = VERIFICATION_TOKEN_PREFIX + token;
        String tokenPreview = token.length() > 8 ? token.substring(0, 8) + "..." : token;

        log.debug("Attempting to verify email with token: {}", tokenPreview);

        return redisTemplate.opsForValue().get(tokenKey)
                .switchIfEmpty(Mono.defer(() -> {
                    log.warn("Email verification failed: Invalid or expired token: {}", tokenPreview);
                    return Mono.error(new BadRequestException("Invalid or expired verification token"));
                }))
                .flatMap(userIdStr -> {
                    UUID userId = UUID.fromString(userIdStr);
                    String userKey = VERIFICATION_USER_PREFIX + userId;
                    log.info("Verifying email for user: {}", userId);

                    return redisTemplate.delete(tokenKey)
                            .doOnSuccess(deleted -> log.debug("Deleted verification token, count: {}", deleted))
                            .doOnError(e -> log.error("Failed to delete verification token for user: {}", userId, e))
                            .then(redisTemplate.delete(userKey))
                            .doOnSuccess(deleted -> log.debug("Deleted user verification key, count: {}", deleted))
                            .doOnError(e -> log.error("Failed to delete user verification key for user: {}", userId, e))
                            .then(userRepository.verifyEmail(userId))
                            .doOnSuccess(v -> log.info("Email verified successfully for user: {}", userId))
                            .doOnError(e -> log.error("Failed to update email_verified in database for user: {}", userId, e));
                });
    }

    @Override
    public Mono<Void> resendVerificationEmail(String email, ServerHttpRequest httpRequest) {
        String normalizedEmail = email.toLowerCase().trim();

        return userRepository.findByEmail(normalizedEmail)
                .switchIfEmpty(Mono.empty())
                .flatMap(user -> {
                    if (user.isEmailVerified()) {
                        return Mono.empty();
                    }
                    return sendVerificationEmail(user, httpRequest);
                })
                .then();
    }

    @Override
    public Mono<Void> forgotPassword(ForgotPasswordRequest request, ServerHttpRequest httpRequest) {
        String normalizedEmail = request.email().toLowerCase().trim();
        log.info("Processing forgot password request for email: {}", normalizedEmail);

        return userRepository.findByEmail(normalizedEmail)
                .switchIfEmpty(Mono.defer(() -> {
                    log.info("Password reset requested for non-existent email: {}", normalizedEmail);
                    return Mono.empty();
                }))
                .flatMap(user -> sendPasswordResetEmail(user, httpRequest))
                .then();
    }

    @Override
    public Mono<Void> validateResetToken(String email, String token) {
        String normalizedEmail = email.toLowerCase().trim();
        String tokenKey = RESET_TOKEN_PREFIX + token;
        String tokenPreview = token.length() > 8 ? token.substring(0, 8) + "..." : token;

        log.debug("Validating reset token: {} for email: {}", tokenPreview, normalizedEmail);

        return redisTemplate.opsForValue().get(tokenKey)
                .switchIfEmpty(Mono.defer(() -> {
                    log.warn("Reset token validation failed: Invalid or expired token for email: {}", normalizedEmail);
                    return Mono.error(new BadRequestException("Invalid or expired reset token"));
                }))
                .flatMap(userIdStr -> {
                    UUID userId = UUID.fromString(userIdStr);
                    log.debug("Found user: {} for reset token", userId);

                    return userRepository.findById(userId)
                            .switchIfEmpty(Mono.defer(() -> {
                                log.error("User not found for reset token, userId: {}", userId);
                                return Mono.error(new BadRequestException("User not found"));
                            }))
                            .flatMap(user -> {
                                if (!user.getEmail().equals(normalizedEmail)) {
                                    log.warn("Email mismatch for reset token. Expected: {}, Got: {}", user.getEmail(), normalizedEmail);
                                    return Mono.error(new BadRequestException("Invalid or expired reset token"));
                                }
                                log.info("Reset token validated successfully for email: {}", normalizedEmail);
                                return Mono.empty();
                            });
                });
    }

    @Override
    public Mono<Void> resetPassword(ResetPasswordRequest request) {
        String normalizedEmail = request.email().toLowerCase().trim();
        String tokenKey = RESET_TOKEN_PREFIX + request.token();
        String tokenPreview = request.token().length() > 8 ? request.token().substring(0, 8) + "..." : request.token();

        log.info("Resetting password for email: {}", normalizedEmail);
        log.debug("Using reset token: {}", tokenPreview);

        return redisTemplate.opsForValue().get(tokenKey)
                .switchIfEmpty(Mono.defer(() -> {
                    log.warn("Password reset failed: Invalid or expired token for email: {}", normalizedEmail);
                    return Mono.error(new BadRequestException("Invalid or expired reset token"));
                }))
                .flatMap(userIdStr -> {
                    UUID userId = UUID.fromString(userIdStr);
                    log.debug("Found user: {} for password reset", userId);

                    return userRepository.findById(userId)
                            .switchIfEmpty(Mono.defer(() -> {
                                log.error("User not found for password reset, userId: {}", userId);
                                return Mono.error(new BadRequestException("User not found"));
                            }))
                            .flatMap(user -> {
                                if (!user.getEmail().equals(normalizedEmail)) {
                                    log.warn("Email mismatch for password reset. Expected: {}, Got: {}", user.getEmail(), normalizedEmail);
                                    return Mono.error(new BadRequestException("Invalid or expired reset token"));
                                }

                                String newPasswordHash = passwordEncoder.encode(request.newPassword());
                                String userKey = RESET_USER_PREFIX + userId;

                                return redisTemplate.delete(tokenKey)
                                        .doOnSuccess(deleted -> log.debug("Deleted reset token, count: {}", deleted))
                                        .doOnError(e -> log.error("Failed to delete reset token for user: {}", userId, e))
                                        .then(redisTemplate.delete(userKey))
                                        .doOnSuccess(deleted -> log.debug("Deleted user reset key, count: {}", deleted))
                                        .doOnError(e -> log.error("Failed to delete user reset key for user: {}", userId, e))
                                        .then(userRepository.updatePassword(userId, newPasswordHash))
                                        .doOnSuccess(v -> log.info("Password reset successfully for: {}", normalizedEmail))
                                        .doOnError(e -> log.error("Failed to update password in database for user: {}", userId, e));
                            });
                });
    }

    private Mono<Void> sendVerificationEmail(User user, ServerHttpRequest httpRequest) {
        String token = UUID.randomUUID().toString();
        String tokenKey = VERIFICATION_TOKEN_PREFIX + token;
        String userKey = VERIFICATION_USER_PREFIX + user.getId();

        String encodedToken = URLEncoder.encode(token, StandardCharsets.UTF_8);
        String verificationUrl = frontendUrlResolver.getFrontendUrl(httpRequest) + "/verify-email?token=" + encodedToken;

        log.debug("Generating verification email for user: {}", user.getId());

        // Get old token if exists and delete it
        return redisTemplate.opsForValue().get(userKey)
                .flatMap(oldToken -> {
                    String oldTokenKey = VERIFICATION_TOKEN_PREFIX + oldToken;
                    log.debug("Deleting old verification token for user: {}", user.getId());
                    return redisTemplate.delete(oldTokenKey)
                            .doOnSuccess(deleted -> log.debug("Deleted old verification token, count: {}", deleted))
                            .doOnError(e -> log.error("Failed to delete old verification token for user: {}", user.getId(), e));
                })
                .switchIfEmpty(Mono.just(0L)) // No old token, continue.
                // Delete old user key
                .then(redisTemplate.delete(userKey))
                .doOnSuccess(deleted -> {
                    if (deleted > 0) {
                        log.debug("Deleted old user verification key for user: {}", user.getId());
                    }
                })
                .doOnError(e -> log.error("Failed to delete user verification key for user: {}", user.getId(), e))
                // Store new token key
                .then(redisTemplate.opsForValue().set(tokenKey, user.getId().toString(), Duration.ofHours(24)))
                .flatMap(setResult -> {
                    if (!Boolean.TRUE.equals(setResult)) {
                        log.error("Failed to store verification token in Redis for user: {}", user.getId());
                        return Mono.error(new RuntimeException("Failed to store verification token"));
                    }
                    log.debug("Stored verification token for user: {}", user.getId());
                    return redisTemplate.opsForValue().set(userKey, token, Duration.ofHours(24));
                })
                .flatMap(setResult -> {
                    if (!Boolean.TRUE.equals(setResult)) {
                        log.error("Failed to store user verification key in Redis for user: {}", user.getId());
                        return Mono.error(new RuntimeException("Failed to store user verification key"));
                    }
                    log.debug("Stored user verification key for user: {}", user.getId());
                    return emailService.sendVerificationEmail(user.getEmail(), verificationUrl);
                })
                .doOnSuccess(v -> log.info("Verification email sent to: {}", user.getEmail()))
                .doOnError(e -> log.error("Error in verification email flow for user: {}", user.getId(), e));
    }

    private Mono<Void> sendPasswordResetEmail(User user, ServerHttpRequest httpRequest) {
        String token = UUID.randomUUID().toString();
        String tokenKey = RESET_TOKEN_PREFIX + token;
        String userKey = RESET_USER_PREFIX + user.getId();

        String encodedToken = URLEncoder.encode(token, StandardCharsets.UTF_8);
        String encodedEmail = URLEncoder.encode(user.getEmail(), StandardCharsets.UTF_8);

        String resetUrl = frontendUrlResolver.getFrontendUrl(httpRequest) + "/reset-password?token=" + encodedToken + "&email=" + encodedEmail;

        log.debug("Generating password reset email for user: {}", user.getId());

        // Get old token if exists and delete it
        return redisTemplate.opsForValue().get(userKey)
                .flatMap(oldToken -> {
                    String oldTokenKey = RESET_TOKEN_PREFIX + oldToken;
                    log.debug("Deleting old password reset token for user: {}", user.getId());
                    return redisTemplate.delete(oldTokenKey)
                            .doOnSuccess(deleted -> log.debug("Deleted old reset token, count: {}", deleted))
                            .doOnError(e -> log.error("Failed to delete old reset token for user: {}", user.getId(), e));
                })
                .switchIfEmpty(Mono.just(0L)) // No old token, continue.
                // Delete old user key
                .then(redisTemplate.delete(userKey))
                .doOnSuccess(deleted -> {
                    if (deleted > 0) {
                        log.debug("Deleted old user reset key for user: {}", user.getId());
                    }
                })
                .doOnError(e -> log.error("Failed to delete user reset key for user: {}", user.getId(), e))
                // Store new token key
                .then(redisTemplate.opsForValue().set(tokenKey, user.getId().toString(), Duration.ofMinutes(5)))
                .flatMap(setResult -> {
                    if (!Boolean.TRUE.equals(setResult)) {
                        log.error("Failed to store password reset token in Redis for user: {}", user.getId());
                        return Mono.error(new RuntimeException("Failed to store password reset token"));
                    }
                    log.debug("Stored password reset token for user: {}", user.getId());
                    return redisTemplate.opsForValue().set(userKey, token, Duration.ofMinutes(5));
                })
                .flatMap(setResult -> {
                    if (!Boolean.TRUE.equals(setResult)) {
                        log.error("Failed to store user reset key in Redis for user: {}", user.getId());
                        return Mono.error(new RuntimeException("Failed to store user reset key"));
                    }
                    log.debug("Stored user reset key for user: {}", user.getId());
                    return emailService.sendPasswordResetEmail(user.getEmail(), resetUrl);
                })
                .doOnSuccess(v -> log.info("Password reset email sent to: {}", user.getEmail()))
                .doOnError(e -> log.error("Error in password reset flow for user: {}", user.getId(), e));
    }

    private Mono<AuthResponse> generateAuthResponse(User user) {
        String accessToken = tokenService.generateAccessToken(user);

        return tokenService.generateRefreshToken(user)
                .map(refreshToken -> new AuthResponse(
                        accessToken,
                        refreshToken,
                        authProperties.getJwt().getAccessTokenExpiration() / 1000,
                        UserResponse.from(user)
                ));
    }

    private Mono<Void> checkRateLimit(String email) {
        String lockoutKey = LOCKOUT_PREFIX + email;

        log.debug("Checking rate limit for: {}", email);

        return redisTemplate.hasKey(lockoutKey)
                .doOnNext(locked -> {
                    if (locked) {
                        log.warn("Login attempt blocked for locked out user: {}", email);
                    }
                })
                .flatMap(locked -> {
                    if (locked) {
                        return Mono.error(new TooManyRequestsException(
                                "Too many failed attempts. Please try again in " +
                                        authProperties.getRateLimit().getLockoutSeconds() + " seconds."));
                    }
                    return Mono.empty();
                })
                .doOnError(e -> {
                    if (!(e instanceof TooManyRequestsException)) {
                        log.error("Redis error during rate limit check for: {}. Allowing login (fail-open)", email, e);
                    }
                })
                .onErrorResume(e -> {
                    if (e instanceof TooManyRequestsException) {
                        return Mono.error(e);
                    }
                    // Fail-open: allow login if Redis is down
                    return Mono.empty();
                })
                .then();
    }

    private Mono<Void> incrementFailedAttempts(String email) {
        String rateLimitKey = RATE_LIMIT_PREFIX + email;
        Duration window = Duration.ofSeconds(authProperties.getRateLimit().getWindowSeconds());

        return redisTemplate.opsForValue().increment(rateLimitKey)
                .flatMap(count -> {
                    log.debug("Failed login attempt #{} for: {}", count, email);
                    if (count == 1) {
                        return redisTemplate.expire(rateLimitKey, window)
                                .doOnSuccess(v -> log.debug("Set rate limit window expiry for: {}", email))
                                .doOnError(e -> log.error("Failed to set expiry for rate limit key: {}", email, e))
                                .thenReturn(count);
                    }
                    return Mono.just(count);
                })
                .flatMap(count -> {
                    if (count >= authProperties.getRateLimit().getMaxAttempts()) {
                        log.warn("Locking out user after {} failed attempts: {}", count, email);
                        String lockoutKey = LOCKOUT_PREFIX + email;
                        Duration lockout = Duration.ofSeconds(authProperties.getRateLimit().getLockoutSeconds());
                        return redisTemplate.opsForValue().set(lockoutKey, "1", lockout)
                                .doOnSuccess(v -> log.info("User locked out for {} seconds: {}", lockout.getSeconds(), email))
                                .doOnError(e -> log.error("Failed to set lockout for: {}", email, e))
                                .then(redisTemplate.delete(rateLimitKey))
                                .doOnError(e -> log.error("Failed to delete rate limit key for: {}", email, e))
                                .then();
                    }
                    return Mono.empty();
                })
                .doOnError(e -> log.error("Error incrementing failed attempts for: {}", email, e))
                .onErrorResume(e -> {
                    // Fail-open: continue even if Redis fails
                    log.error("Redis error during failed attempt increment. Rate limiting disabled for: {}", email);
                    return Mono.empty();
                });
    }

    private Mono<Void> clearRateLimit(String email) {
        String rateLimitKey = RATE_LIMIT_PREFIX + email;

        return redisTemplate.delete(rateLimitKey)
                .doOnSuccess(deleted -> {
                    if (deleted > 0) {
                        log.debug("Cleared rate limit for successful login: {}", email);
                    }
                })
                .doOnError(e -> log.error("Failed to clear rate limit for: {}", email, e))
                .onErrorResume(e -> {
                    // Fail-open: continue login even if Redis fails
                    log.error("Redis error clearing rate limit. Continuing login for: {}", email);
                    return Mono.empty();
                })
                .then();
    }

    @Override
    public Mono<String> initiateGoogleOAuthLink() {
        return ReactiveSecurityContextHolder.getContext()
                .map(securityContext -> securityContext.getAuthentication().getName())
                .map(UUID::fromString)
                .flatMap(userId -> {
                    // Generate link token and store in Redis (5 min TTL)
                    String linkToken = UUID.randomUUID().toString();
                    String redisKey = OAUTH_LINK_TOKEN_PREFIX + linkToken;

                    return redisTemplate.opsForValue()
                            .set(redisKey, userId.toString(), Duration.ofMinutes(5))
                            .then(Mono.defer(() -> {
                                String state = "action:link,token:" + linkToken + ",redirect:/dashboard/settings";
                                String authorizationUrl = oauthProperties.getGoogle().getAuthorizationUri() +
                                        "?client_id=" + oauthProperties.getGoogle().getClientId() +
                                        "&redirect_uri=" + oauthProperties.getGoogle().getRedirectUri() +
                                        "&response_type=code" +
                                        "&scope=email profile" +
                                        "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8);

                                log.info("Initiating Google OAuth link for user: {}", userId);
                                return Mono.just(authorizationUrl);
                            }));
                });
    }

    @Override
    public Mono<Void> handleGoogleLinkCallback(String code, String state, ServerHttpRequest httpRequest, ServerHttpResponse response) {
        if (code == null || code.isBlank()) {
            return redirectToSettingsWithError("OAuth code is missing", httpRequest, response);
        }

        // Parse state to extract link token
        String linkToken = extractStateParam(state, "token");
        if (linkToken == null) {
            return redirectToSettingsWithError("Invalid OAuth state", httpRequest, response);
        }

        // Get userId from Redis
        String redisKey = OAUTH_LINK_TOKEN_PREFIX + linkToken;
        return redisTemplate.opsForValue().get(redisKey)
                .switchIfEmpty(Mono.defer(() -> {
                    log.warn("OAuth link token expired or invalid: {}", linkToken);
                    return Mono.error(new UnauthorizedException("OAuth link session expired. Please try again."));
                }))
                .flatMap(userIdStr -> {
                    UUID userId = UUID.fromString(userIdStr);

                    // Delete token (one-time use)
                    return redisTemplate.delete(redisKey)
                            .then(oauth2Handler.handleGoogleLinkCallback(code, userId))
                            .then(redirectToSettingsWithSuccess("google", httpRequest, response));
                })
                .onErrorResume(error -> redirectToSettingsWithError(error.getMessage(), httpRequest, response));
    }

    @Override
    public Mono<String> initiateGitHubOAuthLink() {
        return ReactiveSecurityContextHolder.getContext()
                .map(securityContext -> securityContext.getAuthentication().getName())
                .map(UUID::fromString)
                .flatMap(userId -> {
                    // Generate link token and store in Redis (5 min TTL)
                    String linkToken = UUID.randomUUID().toString();
                    String redisKey = OAUTH_LINK_TOKEN_PREFIX + linkToken;

                    return redisTemplate.opsForValue()
                            .set(redisKey, userId.toString(), Duration.ofMinutes(5))
                            .then(Mono.defer(() -> {
                                String state = "action:link,token:" + linkToken + ",redirect:/dashboard/settings";
                                String authorizationUrl = oauthProperties.getGithub().getAuthorizationUri() +
                                        "?client_id=" + oauthProperties.getGithub().getClientId() +
                                        "&redirect_uri=" + oauthProperties.getGithub().getRedirectUri() +
                                        "&scope=user:email" +
                                        "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8);

                                log.info("Initiating GitHub OAuth link for user: {}", userId);
                                return Mono.just(authorizationUrl);
                            }));
                });
    }

    @Override
    public Mono<Void> handleGitHubLinkCallback(String code, String state, ServerHttpRequest httpRequest, ServerHttpResponse response) {
        if (code == null || code.isBlank()) {
            return redirectToSettingsWithError("OAuth code is missing", httpRequest, response);
        }

        // Parse state to extract link token
        String linkToken = extractStateParam(state, "token");
        if (linkToken == null) {
            return redirectToSettingsWithError("Invalid OAuth state", httpRequest, response);
        }

        // Get userId from Redis
        String redisKey = OAUTH_LINK_TOKEN_PREFIX + linkToken;
        return redisTemplate.opsForValue().get(redisKey)
                .switchIfEmpty(Mono.defer(() -> {
                    log.warn("OAuth link token expired or invalid: {}", linkToken);
                    return Mono.error(new UnauthorizedException("OAuth link session expired. Please try again."));
                }))
                .flatMap(userIdStr -> {
                    UUID userId = UUID.fromString(userIdStr);

                    // Delete token (one-time use)
                    return redisTemplate.delete(redisKey)
                            .then(oauth2Handler.handleGitHubLinkCallback(code, userId))
                            .then(redirectToSettingsWithSuccess("github", httpRequest, response));
                })
                .onErrorResume(error -> redirectToSettingsWithError(error.getMessage(), httpRequest, response));
    }

    private String extractStateParam(String state, String param) {
        if (state == null || !state.contains(param + ":")) {
            return null;
        }

        String[] parts = state.split(",");
        for (String part : parts) {
            if (part.startsWith(param + ":")) {
                return part.substring((param + ":").length());
            }
        }
        return null;
    }

    private Mono<Void> redirectToSettingsWithSuccess(String provider, ServerHttpRequest httpRequest, ServerHttpResponse response) {
        String frontendUrl = frontendUrlResolver.getFrontendUrl(httpRequest);
        String redirectUrl = String.format("%s/dashboard/settings?connected=%s", frontendUrl, provider);

        log.debug("Redirecting to settings after successful OAuth link: {}", provider);
        response.setStatusCode(HttpStatus.FOUND);
        response.getHeaders().setLocation(URI.create(redirectUrl));
        return response.setComplete();
    }

    private Mono<Void> redirectToSettingsWithError(String errorMessage, ServerHttpRequest httpRequest, ServerHttpResponse response) {
        String frontendUrl = frontendUrlResolver.getFrontendUrl(httpRequest);
        String redirectUrl = String.format(
                "%s/dashboard/settings?error=oauth_link_failed&message=%s",
                frontendUrl,
                URLEncoder.encode(errorMessage, StandardCharsets.UTF_8)
        );

        log.warn("OAuth link failed, redirecting to settings: {}", errorMessage);
        response.setStatusCode(HttpStatus.FOUND);
        response.getHeaders().setLocation(URI.create(redirectUrl));
        return response.setComplete();
    }
}