package dev.slethware.hermez.auth;

import dev.slethware.hermez.auth.api.*;
import dev.slethware.hermez.auth.config.AuthProperties;
import dev.slethware.hermez.auth.config.OAuthProperties;
import dev.slethware.hermez.auth.oauth.OAuth2Handler;
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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

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

    private static final String VERIFICATION_TOKEN_PREFIX = "email_verification:";
    private static final String VERIFICATION_USER_PREFIX = "email_verification:user:";
    private static final String RESET_TOKEN_PREFIX = "password_reset:";
    private static final String RESET_USER_PREFIX = "password_reset:user:";
    private static final String RATE_LIMIT_PREFIX = "ratelimit:login:";
    private static final String LOCKOUT_PREFIX = "lockout:login:";

    @Override
    public Mono<Void> register(SignupRequest request) {
        String normalizedEmail = request.email().toLowerCase().trim();
        log.info("Processing registration for email: {}", normalizedEmail);

        return userRepository.existsByEmail(normalizedEmail)
                .flatMap(exists -> {
                    if (exists) {
                        return Mono.error(new BadRequestException("Email already registered"));
                    }

                    User user = User.builder()
                            .email(normalizedEmail)
                            .name(request.name())
                            .passwordHash(passwordEncoder.encode(request.password()))
                            .tier("free")
                            .emailVerified(false)
                            .createdAt(LocalDateTime.now())
                            .build();

                    return userRepository.save(user);
                })
                .flatMap(savedUser -> {
                    log.info("User registered successfully: {}", savedUser.getEmail());
                    return sendVerificationEmail(savedUser);
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
                    if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
                        return incrementFailedAttempts(normalizedEmail)
                                .then(Mono.error(new UnauthorizedException("Invalid email or password")));
                    }

                    if (!user.isEmailVerified()) {
                        return Mono.error(new ForbiddenException("Please verify your email before logging in"));
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

        return redisTemplate.opsForValue().get(tokenKey)
                .switchIfEmpty(Mono.error(new BadRequestException("Invalid or expired verification token")))
                .flatMap(userIdStr -> {
                    UUID userId = UUID.fromString(userIdStr);
                    String userKey = VERIFICATION_USER_PREFIX + userId;

                    return redisTemplate.delete(tokenKey)
                            .then(redisTemplate.delete(userKey))
                            .then(userRepository.verifyEmail(userId));
                })
                .doOnSuccess(v -> log.info("Email verified successfully"));
    }

    @Override
    public Mono<Void> resendVerificationEmail(String email) {
        String normalizedEmail = email.toLowerCase().trim();

        return userRepository.findByEmail(normalizedEmail)
                .switchIfEmpty(Mono.empty()) // Silent success pattern
                .flatMap(user -> {
                    if (user.isEmailVerified()) {
                        return Mono.empty(); // Already verified, silent success
                    }
                    return sendVerificationEmail(user);
                })
                .then();
    }

    @Override
    public Mono<Void> forgotPassword(ForgotPasswordRequest request) {
        String normalizedEmail = request.email().toLowerCase().trim();
        log.info("Processing forgot password request for email: {}", normalizedEmail);

        return userRepository.findByEmail(normalizedEmail)
                .flatMap(user -> {
                    String userKey = RESET_USER_PREFIX + user.getId();

                    return redisTemplate.opsForValue().get(userKey)
                            .flatMap(oldToken -> redisTemplate.delete(RESET_TOKEN_PREFIX + oldToken))
                            .then(sendPasswordResetEmail(user));
                })
                .switchIfEmpty(Mono.defer(() -> {
                    log.info("Password reset requested for non-existent email: {}", normalizedEmail);
                    return Mono.empty();
                }))
                .then();
    }

    @Override
    public Mono<Void> validateResetToken(String email, String token) {
        String normalizedEmail = email.toLowerCase().trim();
        log.info("Validating reset token for email: {}", normalizedEmail);

        String tokenKey = RESET_TOKEN_PREFIX + token;

        return redisTemplate.opsForValue().get(tokenKey)
                .switchIfEmpty(Mono.error(new BadRequestException("Invalid or expired reset token")))
                .flatMap(userIdStr -> {
                    UUID userId = UUID.fromString(userIdStr);

                    return userRepository.findById(userId)
                            .switchIfEmpty(Mono.error(new BadRequestException("User not found")))
                            .flatMap(user -> {
                                if (!user.getEmail().equals(normalizedEmail)) {
                                    return Mono.error(new BadRequestException("Token does not belong to this user"));
                                }
                                return Mono.empty();
                            });
                });
    }

    @Override
    public Mono<Void> resetPassword(ResetPasswordRequest request) {
        String normalizedEmail = request.email().toLowerCase().trim();
        log.info("Resetting password for email: {}", normalizedEmail);

        String tokenKey = RESET_TOKEN_PREFIX + request.token();

        return redisTemplate.opsForValue().get(tokenKey)
                .switchIfEmpty(Mono.error(new BadRequestException("Invalid or expired reset token")))
                .flatMap(userIdStr -> {
                    UUID userId = UUID.fromString(userIdStr);

                    return userRepository.findById(userId)
                            .switchIfEmpty(Mono.error(new BadRequestException("User not found")))
                            .flatMap(user -> {
                                if (!user.getEmail().equals(normalizedEmail)) {
                                    return Mono.error(new BadRequestException("Token does not belong to this user"));
                                }

                                String newPasswordHash = passwordEncoder.encode(request.newPassword());

                                String userKey = RESET_USER_PREFIX + userId;

                                return redisTemplate.delete(tokenKey)
                                        .then(redisTemplate.delete(userKey))
                                        .then(userRepository.updatePassword(userId, newPasswordHash))
                                        .doOnSuccess(v -> log.info("Password reset successfully for: {}", normalizedEmail));
                            });
                });
    }

    private Mono<Void> sendVerificationEmail(User user) {
        String token = UUID.randomUUID().toString();
        String tokenKey = VERIFICATION_TOKEN_PREFIX + token;
        String userKey = VERIFICATION_USER_PREFIX + user.getId().toString();
        Duration ttl = Duration.ofSeconds(authProperties.getVerificationTokenExpiration());

        return redisTemplate.opsForValue().get(userKey)
                .flatMap(oldToken -> redisTemplate.delete(VERIFICATION_TOKEN_PREFIX + oldToken))
                .then(redisTemplate.opsForValue().set(tokenKey, user.getId().toString(), ttl))
                .then(redisTemplate.opsForValue().set(userKey, token, ttl))
                .then(emailService.sendVerificationEmail(user.getEmail(), token));
    }

    private Mono<Void> sendPasswordResetEmail(User user) {
        String token = UUID.randomUUID().toString();
        String tokenKey = RESET_TOKEN_PREFIX + token;
        String userKey = RESET_USER_PREFIX + user.getId();

        return redisTemplate.opsForValue()
                .set(tokenKey, user.getId().toString(), Duration.ofMinutes(5))
                .then(redisTemplate.opsForValue().set(userKey, token, Duration.ofMinutes(5)))
                .then(emailService.sendPasswordResetEmail(user.getEmail(), token))
                .doOnSuccess(v -> log.info("Password reset email sent to: {}", user.getEmail()));
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

        return redisTemplate.hasKey(lockoutKey)
                .flatMap(locked -> {
                    if (locked) {
                        return Mono.error(new TooManyRequestsException(
                                "Too many failed attempts. Please try again in " +
                                        authProperties.getRateLimit().getLockoutSeconds() + " seconds."));
                    }
                    return Mono.empty();
                });
    }

    private Mono<Void> incrementFailedAttempts(String email) {
        String rateLimitKey = RATE_LIMIT_PREFIX + email;
        Duration window = Duration.ofSeconds(authProperties.getRateLimit().getWindowSeconds());

        return redisTemplate.opsForValue().increment(rateLimitKey)
                .flatMap(count -> {
                    if (count == 1) {
                        return redisTemplate.expire(rateLimitKey, window).thenReturn(count);
                    }
                    return Mono.just(count);
                })
                .flatMap(count -> {
                    if (count >= authProperties.getRateLimit().getMaxAttempts()) {
                        String lockoutKey = LOCKOUT_PREFIX + email;
                        Duration lockout = Duration.ofSeconds(authProperties.getRateLimit().getLockoutSeconds());
                        return redisTemplate.opsForValue().set(lockoutKey, "1", lockout)
                                .then(redisTemplate.delete(rateLimitKey))
                                .then();
                    }
                    return Mono.empty();
                });
    }

    private Mono<Void> clearRateLimit(String email) {
        String rateLimitKey = RATE_LIMIT_PREFIX + email;
        return redisTemplate.delete(rateLimitKey).then();
    }
}