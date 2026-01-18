package dev.slethware.hermez.auth.oauth;

import dev.slethware.hermez.auth.config.OAuthProperties;
import dev.slethware.hermez.exception.BadRequestException;
import dev.slethware.hermez.exception.UnauthorizedException;
import dev.slethware.hermez.user.OAuthConnection;
import dev.slethware.hermez.user.OAuthConnectionRepository;
import dev.slethware.hermez.user.User;
import dev.slethware.hermez.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2Handler {

    private final WebClient webClient;
    private final UserRepository userRepository;
    private final OAuthConnectionRepository oauthConnectionRepository;
    private final PasswordEncoder passwordEncoder;
    private final OAuthProperties oauthProperties;

    private static final ParameterizedTypeReference<Map<String, Object>> MAP_TYPE_REFERENCE =
            new ParameterizedTypeReference<>() {};

    public Mono<User> handleGoogleCallback(String code) {
        log.info("Processing Google OAuth callback");

        return exchangeCodeForToken(
                code,
                oauthProperties.getGoogle().getTokenUri(),
                oauthProperties.getGoogle().getClientId(),
                oauthProperties.getGoogle().getClientSecret(),
                oauthProperties.getGoogle().getRedirectUri()
        )
                .flatMap(tokenResponse -> fetchGoogleUserInfo(tokenResponse.get("access_token").toString()))
                .flatMap(userInfo -> processOAuthUser("google", userInfo));
    }

    public Mono<User> handleGitHubCallback(String code) {
        log.info("Processing GitHub OAuth callback");

        return exchangeCodeForToken(
                code,
                oauthProperties.getGithub().getTokenUri(),
                oauthProperties.getGithub().getClientId(),
                oauthProperties.getGithub().getClientSecret(),
                oauthProperties.getGithub().getRedirectUri()
        )
                .flatMap(tokenResponse -> fetchGitHubUserInfo(tokenResponse.get("access_token").toString()))
                .flatMap(userInfo -> processOAuthUser("github", userInfo));
    }

    private Mono<Map<String, Object>> exchangeCodeForToken(String code, String tokenUri, String clientId, String clientSecret, String redirectUri) {
        return webClient.post()
                .uri(tokenUri)
                .header("Accept", "application/json")
                .bodyValue(Map.of(
                        "code", code,
                        "client_id", clientId,
                        "client_secret", clientSecret,
                        "redirect_uri", redirectUri,
                        "grant_type", "authorization_code"
                ))
                .retrieve()
                .bodyToMono(MAP_TYPE_REFERENCE)
                .onErrorMap(e -> {
                    log.error("Failed to exchange code for token: {}", e.getMessage());
                    return new UnauthorizedException("Failed to authenticate with OAuth provider");
                });
    }

    private Mono<Map<String, Object>> fetchGoogleUserInfo(String accessToken) {
        return webClient.get()
                .uri(oauthProperties.getGoogle().getUserInfoUri())
                .header("Authorization", "Bearer " + accessToken)
                .retrieve()
                .bodyToMono(MAP_TYPE_REFERENCE)
                .onErrorMap(e -> {
                    log.error("Failed to fetch Google user info: {}", e.getMessage());
                    return new UnauthorizedException("Failed to fetch user information from Google");
                });
    }

    private Mono<Map<String, Object>> fetchGitHubUserInfo(String accessToken) {
        return webClient.get()
                .uri(oauthProperties.getGithub().getUserInfoUri())
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/vnd.github.v3+json")
                .retrieve()
                .bodyToMono(MAP_TYPE_REFERENCE)
                .flatMap(userInfo -> {
                    // Check if email is present and not null
                    Object emailObj = userInfo.get("email");
                    if (emailObj == null) {
                        log.warn("GitHub user info does not contain email");
                        return Mono.error(new BadRequestException(
                                "Unable to retrieve email from GitHub. Please ensure your primary email is public in your GitHub settings."));
                    }
                    return Mono.just(userInfo);
                })
                .onErrorMap(e -> {
                    if (e instanceof BadRequestException) {
                        return e;
                    }
                    log.error("Failed to fetch GitHub user info: {}", e.getMessage());
                    return new UnauthorizedException("Failed to fetch user information from GitHub");
                });
    }

    private Mono<User> processOAuthUser(String provider, Map<String, Object> userInfo) {
        String providerId = userInfo.get("id").toString();
        String email = normalizeEmail(userInfo.get("email").toString());
        String name = extractName(provider, userInfo);

        log.info("Processing OAuth user - Provider: {}, Email: {}", provider, email);

        // Check if OAuth connection already exists
        return oauthConnectionRepository.findByProviderAndProviderId(provider, providerId)
                .flatMap(existingConnection -> {
                    // OAuth connection exists, fetch the associated user
                    log.info("Found existing OAuth connection for provider: {}", provider);
                    return userRepository.findById(existingConnection.getUserId())
                            .flatMap(user -> updateLastLogin(user)
                                    .then(Mono.just(user)));
                })
                .switchIfEmpty(Mono.defer(() ->
                        // No OAuth connection, check if user exists by email
                        userRepository.findByEmail(email)
                                .flatMap(existingUser -> {
                                    // User exists with this email, link OAuth account
                                    log.info("Linking OAuth account to existing user: {}", email);
                                    return createOAuthConnection(existingUser.getId(), provider, providerId)
                                            .then(updateLastLogin(existingUser))
                                            .thenReturn(existingUser);
                                })
                                .switchIfEmpty(Mono.defer(() -> {
                                    // New user, create user and OAuth connection
                                    log.info("Creating new user from OAuth: {}", email);
                                    return createNewOAuthUser(email, name)
                                            .flatMap(newUser -> createOAuthConnection(newUser.getId(), provider, providerId)
                                                    .thenReturn(newUser));
                                }))
                ));
    }

    private Mono<User> createNewOAuthUser(String email, String name) {
        User user = User.builder()
                .email(email)
                .name(name)
                .passwordHash(passwordEncoder.encode(UUID.randomUUID().toString())) // Random password for OAuth-only users
                .tier("free")
                .emailVerified(true) // OAuth emails are pre-verified by the provider
                .createdAt(LocalDateTime.now())
                .lastLoginAt(LocalDateTime.now())
                .build();

        return userRepository.save(user);
    }

    private Mono<OAuthConnection> createOAuthConnection(UUID userId, String provider, String providerId) {
        OAuthConnection connection = OAuthConnection.builder()
                .userId(userId)
                .provider(provider)
                .providerId(providerId)
                .createdAt(LocalDateTime.now())
                .build();

        return oauthConnectionRepository.save(connection);
    }

    private Mono<Void> updateLastLogin(User user) {
        return userRepository.updateLastLoginAt(user.getId(), LocalDateTime.now());
    }

    private String normalizeEmail(String email) {
        return email.toLowerCase().trim();
    }

    private String extractName(String provider, Map<String, Object> userInfo) {
        return switch (provider) {
            case "google" -> userInfo.get("name").toString();
            case "github" -> {
                Object name = userInfo.get("name");
                yield name != null ? name.toString() : userInfo.get("login").toString();
            }
            default -> "User";
        };
    }
}