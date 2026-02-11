package dev.slethware.hermez.user;

import dev.slethware.hermez.exception.BadRequestException;
import dev.slethware.hermez.exception.UnauthorizedException;
import dev.slethware.hermez.subdomain.SubdomainReservationRepository;
import dev.slethware.hermez.user.api.ChangePasswordRequest;
import dev.slethware.hermez.user.api.UpdateAvatarRequest;
import dev.slethware.hermez.user.api.UpdateNameRequest;
import dev.slethware.hermez.user.api.UserProfileResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final OAuthConnectionRepository oauthConnectionRepository;
    private final SubdomainReservationRepository subdomainReservationRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Mono<UserProfileResponse> getCurrentUser() {
        return getCurrentUserId()
                .flatMap(userId -> userRepository.findById(userId)
                        .switchIfEmpty(Mono.error(new UnauthorizedException("User not found")))
                )
                .flatMap(user -> Mono.zip(
                        subdomainReservationRepository.findByUserId(user.getId()).count(),
                        oauthConnectionRepository.findByUserId(user.getId()).collectList()
                ).map(tuple -> UserProfileResponse.from(user, tuple.getT1().intValue(), tuple.getT2())));
    }

    @Override
    public Mono<UserProfileResponse> updateName(UpdateNameRequest request) {
        return getCurrentUserId()
                .flatMap(userId -> userRepository.findById(userId)
                        .switchIfEmpty(Mono.error(new UnauthorizedException("User not found")))
                )
                .flatMap(user -> {
                    user.setName(request.name().trim());
                    return userRepository.save(user);
                })
                .flatMap(savedUser -> Mono.zip(
                        subdomainReservationRepository.findByUserId(savedUser.getId()).count(),
                        oauthConnectionRepository.findByUserId(savedUser.getId()).collectList()
                ).map(tuple -> UserProfileResponse.from(savedUser, tuple.getT1().intValue(), tuple.getT2())))
                .doOnSuccess(user -> log.info("User name updated: {}", user.email()));
    }

    @Override
    public Mono<UserProfileResponse> updateAvatar(UpdateAvatarRequest request) {
        return getCurrentUserId()
                .flatMap(userId -> userRepository.findById(userId)
                        .switchIfEmpty(Mono.error(new UnauthorizedException("User not found")))
                )
                .flatMap(user -> {
                    user.setAvatarUrl(request.avatarUrl().trim());
                    return userRepository.save(user);
                })
                .flatMap(savedUser -> Mono.zip(
                        subdomainReservationRepository.findByUserId(savedUser.getId()).count(),
                        oauthConnectionRepository.findByUserId(savedUser.getId()).collectList()
                ).map(tuple -> UserProfileResponse.from(savedUser, tuple.getT1().intValue(), tuple.getT2())))
                .doOnSuccess(user -> log.info("User avatar updated: {}", user.email()));
    }

    @Override
    public Mono<Void> changePassword(ChangePasswordRequest request) {
        return getCurrentUserId()
                .flatMap(userId -> userRepository.findById(userId)
                        .switchIfEmpty(Mono.error(new UnauthorizedException("User not found")))
                )
                .flatMap(user -> {
                    // Check if user has a password (not OAuth-only)
                    if (user.getPasswordHash() == null) {
                        return Mono.error(new BadRequestException(
                                "Cannot change password for OAuth-only accounts"
                        ));
                    }

                    // Validate current password
                    if (!passwordEncoder.matches(request.currentPassword(), user.getPasswordHash())) {
                        return Mono.error(new BadRequestException("Current password is incorrect"));
                    }

                    // Validate new password matches confirmation
                    if (!request.newPassword().equals(request.confirmPassword())) {
                        return Mono.error(new BadRequestException(
                                "New password and confirmation do not match"
                        ));
                    }

                    // Validate new password is different from current
                    if (passwordEncoder.matches(request.newPassword(), user.getPasswordHash())) {
                        return Mono.error(new BadRequestException(
                                "New password must be different from current password"
                        ));
                    }

                    // Update password
                    String newPasswordHash = passwordEncoder.encode(request.newPassword());
                    return userRepository.updatePassword(user.getId(), newPasswordHash);
                })
                .doOnSuccess(v -> log.info("Password changed successfully"))
                .then();
    }

    @Override
    public Mono<Void> disconnectOAuth(String provider) {
        // Validate provider
        if (!provider.equals("google") && !provider.equals("github")) {
            return Mono.error(new BadRequestException("Invalid provider. Must be 'google' or 'github'."));
        }

        return getCurrentUserId()
                .flatMap(userId -> {
                    log.info("Attempting to disconnect {} OAuth for user: {}", provider, userId);

                    // Get user and their OAuth connections
                    return Mono.zip(
                            userRepository.findById(userId),
                            oauthConnectionRepository.findByUserId(userId).collectList()
                    ).flatMap(tuple -> {
                        User user = tuple.getT1();
                        List<OAuthConnection> connections = tuple.getT2();

                        // Check if user has at least one other auth method
                        boolean hasPassword = user.getPasswordHash() != null && !user.getPasswordHash().isEmpty();
                        long connectionCount = connections.size();

                        // User must have password OR another OAuth connection
                        if (!hasPassword && connectionCount <= 1) {
                            log.warn("User {} attempted to disconnect only auth method: {}", userId, provider);
                            return Mono.error(new BadRequestException(
                                    "Cannot disconnect your only authentication method. " +
                                            "Please add a password or connect another account first."
                            ));
                        }

                        // Find and delete the specific connection (idempotent)
                        Mono<OAuthConnection> connectionMono = oauthConnectionRepository
                                .findByUserIdAndProvider(userId, provider)
                                .cache();

                        return connectionMono.hasElement()
                                .flatMap(exists -> {
                                    if (exists) {
                                        log.info("Disconnecting {} OAuth for user: {}", provider, userId);
                                        return connectionMono.flatMap(oauthConnectionRepository::delete);
                                    } else {
                                        log.debug("No {} connection found for user {}, treating as success (idempotent)", provider, userId);
                                        return Mono.empty();
                                    }
                                });
                    });
                });
    }

    @Override
    public Mono<Void> deleteAccount() {
        return getCurrentUserId()
                .flatMap(userId -> userRepository.findById(userId)
                        .switchIfEmpty(Mono.error(new UnauthorizedException("User not found")))
                )
                .flatMap(user -> {
                    user.setDeletedAt(LocalDateTime.now());
                    return userRepository.save(user);
                })
                .doOnSuccess(user -> log.info("User account soft deleted: {}", user.getEmail()))
                .then();
    }

    private Mono<UUID> getCurrentUserId() {
        return ReactiveSecurityContextHolder.getContext()
                .map(securityContext -> securityContext.getAuthentication().getName())
                .map(UUID::fromString)
                .switchIfEmpty(Mono.error(new UnauthorizedException("Not authenticated")));
    }
}