package dev.slethware.hermez.user;

import dev.slethware.hermez.common.util.SecurityContextUtil;
import dev.slethware.hermez.exception.BadRequestException;
import dev.slethware.hermez.exception.UnauthorizedException;
import dev.slethware.hermez.requestinspection.RequestLogRepository;
import dev.slethware.hermez.subdomain.SubdomainReservationRepository;
import dev.slethware.hermez.tunnel.TunnelRegistry;
import dev.slethware.hermez.user.api.ChangePasswordRequest;
import dev.slethware.hermez.user.api.UpdateAvatarRequest;
import dev.slethware.hermez.user.api.UpdateNameRequest;
import dev.slethware.hermez.user.api.UserProfileResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final OAuthConnectionRepository oauthConnectionRepository;
    private final SubdomainReservationRepository subdomainReservationRepository;
    private final TunnelRegistry tunnelRegistry;
    private final RequestLogRepository requestLogRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Mono<UserProfileResponse> getCurrentUser() {
        return SecurityContextUtil.getCurrentUserId()
                .flatMap(userId -> userRepository.findById(userId)
                        .switchIfEmpty(Mono.error(new UnauthorizedException("User not found")))
                )
                .flatMap(this::buildProfileResponse);
    }

    @Override
    public Mono<UserProfileResponse> updateName(UpdateNameRequest request) {
        return SecurityContextUtil.getCurrentUserId()
                .flatMap(userId -> userRepository.findById(userId)
                        .switchIfEmpty(Mono.error(new UnauthorizedException("User not found")))
                )
                .flatMap(user -> {
                    user.setName(request.name().trim());
                    return userRepository.save(user);
                })
                .flatMap(this::buildProfileResponse)
                .doOnSuccess(user -> log.info("User name updated: {}", user.email()));
    }

    @Override
    public Mono<UserProfileResponse> updateAvatar(UpdateAvatarRequest request) {
        return SecurityContextUtil.getCurrentUserId()
                .flatMap(userId -> userRepository.findById(userId)
                        .switchIfEmpty(Mono.error(new UnauthorizedException("User not found")))
                )
                .flatMap(user -> {
                    user.setAvatarUrl(request.avatarUrl().trim());
                    return userRepository.save(user);
                })
                .flatMap(this::buildProfileResponse)
                .doOnSuccess(user -> log.info("User avatar updated: {}", user.email()));
    }

    @Override
    public Mono<Void> updateConsent(boolean consent) {
        return SecurityContextUtil.getCurrentUserId()
                .flatMap(userId -> userRepository.findById(userId)
                        .switchIfEmpty(Mono.error(new UnauthorizedException("User not found")))
                )
                .flatMap(user -> {
                    user.setDataConsent(consent);
                    return userRepository.save(user);
                })
                .doOnSuccess(user -> log.info("Data consent updated to {} for user: {}", consent, user.getEmail()))
                .then();
    }

    @Override
    public Mono<Void> changePassword(ChangePasswordRequest request) {
        return SecurityContextUtil.getCurrentUserId()
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

        return SecurityContextUtil.getCurrentUserId()
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
        return SecurityContextUtil.getCurrentUserId()
                .flatMap(userId -> userRepository.findById(userId)
                        .switchIfEmpty(Mono.error(new UnauthorizedException("User not found")))
                )
                .flatMap(user -> {
                    user.setDeletedAt(Instant.now());
                    return userRepository.save(user);
                })
                .doOnSuccess(user -> log.info("User account soft deleted: {}", user.getEmail()))
                .then();
    }

    private Mono<UserProfileResponse> buildProfileResponse(User user) {
        Instant startOfToday = LocalDate.now(ZoneOffset.UTC).atStartOfDay(ZoneOffset.UTC).toInstant();
        Instant startOfYesterday = startOfToday.minus(Duration.ofDays(1));

        return Mono.zip(
                subdomainReservationRepository.countByUserId(user.getId()),
                tunnelRegistry.listByUser(user.getId()).count(),
                requestLogRepository.countByUserIdAndStartedAtAfter(user.getId(), startOfToday),
                requestLogRepository.countByUserIdAndStartedAtBetween(user.getId(), startOfYesterday, startOfToday),
                oauthConnectionRepository.findByUserId(user.getId()).collectList()
        ).map(tuple -> UserProfileResponse.from(
                user,
                tuple.getT1().intValue(),
                tuple.getT2().intValue(),
                tuple.getT3().intValue(),
                tuple.getT4().intValue(),
                tuple.getT5()
        ));
    }
}