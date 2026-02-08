package dev.slethware.hermez.user;

import dev.slethware.hermez.auth.api.UserResponse;
import dev.slethware.hermez.exception.BadRequestException;
import dev.slethware.hermez.exception.UnauthorizedException;
import dev.slethware.hermez.subdomain.SubdomainReservationRepository;
import dev.slethware.hermez.user.api.ChangePasswordRequest;
import dev.slethware.hermez.user.api.UpdateAvatarRequest;
import dev.slethware.hermez.user.api.UpdateNameRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final SubdomainReservationRepository subdomainReservationRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Mono<UserResponse> getCurrentUser() {
        return getCurrentUserId()
                .flatMap(userId -> userRepository.findById(userId)
                        .switchIfEmpty(Mono.error(new UnauthorizedException("User not found")))
                )
                .flatMap(user -> subdomainReservationRepository.findByUserId(user.getId())
                        .count()
                        .map(count -> UserResponse.from(user, count.intValue()))
                );
    }

    @Override
    public Mono<UserResponse> updateName(UpdateNameRequest request) {
        return getCurrentUserId()
                .flatMap(userId -> userRepository.findById(userId)
                        .switchIfEmpty(Mono.error(new UnauthorizedException("User not found")))
                )
                .flatMap(user -> {
                    user.setName(request.name().trim());
                    return userRepository.save(user);
                })
                .flatMap(savedUser -> subdomainReservationRepository.findByUserId(savedUser.getId())
                        .count()
                        .map(count -> UserResponse.from(savedUser, count.intValue()))
                )
                .doOnSuccess(user -> log.info("User name updated: {}", user.email()));
    }

    @Override
    public Mono<UserResponse> updateAvatar(UpdateAvatarRequest request) {
        return getCurrentUserId()
                .flatMap(userId -> userRepository.findById(userId)
                        .switchIfEmpty(Mono.error(new UnauthorizedException("User not found")))
                )
                .flatMap(user -> {
                    user.setAvatarUrl(request.avatarUrl().trim());
                    return userRepository.save(user);
                })
                .flatMap(savedUser -> subdomainReservationRepository.findByUserId(savedUser.getId())
                        .count()
                        .map(count -> UserResponse.from(savedUser, count.intValue()))
                )
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