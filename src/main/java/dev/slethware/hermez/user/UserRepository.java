package dev.slethware.hermez.user;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.UUID;

@Repository
public interface UserRepository extends ReactiveCrudRepository<User, UUID> {

    Mono<User> findByEmail(String email);

    Mono<Boolean> existsByEmail(String email);

    @Query("SELECT * FROM users WHERE id = :id FOR UPDATE")
    Mono<User> findByIdForUpdate(UUID id);

    @Modifying
    @Query("UPDATE users SET last_login_at = :lastLoginAt WHERE id = :id")
    Mono<Void> updateLastLoginAt(UUID id, LocalDateTime lastLoginAt);

    @Modifying
    @Query("UPDATE users SET email_verified = true WHERE id = :id")
    Mono<Void> verifyEmail(UUID id);
}