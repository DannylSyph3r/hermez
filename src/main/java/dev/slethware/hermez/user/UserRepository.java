package dev.slethware.hermez.user;

import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Repository
public interface UserRepository extends ReactiveCrudRepository<User, UUID> {

    Mono<User> findByEmail(String email);

    @Query("SELECT * FROM users WHERE id = :id FOR UPDATE")
    Mono<User> findByIdForUpdate(UUID id);
}