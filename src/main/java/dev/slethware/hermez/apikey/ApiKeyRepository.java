package dev.slethware.hermez.apikey;

import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface ApiKeyRepository extends ReactiveCrudRepository<ApiKey, UUID> {

    Mono<ApiKey> findByKeyHash(String keyHash);
    Mono<Boolean> existsByUserIdAndNameAndRevokedAtIsNull(UUID userId, String name);
    Flux<ApiKey> findByUserIdAndRevokedAtIsNull(UUID userId);
    Mono<Long> countByUserIdAndRevokedAtIsNull(UUID userId);
}