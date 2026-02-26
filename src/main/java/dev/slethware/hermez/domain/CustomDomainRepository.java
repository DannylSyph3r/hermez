package dev.slethware.hermez.domain;

import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Repository
public interface CustomDomainRepository extends ReactiveCrudRepository<CustomDomain, UUID> {

    Mono<CustomDomain> findByDomain(String domain);
    Flux<CustomDomain> findAllByUserId(UUID userId);
    Mono<CustomDomain> findByUserIdAndDomain(UUID userId, String domain);
    @Query("SELECT COUNT(*) FROM custom_domains WHERE user_id = :userId AND status != :status")
    Mono<Long> countByUserIdAndStatusNot(UUID userId, String status);
}