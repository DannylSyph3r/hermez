package dev.slethware.hermez.subdomain;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Repository
public interface SubdomainReservationRepository extends ReactiveCrudRepository<SubdomainReservation, UUID> {

    Flux<SubdomainReservation> findByUserId(UUID userId);
    Mono<SubdomainReservation> findBySubdomain(String subdomain);  // ← Add this
    Mono<Boolean> existsBySubdomain(String subdomain);
    @Modifying
    @Query("DELETE FROM subdomain_reservations WHERE expires_at < NOW()")
    Mono<Integer> deleteExpired();
}