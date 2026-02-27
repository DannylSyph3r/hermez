package dev.slethware.hermez.requestinspection;

import org.springframework.data.domain.Pageable;
import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

@Repository
public interface RequestLogRepository extends ReactiveCrudRepository<RequestLog, UUID> {

    Flux<RequestLog> findByTunnelIdOrderByStartedAtDesc(String tunnelId, Pageable pageable);

    Mono<RequestLog> findByIdAndUserId(UUID id, UUID userId);

    @Modifying
    @Query("DELETE FROM request_logs WHERE user_id = :userId AND started_at < :cutoff")
    Mono<Void> deleteByUserIdAndStartedAtBefore(UUID userId, Instant cutoff);

    Mono<Long> countByUserId(UUID userId);

    @Query("SELECT id FROM request_logs WHERE user_id = :userId ORDER BY started_at ASC LIMIT :limit")
    Flux<UUID> findOldestIdsByUserId(UUID userId, int limit);

    @Modifying
    @Query("DELETE FROM request_logs WHERE user_id = :userId AND id IN (SELECT id FROM request_logs WHERE user_id = :userId ORDER BY started_at ASC LIMIT :limit)")
    Mono<Void> deleteOldestByUserId(UUID userId, int limit);

    @Modifying
    @Query("DELETE FROM request_logs WHERE tunnel_id = :tunnelId AND user_id = :userId")
    Mono<Void> deleteByTunnelIdAndUserId(String tunnelId, UUID userId);
}