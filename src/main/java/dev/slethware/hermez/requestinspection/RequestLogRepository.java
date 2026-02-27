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

    Flux<RequestLog> findByTunnelIdAndUserIdOrderByStartedAtDesc(String tunnelId, UUID userId, Pageable pageable);

    Mono<Long> countByTunnelIdAndUserId(String tunnelId, UUID userId);

    Mono<RequestLog> findByIdAndTunnelIdAndUserId(UUID id, String tunnelId, UUID userId);

    Mono<Long> countByUserId(UUID userId);

    @Modifying
    @Query("DELETE FROM request_logs WHERE user_id = :userId AND started_at < :cutoff")
    Mono<Void> deleteByUserIdAndStartedAtBefore(UUID userId, Instant cutoff);

    @Modifying
    @Query("DELETE FROM request_logs WHERE user_id = :userId AND id IN " +
            "(SELECT id FROM request_logs WHERE user_id = :userId ORDER BY started_at ASC LIMIT :limit)")
    Mono<Void> deleteOldestByUserId(UUID userId, int limit);

    @Modifying
    @Query("DELETE FROM request_logs WHERE tunnel_id = :tunnelId AND user_id = :userId")
    Mono<Void> deleteByTunnelIdAndUserId(String tunnelId, UUID userId);

    @Modifying
    @Query("UPDATE request_logs SET status = 'completed', status_code = :statusCode, " +
            "response_headers = CAST(:responseHeaders AS jsonb), response_body = :responseBody, " +
            "response_body_truncated = :truncated, response_size = :responseSize, " +
            "completed_at = :completedAt, duration_ms = :durationMs WHERE id = :logId")
    Mono<Void> updateCompleted(UUID logId, int statusCode, String responseHeaders,
                               byte[] responseBody, boolean truncated, Integer responseSize,
                               Instant completedAt, int durationMs);

    @Modifying
    @Query("UPDATE request_logs SET status = :status, error_message = :errorMessage, " +
            "completed_at = :completedAt WHERE id = :logId")
    Mono<Void> updateFailed(UUID logId, String status, String errorMessage, Instant completedAt);
}