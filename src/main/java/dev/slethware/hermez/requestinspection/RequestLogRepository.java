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

    // Scheduler — Pass 1: retention cleanup (time-based, per tier)
    @Modifying
    @Query("DELETE FROM request_logs " +
            "WHERE started_at < :cutoff " +
            "AND user_id IN (SELECT id FROM users WHERE tier = :tier)")
    Mono<Integer> deleteByTierAndStartedAtBefore(String tier, Instant cutoff);

    // Scheduler — Pass 2: rolling cap enforcement (count-based, per tier)
    @Modifying
    @Query("DELETE FROM request_logs WHERE id IN (" +
            "SELECT id FROM (" +
            "SELECT id, ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY started_at DESC) AS rn " +
            "FROM request_logs " +
            "WHERE user_id IN (SELECT id FROM users WHERE tier = :tier)" +
            ") ranked WHERE rn > :cap" +
            ")")
    Mono<Integer> deleteExcessByTier(String tier, int cap);
}