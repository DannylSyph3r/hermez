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

    Mono<Long> countByUserIdAndStartedAtAfter(UUID userId, Instant since);

    @Query("SELECT COUNT(*) FROM request_logs WHERE user_id = :userId AND started_at >= :from AND started_at < :to")
    Mono<Long> countByUserIdAndStartedAtBetween(UUID userId, Instant from, Instant to);

    Mono<RequestLog> findByIdAndTunnelIdAndUserId(UUID id, String tunnelId, UUID userId);

    @Query("INSERT INTO request_logs (tunnel_id, user_id, request_id, method, path, query_string, " +
            "request_headers, request_body, request_body_truncated, request_size, client_ip, " +
            "status_code, response_headers, response_body, response_body_truncated, response_size, " +
            "started_at, completed_at, duration_ms, status, error_message, parent_request_id, log_detail) " +
            "VALUES (:tunnelId, :userId, :requestId, :method, :path, :queryString, " +
            "CAST(:requestHeaders AS jsonb), :requestBody, :requestBodyTruncated, :requestSize, :clientIp, " +
            ":statusCode, CAST(:responseHeaders AS jsonb), :responseBody, :responseBodyTruncated, :responseSize, " +
            ":startedAt, :completedAt, :durationMs, :status, :errorMessage, :parentRequestId, :logDetail) " +
            "RETURNING *")
    Mono<RequestLog> insertLog(String tunnelId, UUID userId, String requestId, String method, String path,
                               String queryString, String requestHeaders, byte[] requestBody,
                               boolean requestBodyTruncated, int requestSize, String clientIp,
                               Integer statusCode, String responseHeaders, byte[] responseBody,
                               boolean responseBodyTruncated, Integer responseSize,
                               Instant startedAt, Instant completedAt, Integer durationMs,
                               String status, String errorMessage, UUID parentRequestId, String logDetail);

    @Modifying
    @Query("DELETE FROM request_logs WHERE tunnel_id = :tunnelId AND user_id = :userId")
    Mono<Void> deleteByTunnelIdAndUserId(String tunnelId, UUID userId);

    @Modifying
    @Query("DELETE FROM request_logs WHERE id = :requestId AND tunnel_id = :tunnelId AND user_id = :userId")
    Mono<Void> deleteByIdAndTunnelIdAndUserId(UUID requestId, String tunnelId, UUID userId);

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