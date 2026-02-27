package dev.slethware.hermez.requestinspection;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.slethware.hermez.config.HermezConfigProperties;
import dev.slethware.hermez.exception.ResourceNotFoundException;
import dev.slethware.hermez.requestinspection.api.RequestLogPage;
import dev.slethware.hermez.requestinspection.api.RequestLogResponse;
import dev.slethware.hermez.tunnel.protocol.HttpResponseMessage;
import dev.slethware.hermez.user.SubscriptionTier;
import dev.slethware.hermez.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class RequestInspectionService {

    private final RequestLogRepository requestLogRepository;
    private final UserRepository userRepository;
    private final HermezConfigProperties config;
    private final ObjectMapper objectMapper;

    public Mono<UUID> captureRequest(String subdomain, UUID userId, String requestId,
                                     String method, String path, String queryString, String clientIp,
                                     Map<String, String> transformedHeaders, byte[] bodyBytes,
                                     Instant startedAt) {
        return userRepository.findById(userId)
                .map(user -> SubscriptionTier.fromValue(user.getTier()))
                .defaultIfEmpty(SubscriptionTier.CHELYS)
                .flatMap(tier -> {
                    boolean isFull = tier.hasFullLogDetail();
                    int cap = config.getInspection().getMaxBodySizeBytes();

                    byte[] storedBody = null;
                    boolean requestTruncated = false;
                    int requestSize = bodyBytes != null ? bodyBytes.length : 0;

                    if (isFull && bodyBytes != null && bodyBytes.length > 0) {
                        if (bodyBytes.length > cap) {
                            storedBody = Arrays.copyOf(bodyBytes, cap);
                            requestTruncated = true;
                        } else {
                            storedBody = bodyBytes;
                        }
                    }

                    String headersJson = null;
                    if (isFull) {
                        try {
                            headersJson = objectMapper.writeValueAsString(transformedHeaders);
                        } catch (JsonProcessingException e) {
                            log.warn("Failed to serialize request headers for requestId={}: {}", requestId, e.getMessage());
                        }
                    }

                    RequestLog entry = RequestLog.builder()
                            .tunnelId(subdomain)
                            .userId(userId)
                            .requestId(requestId)
                            .method(method)
                            .path(path)
                            .queryString(queryString)
                            .requestHeaders(headersJson)
                            .requestBody(storedBody)
                            .requestBodyTruncated(requestTruncated)
                            .requestSize(requestSize)
                            .clientIp(clientIp)
                            .startedAt(startedAt)
                            .status(LogStatus.PENDING.value())
                            .logDetail(isFull
                                    ? SubscriptionTier.LogDetail.FULL.name().toLowerCase()
                                    : SubscriptionTier.LogDetail.BASIC.name().toLowerCase())
                            .build();

                    return requestLogRepository.save(entry)
                            .map(RequestLog::getId);
                });
    }

    public Mono<Void> completeCapture(UUID logId, HttpResponseMessage tunnelResponse, Instant completedAt) {
        return requestLogRepository.findById(logId)
                .flatMap(existing -> {
                    boolean isFull = SubscriptionTier.LogDetail.FULL.name().toLowerCase()
                            .equals(existing.getLogDetail());
                    int cap = config.getInspection().getMaxBodySizeBytes();

                    byte[] responseBody = tunnelResponse.body();
                    boolean truncated = false;
                    Integer responseSize = responseBody != null ? responseBody.length : null;
                    String responseHeadersJson = null;

                    if (isFull) {
                        if (responseBody != null && responseBody.length > cap) {
                            responseBody = Arrays.copyOf(responseBody, cap);
                            truncated = true;
                        }
                        if (!tunnelResponse.headers().isEmpty()) {
                            try {
                                responseHeadersJson = objectMapper.writeValueAsString(tunnelResponse.headers());
                            } catch (JsonProcessingException e) {
                                log.warn("Failed to serialize response headers for logId={}: {}", logId, e.getMessage());
                            }
                        }
                    } else {
                        responseBody = null;
                    }

                    int durationMs = (int) (completedAt.toEpochMilli() - existing.getStartedAt().toEpochMilli());

                    return requestLogRepository.updateCompleted(
                            logId,
                            tunnelResponse.statusCode(),
                            responseHeadersJson,
                            responseBody,
                            truncated,
                            responseSize,
                            completedAt,
                            durationMs
                    );
                });
    }

    public Mono<Void> failCapture(UUID logId, String errorMessage, LogStatus status, Instant completedAt) {
        return requestLogRepository.updateFailed(logId, status.value(), errorMessage, completedAt);
    }

    public Mono<RequestLogPage> listRequests(UUID userId, String tunnelId, int page, int size) {
        return Mono.zip(
                requestLogRepository.findByTunnelIdAndUserIdOrderByStartedAtDesc(
                                tunnelId, userId, PageRequest.of(page, size))
                        .map(RequestLogResponse::from)
                        .collectList(),
                requestLogRepository.countByTunnelIdAndUserId(tunnelId, userId)
        ).map(tuple -> new RequestLogPage(tuple.getT1(), page, size, tuple.getT2()));
    }

    public Mono<RequestLog> getRequest(UUID userId, String tunnelId, UUID requestId) {
        return requestLogRepository.findByIdAndTunnelIdAndUserId(requestId, tunnelId, userId)
                .switchIfEmpty(Mono.error(new ResourceNotFoundException("Request log not found")));
    }

    public Mono<Void> clearLogs(UUID userId, String tunnelId) {
        return requestLogRepository.deleteByTunnelIdAndUserId(tunnelId, userId);
    }
}