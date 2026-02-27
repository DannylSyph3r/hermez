package dev.slethware.hermez.requestinspection.api;

import dev.slethware.hermez.requestinspection.RequestLog;

import java.time.Instant;
import java.util.UUID;

public record RequestLogResponse(
        UUID id,
        String tunnelId,
        String requestId,
        String method,
        String path,
        String queryString,
        String requestHeaders,
        boolean requestBodyTruncated,
        int requestSize,
        String clientIp,
        Integer statusCode,
        String responseHeaders,
        boolean responseBodyTruncated,
        Integer responseSize,
        Instant startedAt,
        Instant completedAt,
        Integer durationMs,
        String status,
        String errorMessage,
        UUID parentRequestId,
        String logDetail
) {
    public static RequestLogResponse from(RequestLog log) {
        boolean isFull = "full".equals(log.getLogDetail());
        return new RequestLogResponse(
                log.getId(),
                log.getTunnelId(),
                log.getRequestId(),
                log.getMethod(),
                log.getPath(),
                log.getQueryString(),
                isFull ? log.getRequestHeaders() : null,
                log.isRequestBodyTruncated(),
                log.getRequestSize(),
                log.getClientIp(),
                log.getStatusCode(),
                isFull ? log.getResponseHeaders() : null,
                log.isResponseBodyTruncated(),
                log.getResponseSize(),
                log.getStartedAt(),
                log.getCompletedAt(),
                log.getDurationMs(),
                log.getStatus(),
                log.getErrorMessage(),
                log.getParentRequestId(),
                log.getLogDetail()
        );
    }
}