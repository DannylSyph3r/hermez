package dev.slethware.hermez.requestinspection.api;

import dev.slethware.hermez.requestinspection.RequestLog;

import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

public record RequestLogResponse(
        UUID id,
        String tunnelId,
        String requestId,
        String method,
        String path,
        String queryString,
        String requestHeaders,
        String requestBody,
        boolean requestBodyTruncated,
        int requestSize,
        String clientIp,
        Integer statusCode,
        String responseHeaders,
        String responseBody,
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
    // Used for list endpoint — no body bytes
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
                null,
                log.isRequestBodyTruncated(),
                log.getRequestSize(),
                log.getClientIp(),
                log.getStatusCode(),
                isFull ? log.getResponseHeaders() : null,
                null,
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

    // Used for detail and replay endpoints, includes base64-encoded bodies for FULL logs
    public static RequestLogResponse fromDetail(RequestLog log) {
        boolean isFull = "full".equals(log.getLogDetail());
        String requestBodyBase64 = null;
        String responseBodyBase64 = null;
        if (isFull) {
            if (log.getRequestBody() != null) {
                requestBodyBase64 = Base64.getEncoder().encodeToString(log.getRequestBody());
            }
            if (log.getResponseBody() != null) {
                responseBodyBase64 = Base64.getEncoder().encodeToString(log.getResponseBody());
            }
        }
        return new RequestLogResponse(
                log.getId(),
                log.getTunnelId(),
                log.getRequestId(),
                log.getMethod(),
                log.getPath(),
                log.getQueryString(),
                isFull ? log.getRequestHeaders() : null,
                requestBodyBase64,
                log.isRequestBodyTruncated(),
                log.getRequestSize(),
                log.getClientIp(),
                log.getStatusCode(),
                isFull ? log.getResponseHeaders() : null,
                responseBodyBase64,
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