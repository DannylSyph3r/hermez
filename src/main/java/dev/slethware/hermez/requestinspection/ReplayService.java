package dev.slethware.hermez.requestinspection;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.slethware.hermez.config.HermezConfigProperties;
import dev.slethware.hermez.exception.BadRequestException;
import dev.slethware.hermez.exception.ConflictException;
import dev.slethware.hermez.exception.ForbiddenException;
import dev.slethware.hermez.exception.ResourceNotFoundException;
import dev.slethware.hermez.requestinspection.api.RequestLogResponse;
import dev.slethware.hermez.tunnel.TunnelLookupResult;
import dev.slethware.hermez.tunnel.TunnelRegistry;
import dev.slethware.hermez.tunnel.protocol.HttpRequestMessage;
import dev.slethware.hermez.user.SubscriptionTier;
import dev.slethware.hermez.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class ReplayService {

    private final RequestLogRepository   requestLogRepository;
    private final TunnelRegistry         tunnelRegistry;
    private final UserRepository         userRepository;
    private final ObjectMapper           objectMapper;
    private final HermezConfigProperties config;

    public Mono<RequestLogResponse> replay(UUID userId, String tunnelId, UUID requestId) {
        return requestLogRepository.findByIdAndTunnelIdAndUserId(requestId, tunnelId, userId)
                .switchIfEmpty(Mono.error(new ResourceNotFoundException("Request log not found")))
                .flatMap(originalLog -> {
                    if (!LogStatus.COMPLETED.value().equals(originalLog.getStatus())) {
                        return Mono.error(new BadRequestException("Cannot replay a request that has not completed"));
                    }
                    if (!SubscriptionTier.LogDetail.FULL.name().toLowerCase().equals(originalLog.getLogDetail())) {
                        return Mono.error(new BadRequestException("Cannot replay a request captured without full detail"));
                    }

                    return userRepository.findById(userId)
                            .switchIfEmpty(Mono.error(new ResourceNotFoundException("User not found")))
                            .flatMap(user -> {
                                SubscriptionTier tier = SubscriptionTier.fromValue(user.getTier());
                                if (!tier.canReplay()) {
                                    return Mono.error(new ForbiddenException("Replay requires Petasos or Talaria"));
                                }
                                return tunnelRegistry.lookup(tunnelId);
                            })
                            .flatMap(result -> {
                                if (!(result instanceof TunnelLookupResult.Local(
                                        dev.slethware.hermez.tunnel.TunnelConnection connection
                                ))) {
                                    return Mono.error(new ConflictException("Tunnel must be connected to replay requests"));
                                }

                                Map<String, String> headers = deserializeHeaders(originalLog.getRequestHeaders(), originalLog.getId());
                                byte[] replayBody = originalLog.getRequestBody() != null ? originalLog.getRequestBody() : new byte[0];
                                String replayPath = originalLog.getQueryString() != null
                                        ? originalLog.getPath() + "?" + originalLog.getQueryString()
                                        : originalLog.getPath();

                                UUID replayRequestId = UUID.randomUUID();
                                HttpRequestMessage replayMessage = new HttpRequestMessage(
                                        replayRequestId,
                                        originalLog.getMethod(),
                                        replayPath,
                                        headers,
                                        replayBody
                                );

                                Instant startedAt = Instant.now();

                                return connection.sendRequest(replayMessage)
                                        .timeout(config.getTunnel().getRequestTimeout())
                                        .flatMap(tunnelResponse -> {
                                            Instant completedAt = Instant.now();
                                            int durationMs = (int) (completedAt.toEpochMilli() - startedAt.toEpochMilli());
                                            int bodyCap = config.getInspection().getMaxBodySizeBytes();

                                            byte[] responseBody = tunnelResponse.body();
                                            boolean truncated = false;
                                            Integer responseSize = responseBody != null ? responseBody.length : null;

                                            if (responseBody != null && responseBody.length > bodyCap) {
                                                responseBody = Arrays.copyOf(responseBody, bodyCap);
                                                truncated = true;
                                            }

                                            String responseHeadersJson = null;
                                            if (tunnelResponse.headers() != null && !tunnelResponse.headers().isEmpty()) {
                                                try {
                                                    responseHeadersJson = objectMapper.writeValueAsString(tunnelResponse.headers());
                                                } catch (JsonProcessingException e) {
                                                    log.warn("Failed to serialize replay response headers for parentLogId={}: {}",
                                                            originalLog.getId(), e.getMessage());
                                                }
                                            }

                                            RequestLog replayLog = RequestLog.builder()
                                                    .tunnelId(originalLog.getTunnelId())
                                                    .userId(originalLog.getUserId())
                                                    .requestId(replayRequestId.toString())
                                                    .method(originalLog.getMethod())
                                                    .path(originalLog.getPath())
                                                    .queryString(originalLog.getQueryString())
                                                    .requestHeaders(originalLog.getRequestHeaders())
                                                    .requestBody(originalLog.getRequestBody())
                                                    .requestBodyTruncated(originalLog.isRequestBodyTruncated())
                                                    .requestSize(originalLog.getRequestSize())
                                                    .clientIp(originalLog.getClientIp())
                                                    .startedAt(startedAt)
                                                    .completedAt(completedAt)
                                                    .durationMs(durationMs)
                                                    .status(LogStatus.COMPLETED.value())
                                                    .statusCode(tunnelResponse.statusCode())
                                                    .responseHeaders(responseHeadersJson)
                                                    .responseBody(responseBody)
                                                    .responseBodyTruncated(truncated)
                                                    .responseSize(responseSize)
                                                    .logDetail(SubscriptionTier.LogDetail.FULL.name().toLowerCase())
                                                    .parentRequestId(originalLog.getId())
                                                    .build();

                                            return requestLogRepository.save(replayLog)
                                                    .map(RequestLogResponse::from);
                                        });
                            });
                });
    }

    private Map<String, String> deserializeHeaders(String headersJson, UUID logId) {
        if (headersJson == null) {
            return Collections.emptyMap();
        }
        try {
            return objectMapper.readValue(headersJson, new TypeReference<>() {
            });
        } catch (JsonProcessingException e) {
            log.warn("Failed to deserialize request headers for replay logId={}: {}", logId, e.getMessage());
            return Collections.emptyMap();
        }
    }
}