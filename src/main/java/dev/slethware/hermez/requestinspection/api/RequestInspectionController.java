package dev.slethware.hermez.requestinspection.api;

import dev.slethware.hermez.common.models.response.ApiResponse;
import dev.slethware.hermez.common.util.ApiResponseUtil;
import dev.slethware.hermez.common.util.SecurityContextUtil;
import dev.slethware.hermez.requestinspection.RequestInspectionService;
import dev.slethware.hermez.requestinspection.ReplayService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/inspection")
@RequiredArgsConstructor
@Tag(name = "Inspection", description = "Request inspection and log management endpoints")
public class RequestInspectionController {

    private static final int MAX_PAGE_SIZE = 100;

    private final RequestInspectionService requestInspectionService;
    private final ReplayService            replayService;

    @GetMapping("/{tunnelId}/requests")
    @Operation(
            summary = "List requests for a tunnel",
            description = "Returns a paginated list of captured requests for the specified tunnel. Maximum page size is 100."
    )
    public Mono<ApiResponse<RequestLogPage>> listRequests(
            @PathVariable String tunnelId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        int clampedSize = Math.min(size, MAX_PAGE_SIZE);
        return SecurityContextUtil.getCurrentUserId()
                .flatMap(userId -> requestInspectionService.listRequests(userId, tunnelId, page, clampedSize))
                .map(result -> ApiResponseUtil.successFull("Requests retrieved successfully", result));
    }

    @GetMapping("/{tunnelId}/requests/{requestId}")
    @Operation(
            summary = "Get request detail",
            description = "Returns the full detail of a single captured request, including base64-encoded body for Petasos+ tier."
    )
    public Mono<ApiResponse<RequestLogResponse>> getRequest(
            @PathVariable String tunnelId,
            @PathVariable UUID requestId) {
        return SecurityContextUtil.getCurrentUserId()
                .flatMap(userId -> requestInspectionService.getRequest(userId, tunnelId, requestId))
                .map(log -> ApiResponseUtil.successFull("Request retrieved successfully", RequestLogResponse.fromDetail(log)));
    }

    @PostMapping("/{tunnelId}/requests/{requestId}/replay")
    @Operation(
            summary = "Replay a captured request",
            description = "Replays a stored request through the active tunnel. Requires Petasos or Talaria tier."
    )
    public Mono<ApiResponse<RequestLogResponse>> replayRequest(
            @PathVariable String tunnelId,
            @PathVariable UUID requestId) {
        return SecurityContextUtil.getCurrentUserId()
                .flatMap(userId -> replayService.replay(userId, tunnelId, requestId))
                .map(result -> ApiResponseUtil.successFull("Request replayed successfully", result));
    }

    @DeleteMapping("/{tunnelId}/requests")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(
            summary = "Clear request logs",
            description = "Deletes all captured request logs for the specified tunnel."
    )
    public Mono<Void> clearLogs(@PathVariable String tunnelId) {
        return SecurityContextUtil.getCurrentUserId()
                .flatMap(userId -> requestInspectionService.clearLogs(userId, tunnelId));
    }
}