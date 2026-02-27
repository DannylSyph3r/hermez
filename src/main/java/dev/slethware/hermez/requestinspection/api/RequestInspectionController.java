package dev.slethware.hermez.requestinspection.api;

import dev.slethware.hermez.common.models.response.ApiResponse;
import dev.slethware.hermez.common.util.ApiResponseUtil;
import dev.slethware.hermez.common.util.SecurityContextUtil;
import dev.slethware.hermez.requestinspection.RequestInspectionService;
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

    private final RequestInspectionService requestInspectionService;

    @GetMapping("/{tunnelId}/requests")
    @Operation(
            summary = "List requests for a tunnel",
            description = "Returns a paginated list of captured requests for the specified tunnel."
    )
    public Mono<ApiResponse<RequestLogPage>> listRequests(
            @PathVariable String tunnelId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        return SecurityContextUtil.getCurrentUserId()
                .flatMap(userId -> requestInspectionService.listRequests(userId, tunnelId, page, size))
                .map(result -> ApiResponseUtil.successFull("Requests retrieved successfully", result));
    }

    @GetMapping("/{tunnelId}/requests/{requestId}")
    @Operation(
            summary = "Get request detail",
            description = "Returns the full detail of a single captured request."
    )
    public Mono<ApiResponse<RequestLogResponse>> getRequest(
            @PathVariable String tunnelId,
            @PathVariable UUID requestId) {
        return SecurityContextUtil.getCurrentUserId()
                .flatMap(userId -> requestInspectionService.getRequest(userId, tunnelId, requestId))
                .map(log -> ApiResponseUtil.successFull("Request retrieved successfully", RequestLogResponse.from(log)));
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