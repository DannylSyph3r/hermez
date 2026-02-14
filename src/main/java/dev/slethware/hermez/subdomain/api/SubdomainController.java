package dev.slethware.hermez.subdomain.api;

import dev.slethware.hermez.common.models.response.ApiResponse;
import dev.slethware.hermez.common.util.ApiResponseUtil;
import dev.slethware.hermez.common.util.SecurityContextUtil;
import dev.slethware.hermez.subdomain.SubdomainService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@Slf4j
@RestController
@RequestMapping("/api/v1/subdomains")
@RequiredArgsConstructor
@Tag(name = "Subdomain Management", description = "Subdomain reservation and management endpoints")
public class SubdomainController {

    private final SubdomainService subdomainService;

    @GetMapping
    @Operation(
            summary = "List reserved subdomains",
            description = "Retrieves all subdomains reserved by the authenticated user with their active status and tier limits"
    )
    public Mono<ApiResponse<SubdomainListResponse>> getReservations() {
        return SecurityContextUtil.getCurrentUserId()
                .flatMap(subdomainService::getReservations)
                .map(response -> ApiResponseUtil.successFull("Subdomains retrieved successfully", response));
    }

    @PostMapping
    @Operation(
            summary = "Reserve a subdomain",
            description = "Reserves a new subdomain for the authenticated user. Validates format, blocklist, and tier limits."
    )
    public Mono<ApiResponse<SubdomainResponse>> reserveSubdomain(
            @Valid @RequestBody ReserveSubdomainRequest request
    ) {
        return SecurityContextUtil.getCurrentUserId()
                .flatMap(userId -> subdomainService.reserveSubdomain(request.subdomain(), userId))
                .map(response -> ApiResponseUtil.successFull("Subdomain reserved successfully", response));
    }

    @GetMapping("/{subdomain}")
    @Operation(
            summary = "Get subdomain reservation details",
            description = "Retrieves details of a specific subdomain reservation owned by the authenticated user"
    )
    public Mono<ApiResponse<SubdomainResponse>> getReservation(@PathVariable String subdomain) {
        return SecurityContextUtil.getCurrentUserId()
                .flatMap(userId -> subdomainService.getReservation(subdomain, userId))
                .map(response -> ApiResponseUtil.successFull("Subdomain details retrieved successfully", response));
    }

    @DeleteMapping("/{subdomain}")
    @Operation(
            summary = "Release a subdomain",
            description = "Releases a subdomain reservation. Cannot release if subdomain has an active tunnel."
    )
    public Mono<ApiResponse<Void>> releaseSubdomain(@PathVariable String subdomain) {
        return SecurityContextUtil.getCurrentUserId()
                .flatMap(userId -> subdomainService.releaseSubdomain(subdomain, userId))
                .then(Mono.fromCallable(() -> ApiResponseUtil.successFullVoid("Subdomain released successfully")));
    }

    @GetMapping("/{subdomain}/available")
    @Operation(
            summary = "Check subdomain availability",
            description = "Checks if a subdomain is available for reservation. Returns availability status and reason."
    )
    public Mono<ApiResponse<AvailabilityResponse>> checkAvailability(@PathVariable String subdomain) {
        return SecurityContextUtil.getCurrentUserId()
                .flatMap(userId -> subdomainService.checkAvailability(subdomain, userId))
                .map(response -> ApiResponseUtil.successFull("Availability checked successfully", response));
    }
}