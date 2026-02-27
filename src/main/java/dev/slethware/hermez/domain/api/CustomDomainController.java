package dev.slethware.hermez.domain.api;

import dev.slethware.hermez.common.models.response.ApiResponse;
import dev.slethware.hermez.common.util.ApiResponseUtil;
import dev.slethware.hermez.common.util.SecurityContextUtil;
import dev.slethware.hermez.config.HermezConfigProperties;
import dev.slethware.hermez.domain.CustomDomain;
import dev.slethware.hermez.domain.CustomDomainService;
import dev.slethware.hermez.domain.DomainVerificationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/v1/domains")
@RequiredArgsConstructor
@Tag(name = "Custom Domains", description = "BYOD custom domain management endpoints")
public class CustomDomainController {

    private final CustomDomainService domainService;
    private final DomainVerificationService verificationService;
    private final HermezConfigProperties configProperties;

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(
            summary = "Register a custom domain",
            description = "Registers a custom domain linked to a reserved subdomain. Returns DNS instructions for verification."
    )
    public Mono<ApiResponse<CustomDomainResponse>> registerDomain(
            @Valid @RequestBody CustomDomainRequest request
    ) {
        return SecurityContextUtil.getCurrentUserId()
                .flatMap(userId -> domainService.registerDomain(userId, request.domain(), request.linkedSubdomain()))
                .map(domain -> ApiResponseUtil.created("Domain registered successfully", toResponse(domain)));
    }

    @GetMapping
    @Operation(
            summary = "List custom domains",
            description = "Returns all custom domains registered by the authenticated user."
    )
    public Mono<ApiResponse<List<CustomDomainResponse>>> listDomains() {
        return SecurityContextUtil.getCurrentUserId()
                .flatMapMany(domainService::listDomains)
                .map(this::toResponse)
                .collectList()
                .map(domains -> ApiResponseUtil.successFull("Domains retrieved successfully", domains));
    }

    @PostMapping("/{domainId}/verify")
    @Operation(
            summary = "Verify domain ownership",
            description = "Triggers a DNS TXT record check. Domain moves to ACTIVE on success, stays PENDING if DNS is not yet propagated."
    )
    public Mono<ApiResponse<CustomDomainResponse>> verifyDomain(@PathVariable UUID domainId) {
        return SecurityContextUtil.getCurrentUserId()
                .flatMap(userId -> domainService.verifyDomain(userId, domainId))
                .map(domain -> ApiResponseUtil.successFull("Domain verification attempted", toResponse(domain)));
    }

    @DeleteMapping("/{domainId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(
            summary = "Delete a custom domain",
            description = "Permanently removes a custom domain. Cache is evicted immediately."
    )
    public Mono<Void> deleteDomain(@PathVariable UUID domainId) {
        return SecurityContextUtil.getCurrentUserId()
                .flatMap(userId -> domainService.deleteDomain(userId, domainId));
    }

    private CustomDomainResponse toResponse(CustomDomain domain) {
        return CustomDomainResponse.from(
                domain,
                verificationService.buildTxtRecordName(domain.getDomain()),
                verificationService.buildExpectedTxtValue(domain.getVerificationToken()),
                configProperties.getDomain().getIngressDomain()
        );
    }
}