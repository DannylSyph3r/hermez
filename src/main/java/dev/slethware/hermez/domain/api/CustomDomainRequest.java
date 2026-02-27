package dev.slethware.hermez.domain.api;

import jakarta.validation.constraints.NotBlank;

public record CustomDomainRequest(
        @NotBlank(message = "Domain is required")
        String domain,

        @NotBlank(message = "Linked subdomain is required")
        String linkedSubdomain
) {}