package dev.slethware.hermez.subdomain.api;

import jakarta.validation.constraints.NotBlank;

public record ReserveSubdomainRequest(
        @NotBlank(message = "Subdomain is required")
        String subdomain
) {}