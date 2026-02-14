package dev.slethware.hermez.subdomain.api;

import java.util.List;

public record SubdomainListResponse(
        List<SubdomainResponse> subdomains,
        int total,
        LimitsInfo limits
) {
    public record LimitsInfo(
            int maxReservations,
            int usedReservations
    ) {}
}