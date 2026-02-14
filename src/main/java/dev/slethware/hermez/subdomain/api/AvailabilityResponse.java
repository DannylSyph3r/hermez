package dev.slethware.hermez.subdomain.api;

public record AvailabilityResponse(
        String subdomain,
        boolean available,
        String reason // "available", "reserved_by_you", "reserved_by_other", "currently_active", "blocked", "invalid_format"
) {
}