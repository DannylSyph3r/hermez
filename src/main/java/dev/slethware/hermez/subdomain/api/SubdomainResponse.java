package dev.slethware.hermez.subdomain.api;

import dev.slethware.hermez.subdomain.SubdomainReservation;

import java.time.LocalDateTime;

public record SubdomainResponse(
        String subdomain,
        String publicUrl,
        LocalDateTime createdAt,
        LocalDateTime expiresAt,
        boolean isActive,
        String tunnelId
) {
    public static SubdomainResponse from(SubdomainReservation reservation, boolean isActive, String tunnelId, String baseDomain) {
        String publicUrl = String.format("https://%s.%s", reservation.getSubdomain(), baseDomain);

        return new SubdomainResponse(
                reservation.getSubdomain(),
                publicUrl,
                reservation.getCreatedAt(),
                reservation.getExpiresAt(),
                isActive,
                tunnelId
        );
    }
}