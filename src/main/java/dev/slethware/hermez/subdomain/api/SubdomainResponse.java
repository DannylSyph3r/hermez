package dev.slethware.hermez.subdomain.api;

import dev.slethware.hermez.subdomain.SubdomainReservation;

import java.time.LocalDateTime;

public record SubdomainResponse(
        String subdomain,
        LocalDateTime createdAt,
        LocalDateTime expiresAt,
        boolean isActive,
        String tunnelId
) {
    public static SubdomainResponse from(SubdomainReservation reservation, boolean isActive, String tunnelId) {
        return new SubdomainResponse(
                reservation.getSubdomain(),
                reservation.getCreatedAt(),
                reservation.getExpiresAt(),
                isActive,
                tunnelId
        );
    }
}