package dev.slethware.hermez.auth.api;

import dev.slethware.hermez.user.User;

import java.util.UUID;

public record UserResponse(
        UUID id,
        String email,
        String name,
        String avatarUrl,
        String tier,
        boolean hasPassword,
        Integer activeTunnels,
        Integer reservedSubdomains
) {
    public static UserResponse from(User user, Integer reservedSubdomains) {
        return new UserResponse(
                user.getId(),
                user.getEmail(),
                user.getName(),
                user.getAvatarUrl(),
                user.getTier(),
                user.getPasswordHash() != null,
                0, // Scaffold
                reservedSubdomains
        );
    }
}