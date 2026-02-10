package dev.slethware.hermez.user.api;

import dev.slethware.hermez.user.OAuthConnection;
import dev.slethware.hermez.user.User;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

public record UserProfileResponse(
        UUID id,
        String email,
        String name,
        String avatarUrl,
        String tier,
        boolean hasPassword,
        Integer reservedSubdomains,
        List<OAuthConnectionInfo> oauthConnections
) {
    public record OAuthConnectionInfo(
            String provider,
            LocalDateTime connectedAt
    ) {
        public static OAuthConnectionInfo from(OAuthConnection connection) {
            return new OAuthConnectionInfo(
                    connection.getProvider(),
                    connection.getCreatedAt()
            );
        }
    }

    public static UserProfileResponse from(User user, Integer reservedSubdomains, List<OAuthConnection> connections) {
        List<OAuthConnectionInfo> oauthInfos = connections.stream()
                .map(OAuthConnectionInfo::from)
                .toList();

        return new UserProfileResponse(
                user.getId(),
                user.getEmail(),
                user.getName(),
                user.getAvatarUrl(),
                user.getTier(),
                user.getPasswordHash() != null,
                reservedSubdomains,
                oauthInfos
        );
    }
}