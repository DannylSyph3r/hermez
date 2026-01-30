package dev.slethware.hermez.auth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "auth")
public class AuthProperties {

    private Jwt jwt = new Jwt();
    private RateLimit rateLimit = new RateLimit();
    private long verificationTokenExpiration = 86400;
    private long passwordResetTokenExpiration = 300;

    @Data
    public static class Jwt {
        private String secret;
        private long accessTokenExpiration = 86400000; // 24 hours
        private long refreshTokenExpiration = 2592000000L; // 30 days
    }

    @Data
    public static class RateLimit {
        private int maxAttempts = 5;
        private int windowSeconds = 60;
        private int lockoutSeconds = 120;
    }
}