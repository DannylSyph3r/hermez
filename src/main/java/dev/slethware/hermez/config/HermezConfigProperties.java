package dev.slethware.hermez.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;
import java.util.List;

@Data
@Configuration
@ConfigurationProperties(prefix = "hermez")
public class HermezConfigProperties {

    private ServerConfig     server     = new ServerConfig();
    private TunnelConfig     tunnel     = new TunnelConfig();
    private RateLimitConfig  rateLimit  = new RateLimitConfig();
    private SubdomainConfig  subdomain  = new SubdomainConfig();
    private InspectionConfig inspection = new InspectionConfig();

    @Data
    public static class ServerConfig {
        // Used for multi-server routing in Redis. Redundant for single-server MVP.
        private String id = "server-1";
        private String address = "localhost:8080";
    }

    @Data
    public static class TunnelConfig {
        private Duration heartbeatInterval = Duration.ofSeconds(5);
        private Duration heartbeatTimeout  = Duration.ofSeconds(3);
        private Duration requestTimeout    = Duration.ofSeconds(60);
        private int      maxTunnelsPerUser = 5;
    }

    @Data
    public static class RateLimitConfig {
        private int freeTier = 20;
        private int paidTier = 100;
    }

    @Data
    public static class SubdomainConfig {
        private int          minLength  = 3;
        private int          maxLength  = 63;
        private String       baseDomain = "hermez.one";
        private List<String> blocked    = List.of(
                "www", "api", "admin", "dashboard", "mail", "ftp",
                "smtp", "pop", "imap", "ns", "dns", "whois", "ssl",
                "tls", "http", "https", "ssh", "sftp", "blog"
        );
    }

    @Data
    public static class InspectionConfig {
        private int maxBodySizeBytes = 65536;
    }
}