package dev.slethware.hermez.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "oauth")
public class OAuthProperties {

    private Google google = new Google();
    private Github github = new Github();

    @Getter
    @Setter
    public static class Google {
        private String clientId;
        private String clientSecret;
        private String redirectUri;

        public String getAuthorizationUri() {
            return "https://accounts.google.com/o/oauth2/v2/auth";
        }

        public String getTokenUri() {
            return "https://oauth2.googleapis.com/token";
        }

        public String getUserInfoUri() {
            return "https://www.googleapis.com/oauth2/v2/userinfo";
        }
    }

    @Getter
    @Setter
    public static class Github {
        private String clientId;
        private String clientSecret;
        private String redirectUri;

        public String getAuthorizationUri() {
            return "https://github.com/login/oauth/authorize";
        }

        public String getTokenUri() {
            return "https://github.com/login/oauth/access_token";
        }

        public String getUserInfoUri() {
            return "https://api.github.com/user";
        }
    }
}