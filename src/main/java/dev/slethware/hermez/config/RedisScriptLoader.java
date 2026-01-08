package dev.slethware.hermez.config;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

@Getter
@Slf4j
@Component
public class RedisScriptLoader {

    private RedisScript<String> tunnelRouteScript;

    private RedisScript<Long> rateLimitScript;

    private RedisScript<String> tunnelRegisterScript;

    @PostConstruct
    public void loadScripts() {
        tunnelRouteScript = loadScript("scripts/tunnel_route.lua", String.class);
        rateLimitScript = loadScript("scripts/rate_limit.lua", Long.class);
        tunnelRegisterScript = loadScript("scripts/tunnel_register.lua", String.class);

        log.info("Redis Lua scripts loaded: tunnel_route, rate_limit, tunnel_register");
    }

    private <T> RedisScript<T> loadScript(String path, Class<T> resultType) {
        try {
            ClassPathResource resource = new ClassPathResource(path);
            try (InputStream is = resource.getInputStream()) {
                String scriptText = StreamUtils.copyToString(is, StandardCharsets.UTF_8);
                return RedisScript.of(scriptText, resultType);
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load Redis script: " + path, e);
        }
    }
}