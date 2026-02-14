package dev.slethware.hermez.common.util;

import dev.slethware.hermez.exception.UnauthorizedException;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import reactor.core.publisher.Mono;

import java.util.UUID;

public class SecurityContextUtil {

    private SecurityContextUtil() {}

    public static Mono<UUID> getCurrentUserId() {
        return ReactiveSecurityContextHolder.getContext()
                .map(securityContext -> securityContext.getAuthentication().getName())
                .map(UUID::fromString)
                .switchIfEmpty(Mono.error(new UnauthorizedException("Not authenticated")));
    }
}