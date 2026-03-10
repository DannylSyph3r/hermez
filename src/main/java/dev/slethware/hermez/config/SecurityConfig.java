package dev.slethware.hermez.config;

import dev.slethware.hermez.auth.JwtAuthenticationFilter;
import dev.slethware.hermez.auth.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final TokenService tokenService;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(tokenService);
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(jsonAuthenticationEntryPoint())
                )
                .addFilterAt(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .authorizeExchange(exchanges -> exchanges
                        // Public endpoints
                        .pathMatchers("/api/v1/auth/register").permitAll()
                        .pathMatchers("/api/v1/auth/login").permitAll()
                        .pathMatchers("/api/v1/auth/refresh").permitAll()
                        .pathMatchers("/api/v1/auth/verify-email").permitAll()
                        .pathMatchers("/api/v1/auth/resend-verification").permitAll()
                        .pathMatchers("/api/v1/auth/forgot-password").permitAll()
                        .pathMatchers("/api/v1/auth/validate-reset-token").permitAll()
                        .pathMatchers("/api/v1/auth/reset-password").permitAll()
                        .pathMatchers("/api/v1/auth/oauth/google").permitAll()
                        .pathMatchers("/api/v1/auth/oauth/google/callback").permitAll()
                        .pathMatchers("/api/v1/auth/oauth/github").permitAll()
                        .pathMatchers("/api/v1/auth/oauth/github/callback").permitAll()
                        .pathMatchers("/api/v1/waitlist/**").permitAll()

                        // Websocket inlet
                        .pathMatchers("/connect").permitAll()

                        // Documentation
                        .pathMatchers("/api-docs/**").permitAll()
                        .pathMatchers("/docs/**").permitAll()
                        .pathMatchers("/swagger-ui/**").permitAll()
                        .pathMatchers("/swagger-ui.html").permitAll()
                        .pathMatchers("/webjars/**").permitAll()

                        // Actuator
                        .pathMatchers("/actuator/**").permitAll()
                        // All other endpoints require authentication
                        .anyExchange().authenticated()
                )
                .build();
    }

    private ServerAuthenticationEntryPoint jsonAuthenticationEntryPoint() {
        return (exchange, ex) -> {
            var response = exchange.getResponse();
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
            var body = "{\"message\":\"Unauthorized\",\"error\":\"Unauthorized\",\"statusCode\":401}";
            var buffer = response.bufferFactory().wrap(body.getBytes());
            return response.writeWith(Mono.just(buffer));
        };
    }
}