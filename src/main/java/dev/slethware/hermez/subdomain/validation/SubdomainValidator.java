package dev.slethware.hermez.subdomain.validation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.slethware.hermez.config.HermezConfigProperties;
import dev.slethware.hermez.subdomain.SubdomainReservationRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.UUID;
import java.util.regex.Pattern;

@Slf4j
@Component
@RequiredArgsConstructor
public class SubdomainValidator {

    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final SubdomainReservationRepository reservationRepository;
    private final HermezConfigProperties configProperties;
    private final ObjectMapper objectMapper;

    private static final Pattern SUBDOMAIN_PATTERN =
            Pattern.compile("^[a-z]([a-z0-9]|[a-z0-9-]{1,61}[a-z0-9])$");

    public Mono<ValidationResult> validate(String subdomain, UUID userId) {
        log.debug("Validating subdomain: {} for user: {}", subdomain, userId);

        // Step 1: Format validation
        ValidationResult formatCheck = validateFormat(subdomain);
        if (!(formatCheck instanceof ValidationResult.Valid)) {
            return Mono.just(formatCheck);
        }

        // Step 2: Blocklist check
        if (isBlocked(subdomain)) {
            log.debug("Subdomain is blocked: {}", subdomain);
            return Mono.just(new ValidationResult.Blocked(subdomain));
        }

        // Step 3: Check active tunnel in Redis
        return checkActiveTunnel(subdomain)
                .flatMap(result -> {
                    if (result instanceof ValidationResult.InUse) {
                        return Mono.just(result);
                    }
                    // Step 4: Check reservation in PostgreSQL
                    return checkReservation(subdomain);
                });
    }

    public ValidationResult validateFormat(String subdomain) {
        if (subdomain == null || subdomain.isBlank()) {
            return new ValidationResult.InvalidFormat(subdomain, "Subdomain cannot be empty");
        }

        String normalized = subdomain.toLowerCase().trim();

        if (!SUBDOMAIN_PATTERN.matcher(normalized).matches()) {
            return new ValidationResult.InvalidFormat(
                    subdomain,
                    "Subdomain must be 2-63 characters, start with a letter, " +
                            "contain only lowercase letters, numbers, and hyphens, " +
                            "and end with a letter or number"
            );
        }

        return new ValidationResult.Valid(normalized);
    }

    private boolean isBlocked(String subdomain) {
        return configProperties.getSubdomain().getBlocked()
                .stream()
                .anyMatch(blocked -> blocked.equalsIgnoreCase(subdomain));
    }

    private Mono<ValidationResult> checkActiveTunnel(String subdomain) {
        String redisKey = "tunnel:" + subdomain;

        return redisTemplate.opsForValue()
                .get(redisKey)
                .flatMap(tunnelJson -> {
                    try {
                        JsonNode node = objectMapper.readTree(tunnelJson);
                        UUID ownerId = UUID.fromString(node.get("user_id").asText());

                        log.debug("Subdomain {} is actively in use by user: {}", subdomain, ownerId);
                        return Mono.just((ValidationResult) new ValidationResult.InUse(subdomain, ownerId));
                    } catch (Exception e) {
                        log.error("Error parsing tunnel data from Redis for subdomain: {}", subdomain, e);
                        return Mono.just((ValidationResult) new ValidationResult.Valid(subdomain));
                    }
                })
                .defaultIfEmpty(new ValidationResult.Valid(subdomain));
    }

    private Mono<ValidationResult> checkReservation(String subdomain) {
        return reservationRepository.findBySubdomain(subdomain)
                .map(reservation -> (ValidationResult) new ValidationResult.Reserved(
                        subdomain,
                        reservation.getUserId()
                ))
                .defaultIfEmpty(new ValidationResult.Valid(subdomain));
    }
}