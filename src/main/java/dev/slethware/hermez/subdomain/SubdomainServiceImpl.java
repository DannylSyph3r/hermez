package dev.slethware.hermez.subdomain;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.slethware.hermez.exception.BadRequestException;
import dev.slethware.hermez.exception.ConflictException;
import dev.slethware.hermez.exception.ForbiddenException;
import dev.slethware.hermez.exception.ResourceNotFoundException;
import dev.slethware.hermez.subdomain.api.AvailabilityResponse;
import dev.slethware.hermez.subdomain.api.SubdomainListResponse;
import dev.slethware.hermez.subdomain.api.SubdomainResponse;
import dev.slethware.hermez.subdomain.validation.SubdomainValidator;
import dev.slethware.hermez.subdomain.validation.ValidationResult;
import dev.slethware.hermez.user.SubscriptionTier;
import dev.slethware.hermez.user.User;
import dev.slethware.hermez.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class SubdomainServiceImpl implements SubdomainService {

    private final SubdomainValidator validator;
    private final SubdomainReservationRepository reservationRepository;
    private final UserRepository userRepository;
    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper;

    @Override
    public Mono<SubdomainResponse> reserveSubdomain(String subdomain, UUID userId) {
        log.info("Attempting to reserve subdomain: {} for user: {}", subdomain, userId);

        return userRepository.findById(userId)
                .switchIfEmpty(Mono.error(new ResourceNotFoundException("User not found")))
                .flatMap(user -> checkReservationLimit(user)
                        .then(validator.validate(subdomain, userId))
                        .flatMap(result -> handleValidationResult(result, subdomain, userId))
                );
    }

    @Override
    public Mono<SubdomainListResponse> getReservations(UUID userId) {
        log.debug("Fetching reservations for user: {}", userId);

        return userRepository.findById(userId)
                .switchIfEmpty(Mono.error(new ResourceNotFoundException("User not found")))
                .flatMap(user -> {
                    SubscriptionTier tier = SubscriptionTier.fromValue(user.getTier());

                    return reservationRepository.findByUserId(userId)
                            .flatMap(reservation -> checkIfActive(reservation)
                                    .map(activeInfo -> SubdomainResponse.from(
                                            reservation,
                                            activeInfo.isActive(),
                                            activeInfo.tunnelId()
                                    ))
                            )
                            .collectList()
                            .map(subdomains -> new SubdomainListResponse(
                                    subdomains,
                                    subdomains.size(),
                                    new SubdomainListResponse.LimitsInfo(
                                            tier.getMaxSubdomainReservations(),
                                            subdomains.size()
                                    )
                            ));
                });
    }

    @Override
    public Mono<SubdomainResponse> getReservation(String subdomain, UUID userId) {
        log.debug("Fetching reservation details for subdomain: {} and user: {}", subdomain, userId);

        return reservationRepository.findById(subdomain)
                .switchIfEmpty(Mono.error(new ResourceNotFoundException("Subdomain reservation not found")))
                .flatMap(reservation -> {
                    if (!reservation.getUserId().equals(userId)) {
                        return Mono.error(new ForbiddenException("You do not own this subdomain"));
                    }

                    return checkIfActive(reservation)
                            .map(activeInfo -> SubdomainResponse.from(
                                    reservation,
                                    activeInfo.isActive(),
                                    activeInfo.tunnelId()
                            ));
                });
    }

    @Override
    public Mono<Void> releaseSubdomain(String subdomain, UUID userId) {
        log.info("Attempting to release subdomain: {} for user: {}", subdomain, userId);

        return reservationRepository.findById(subdomain)
                .switchIfEmpty(Mono.error(new ResourceNotFoundException("Subdomain reservation not found")))
                .flatMap(reservation -> {
                    if (!reservation.getUserId().equals(userId)) {
                        return Mono.error(new ForbiddenException("You do not own this subdomain"));
                    }

                    // Check if subdomain has active tunnel
                    return checkIfActive(reservation)
                            .flatMap(activeInfo -> {
                                if (activeInfo.isActive()) {
                                    return Mono.error(new ConflictException(
                                            "Cannot release subdomain with active tunnel. Close the tunnel first."
                                    ));
                                }
                                return reservationRepository.delete(reservation);
                            });
                })
                .doOnSuccess(v -> log.info("Subdomain released successfully: {}", subdomain));
    }

    @Override
    public Mono<AvailabilityResponse> checkAvailability(String subdomain, UUID userId) {
        log.debug("Checking availability of subdomain: {} for user: {}", subdomain, userId);

        return validator.validate(subdomain, userId)
                .map(result -> switch (result) {
                    case ValidationResult.Valid ignored ->
                            new AvailabilityResponse(subdomain, true, "available");
                    case ValidationResult.InvalidFormat(String ignored, var reason) ->
                            new AvailabilityResponse(subdomain, false, reason);
                    case ValidationResult.Blocked ignored ->
                            new AvailabilityResponse(subdomain, false, "blocked");
                    case ValidationResult.InUse(String ignored, var ownerId) -> {
                        if (ownerId.equals(userId)) {
                            yield new AvailabilityResponse(subdomain, false, "currently_active");
                        }
                        yield new AvailabilityResponse(subdomain, false, "reserved_by_other");
                    }
                    case ValidationResult.Reserved(String ignored, var ownerId) -> {
                        if (ownerId.equals(userId)) {
                            yield new AvailabilityResponse(subdomain, true, "reserved_by_you");
                        }
                        yield new AvailabilityResponse(subdomain, false, "reserved_by_other");
                    }
                });
    }

    private Mono<Void> checkReservationLimit(User user) {
        SubscriptionTier tier = SubscriptionTier.fromValue(user.getTier());

        if (tier.isUnlimited()) {
            return Mono.empty();
        }

        return reservationRepository.findByUserId(user.getId())
                .count()
                .flatMap(count -> {
                    if (count >= tier.getMaxSubdomainReservations()) {
                        return Mono.error(new ForbiddenException(
                                String.format("Reservation limit reached. Your tier (%s) allows %d reservations.",
                                        tier.getValue(), tier.getMaxSubdomainReservations())
                        ));
                    }
                    return Mono.empty();
                });
    }

    private Mono<SubdomainResponse> handleValidationResult(ValidationResult result, String subdomain, UUID userId
    ) {
        return switch (result) {
            case ValidationResult.Valid ignored -> createReservation(subdomain, userId);
            case ValidationResult.InvalidFormat(String ignored, var reason) ->
                    Mono.error(new BadRequestException(reason));
            case ValidationResult.Blocked ignored ->
                    Mono.error(new BadRequestException("Subdomain is not allowed"));
            case ValidationResult.InUse(String ignored, var ignored2) ->
                    Mono.error(new ConflictException("Subdomain is currently in use"));
            case ValidationResult.Reserved(String ignored, var ownerId) -> {
                if (ownerId.equals(userId)) {
                    // User already owns this reservation
                    yield reservationRepository.findById(subdomain)
                            .flatMap(reservation -> checkIfActive(reservation)
                                    .map(activeInfo -> SubdomainResponse.from(
                                            reservation,
                                            activeInfo.isActive(),
                                            activeInfo.tunnelId()
                                    ))
                            );
                }
                yield Mono.error(new ConflictException("Subdomain is already reserved"));
            }
        };
    }

    private Mono<SubdomainResponse> createReservation(String subdomain, UUID userId) {
        SubdomainReservation reservation = SubdomainReservation.builder()
                .subdomain(subdomain)
                .userId(userId)
                .createdAt(LocalDateTime.now())
                .expiresAt(null) // Permanent reservation for now
                .build();

        return reservationRepository.save(reservation)
                .doOnSuccess(r -> log.info("Subdomain reserved: {} for user: {}", subdomain, userId))
                .map(r -> SubdomainResponse.from(r, false, null));
    }

    private Mono<ActiveTunnelInfo> checkIfActive(SubdomainReservation reservation) {
        String redisKey = "tunnel:" + reservation.getSubdomain();

        return redisTemplate.opsForValue()
                .get(redisKey)
                .flatMap(tunnelJson -> {
                    try {
                        JsonNode node = objectMapper.readTree(tunnelJson);
                        UUID ownerId = UUID.fromString(node.get("user_id").asText());

                        if (ownerId.equals(reservation.getUserId())) {
                            // Extract tunnel ID if available
                            String tunnelId = node.has("tunnel_id")
                                    ? node.get("tunnel_id").asText()
                                    : null;
                            return Mono.just(new ActiveTunnelInfo(true, tunnelId));
                        }

                        return Mono.just(new ActiveTunnelInfo(false, null));
                    } catch (Exception e) {
                        log.error("Error parsing tunnel data from Redis", e);
                        return Mono.just(new ActiveTunnelInfo(false, null));
                    }
                })
                .defaultIfEmpty(new ActiveTunnelInfo(false, null));
    }

    private record ActiveTunnelInfo(boolean isActive, String tunnelId) {}
}