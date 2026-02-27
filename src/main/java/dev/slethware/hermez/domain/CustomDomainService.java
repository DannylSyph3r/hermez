package dev.slethware.hermez.domain;

import dev.slethware.hermez.config.HermezConfigProperties;
import dev.slethware.hermez.exception.BadRequestException;
import dev.slethware.hermez.exception.ForbiddenException;
import dev.slethware.hermez.exception.ResourceNotFoundException;
import dev.slethware.hermez.subdomain.SubdomainReservationRepository;
import dev.slethware.hermez.user.SubscriptionTier;
import dev.slethware.hermez.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.UUID;
import java.util.regex.Pattern;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomDomainService {

    private final CustomDomainRepository            domainRepository;
    private final DomainVerificationService         verificationService;
    private final UserRepository                    userRepository;
    private final SubdomainReservationRepository    subdomainReservationRepository;
    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final HermezConfigProperties            configProperties;

    private static final String   CACHE_PREFIX = "custom_domain:";
    private static final Duration CACHE_TTL    = Duration.ofSeconds(60);

    private static final Pattern FQDN_PATTERN = Pattern.compile(
            "^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
    );
    private static final Pattern IP_PATTERN = Pattern.compile(
            "^(\\d{1,3}\\.){3}\\d{1,3}$"
    );

    public Mono<CustomDomain> registerDomain(UUID userId, String domain, String linkedSubdomain) {
        String normalizedDomain = domain.toLowerCase().trim();
        log.info("Registering custom domain: {} for user: {}", normalizedDomain, userId);

        return userRepository.findById(userId)
                .switchIfEmpty(Mono.error(new ResourceNotFoundException("User not found")))
                .flatMap(user -> {
                    SubscriptionTier tier = SubscriptionTier.fromValue(user.getTier());
                    return checkDomainLimit(userId, tier)
                            .then(validateDomain(normalizedDomain))
                            .then(validateLinkedSubdomain(linkedSubdomain, userId))
                            .then(Mono.defer(() -> {
                                String token = verificationService.generateVerificationToken();
                                CustomDomain customDomain = CustomDomain.builder()
                                        .userId(userId)
                                        .domain(normalizedDomain)
                                        .linkedSubdomain(linkedSubdomain)
                                        .status(DomainStatus.PENDING.value())
                                        .verificationToken(token)
                                        .createdAt(LocalDateTime.now())
                                        .updatedAt(LocalDateTime.now())
                                        .build();
                                return domainRepository.save(customDomain);
                            }));
                });
    }

    public Mono<CustomDomain> verifyDomain(UUID userId, UUID domainId) {
        log.info("Verifying domain id: {} for user: {}", domainId, userId);

        return domainRepository.findById(domainId)
                .filter(d -> d.getUserId().equals(userId))
                .switchIfEmpty(Mono.error(new ResourceNotFoundException("Domain not found")))
                .flatMap(domain -> verificationService
                        .verifyOwnership(domain.getDomain(), domain.getVerificationToken())
                        .flatMap(verified -> {
                            if (verified) {
                                log.info("Domain verified successfully: {}", domain.getDomain());
                                domain.setStatus(DomainStatus.ACTIVE.value());
                                domain.setVerifiedAt(LocalDateTime.now());
                                domain.setUpdatedAt(LocalDateTime.now());
                                return domainRepository.save(domain)
                                        .flatMap(saved -> evictCache(saved.getDomain()).thenReturn(saved));
                            }
                            log.debug("DNS verification not yet passing for domain: {}", domain.getDomain());
                            return Mono.just(domain);
                        })
                );
    }

    public Flux<CustomDomain> listDomains(UUID userId) {
        return domainRepository.findAllByUserId(userId);
    }

    public Mono<Void> deleteDomain(UUID userId, UUID domainId) {
        log.info("Deleting domain id: {} for user: {}", domainId, userId);

        return domainRepository.findById(domainId)
                .filter(d -> d.getUserId().equals(userId))
                .switchIfEmpty(Mono.error(new ResourceNotFoundException("Domain not found")))
                .flatMap(domain -> domainRepository.deleteById(domainId)
                        .then(evictCache(domain.getDomain()))
                );
    }

    public Mono<String> resolveSubdomain(String host) {
        String cacheKey = CACHE_PREFIX + host;
        return redisTemplate.opsForValue().get(cacheKey)
                .switchIfEmpty(
                        domainRepository.findByDomain(host)
                                .filter(d -> DomainStatus.ACTIVE.value().equals(d.getStatus()))
                                .flatMap(d -> redisTemplate.opsForValue()
                                        .set(cacheKey, d.getLinkedSubdomain(), CACHE_TTL)
                                        .thenReturn(d.getLinkedSubdomain())
                                )
                );
    }

    private Mono<Void> checkDomainLimit(UUID userId, SubscriptionTier tier) {
        if (tier.isUnlimitedDomains()) {
            return Mono.empty();
        }
        if (tier.getMaxCustomDomains() == 0) {
            return Mono.error(new ForbiddenException(
                    "Custom domains are not available on your current plan. Please upgrade to add a custom domain."
            ));
        }
        return domainRepository.countByUserIdAndStatusNot(userId, DomainStatus.FAILED.value())
                .flatMap(count -> {
                    if (count >= tier.getMaxCustomDomains()) {
                        return Mono.error(new ForbiddenException(
                                String.format("Domain limit reached. Your %s plan allows %d custom domain(s).",
                                        tier.getValue(), tier.getMaxCustomDomains())
                        ));
                    }
                    return Mono.<Void>empty();
                });
    }

    private Mono<Void> validateDomain(String domain) {
        if (IP_PATTERN.matcher(domain).matches()) {
            return Mono.error(new BadRequestException("Bare IP addresses are not allowed as custom domains"));
        }
        String baseDomain = configProperties.getSubdomain().getBaseDomain();
        if (domain.equals(baseDomain) || domain.endsWith("." + baseDomain)) {
            return Mono.error(new BadRequestException("Hermez subdomains cannot be used as custom domains"));
        }
        if (!FQDN_PATTERN.matcher(domain).matches()) {
            return Mono.error(new BadRequestException("Invalid domain format"));
        }
        return Mono.empty();
    }

    private Mono<Void> validateLinkedSubdomain(String linkedSubdomain, UUID userId) {
        return subdomainReservationRepository.findBySubdomain(linkedSubdomain)
                .switchIfEmpty(Mono.error(new BadRequestException(
                        "Subdomain '" + linkedSubdomain + "' is not reserved"
                )))
                .flatMap(reservation -> {
                    if (!reservation.getUserId().equals(userId)) {
                        return Mono.error(new ForbiddenException(
                                "Subdomain '" + linkedSubdomain + "' is not reserved by you"
                        ));
                    }
                    return Mono.<Void>empty();
                });
    }

    private Mono<Void> evictCache(String host) {
        return redisTemplate.delete(CACHE_PREFIX + host).then();
    }
}