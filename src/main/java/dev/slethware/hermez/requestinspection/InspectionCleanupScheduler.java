package dev.slethware.hermez.requestinspection;

import dev.slethware.hermez.user.SubscriptionTier;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Slf4j
@Component
@RequiredArgsConstructor
public class InspectionCleanupScheduler {

    private final RequestLogRepository requestLogRepository;

    @Scheduled(cron = "0 */30 * * * *")
    public void cleanup() {
        log.debug("Starting inspection log cleanup");
        Instant now = Instant.now();

        // Only tiers with finite retention and finite caps — Talaria is unlimited on both
        Flux<SubscriptionTier> finiteTiers = Flux.just(
                SubscriptionTier.CHELYS,
                SubscriptionTier.INVENTOR,
                SubscriptionTier.PETASOS
        );

        // Pass 1: retention — delete logs older than each tier's logRetentionHours
        Flux<Integer> retentionPass = finiteTiers.flatMap(tier -> {
            Instant cutoff = now.minus(tier.getLogRetentionHours(), ChronoUnit.HOURS);
            return requestLogRepository.deleteByTierAndStartedAtBefore(tier.getValue(), cutoff)
                    .doOnSuccess(count -> {
                        if (count > 0) {
                            log.info("Retention cleanup: removed {} expired logs for tier={}", count, tier.getValue());
                        }
                    });
        });

        // Pass 2: rolling cap — delete excess logs beyond each tier's maxRequestLogs
        Flux<Integer> capPass = finiteTiers.flatMap(tier ->
                requestLogRepository.deleteExcessByTier(tier.getValue(), tier.getMaxRequestLogs())
                        .doOnSuccess(count -> {
                            if (count > 0) {
                                log.info("Rolling cap cleanup: removed {} excess logs for tier={}", count, tier.getValue());
                            }
                        }));

        retentionPass
                .thenMany(capPass)
                .subscribe(
                        null,
                        err -> log.error("Inspection cleanup error: {}", err.getMessage()),
                        () -> log.debug("Inspection log cleanup finished")
                );
    }
}