package dev.slethware.hermez.waitlist;

import dev.slethware.hermez.email.EmailService;
import dev.slethware.hermez.waitlist.api.WaitlistRequest;
import dev.slethware.hermez.waitlist.api.WaitlistResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class WaitlistServiceImpl implements WaitlistService {

    private final WaitlistRepository waitlistRepository;
    private final EmailService emailService;

    @Override
    public Mono<WaitlistResponse> register(WaitlistRequest request) {
        String normalizedEmail = request.email().toLowerCase().trim();
        log.info("Processing waitlist registration for email: {}", normalizedEmail);

        return waitlistRepository.existsByEmail(normalizedEmail)
                .flatMap(exists -> {
                    if (exists) {
                        log.info("Email already registered: {} - returning silent success", normalizedEmail);
                        return Mono.just(new WaitlistResponse(
                                normalizedEmail,
                                "You have successfully joined the waitlist!"
                        ));
                    }

                    Waitlist subscriber = Waitlist.builder()
                            .email(normalizedEmail)
                            .createdAt(LocalDateTime.now())
                            .build();

                    return waitlistRepository.save(subscriber)
                            .doOnSuccess(saved -> {
                                log.info("Successfully saved waitlist entry for: {}", saved.getEmail());
                                emailService.sendWaitlistConfirmationEmail(saved.getEmail())
                                        .subscribe(
                                                unused -> log.info("Confirmation email sent to: {}", saved.getEmail()),
                                                error -> log.error("Failed to send confirmation email to: {}", saved.getEmail(), error)
                                        );
                            })
                            .map(saved -> new WaitlistResponse(
                                    saved.getEmail(),
                                    "You have successfully joined the waitlist!"
                            ))
                            .onErrorResume(e -> {
                                log.error("Error during waitlist registration for: {}", normalizedEmail, e);
                                return Mono.just(new WaitlistResponse(
                                        normalizedEmail,
                                        "You have successfully joined the waitlist!"
                                ));
                            });
                });
    }
}