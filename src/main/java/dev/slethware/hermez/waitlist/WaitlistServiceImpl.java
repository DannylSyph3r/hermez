package dev.slethware.hermez.waitlist;

import dev.slethware.hermez.exception.BadRequestException;
import dev.slethware.hermez.exception.InternalServerException;
import dev.slethware.hermez.mail.EmailService;
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
        log.info("Processing waitlist registration for email: {}", request.email());

        return waitlistRepository.existsByEmail(request.email())
                .flatMap(exists -> {
                    if (exists) {
                        log.error("Email already registered: {}", request.email());
                        return Mono.error(new BadRequestException("Email already registered"));
                    }

                    Waitlist subscriber = Waitlist.builder()
                            .email(request.email())
                            .createdAt(LocalDateTime.now())
                            .build();

                    return waitlistRepository.save(subscriber)
                            .doOnSuccess(saved -> {
                                log.info("Successfully saved waitlist entry for: {}", saved.getEmail());
                                emailService.sendWaitlistConfirmationEmail(saved.getEmail())
                                        .subscribe();
                            })
                            .map(saved -> new WaitlistResponse(
                                    saved.getEmail(),
                                    "You have successfully joined the waitlist!"
                            ))
                            .onErrorMap(e -> {
                                if (e instanceof BadRequestException) {
                                    return e;
                                }
                                log.error("Error during waitlist registration: {}", e.getMessage(), e);
                                return new InternalServerException("Failed to register for waitlist", e);
                            });
                });
    }
}