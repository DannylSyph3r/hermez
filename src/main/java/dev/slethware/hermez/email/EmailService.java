package dev.slethware.hermez.email;

import reactor.core.publisher.Mono;

public interface EmailService {

    Mono<Void> sendWaitlistConfirmationEmail(String toEmail);
}