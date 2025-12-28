package dev.slethware.hermez.mail;

import reactor.core.publisher.Mono;

public interface EmailService {

    Mono<Void> sendWaitlistConfirmationEmail(String toEmail);
}