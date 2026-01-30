package dev.slethware.hermez.email;

import reactor.core.publisher.Mono;

public interface EmailService {
    Mono<Void> sendWaitlistConfirmationEmail(String toEmail);
    Mono<Void> sendVerificationEmail(String toEmail, String token);
    Mono<Void> sendPasswordResetEmail(String toEmail, String token);
}