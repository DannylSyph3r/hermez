package dev.slethware.hermez.email;

import reactor.core.publisher.Mono;

public interface EmailService {
    Mono<Void> sendWaitlistConfirmationEmail(String toEmail);
    Mono<Void> sendVerificationEmail(String toEmail, String verificationUrl);
    Mono<Void> sendPasswordResetEmail(String toEmail, String resetUrl);
    Mono<Void> sendAccountExistsEmail(String toEmail, String loginUrl);
}