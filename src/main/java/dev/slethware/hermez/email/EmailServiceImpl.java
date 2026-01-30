package dev.slethware.hermez.email;

import com.resend.Resend;
import com.resend.core.exception.ResendException;
import com.resend.services.emails.model.CreateEmailOptions;
import com.resend.services.emails.model.CreateEmailResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailServiceImpl implements EmailService {

    private final Resend resend;

    @Value("${resend.from-email}")
    private String fromEmail;

    @Value("${resend.enabled:false}")
    private boolean emailEnabled;

    @Value("${app.base-url:https://hermez.one}")
    private String baseUrl;

    @Override
    public Mono<Void> sendWaitlistConfirmationEmail(String toEmail) {
        if (!emailEnabled) {
            log.info("Email service disabled - skipping confirmation email for: {}", toEmail);
            return Mono.empty();
        }

        return Mono.fromCallable(() -> {
                    try {
                        CreateEmailOptions email = CreateEmailOptions.builder()
                                .from("Hermez Team <" + fromEmail + ">")
                                .to(toEmail)
                                .subject("On Winged Feet")
                                .html(buildWaitlistEmailContent())
                                .build();

                        CreateEmailResponse response = resend.emails().send(email);
                        log.info("Waitlist confirmation email sent to: {} with ID: {}", toEmail, response.getId());
                        return null;
                    } catch (ResendException e) {
                        log.error("Failed to send waitlist confirmation email to: {}", toEmail, e);
                        throw new RuntimeException("Failed to send email", e);
                    }
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    @Override
    public Mono<Void> sendVerificationEmail(String toEmail, String token) {
        if (!emailEnabled) {
            log.info("Email service disabled - skipping verification email for: {}", toEmail);
            log.info("Verification token for {}: {}", toEmail, token);
            return Mono.empty();
        }

        return Mono.fromCallable(() -> {
                    try {
                        String verificationUrl = baseUrl + "/api/v1/auth/verify-email?token=" + token;

                        CreateEmailOptions email = CreateEmailOptions.builder()
                                .from("Hermez <" + fromEmail + ">")
                                .to(toEmail)
                                .subject("Verify your Hermez account")
                                .html(buildVerificationEmailContent(verificationUrl))
                                .build();

                        CreateEmailResponse response = resend.emails().send(email);
                        log.info("Verification email sent to: {} with ID: {}", toEmail, response.getId());
                        return null;
                    } catch (ResendException e) {
                        log.error("Failed to send verification email to: {}", toEmail, e);
                        throw new RuntimeException("Failed to send email", e);
                    }
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    @Override
    public Mono<Void> sendPasswordResetEmail(String toEmail, String token) {
        if (!emailEnabled) {
            log.info("Email service disabled - skipping password reset email for: {}", toEmail);
            log.info("Password reset token for {}: {}", toEmail, token);
            return Mono.empty();
        }

        return Mono.fromCallable(() -> {
                    try {
                        String resetUrl = baseUrl + "/reset-password?token=" + token;

                        CreateEmailOptions email = CreateEmailOptions.builder()
                                .from("Hermez <" + fromEmail + ">")
                                .to(toEmail)
                                .subject("Reset your Hermez password")
                                .html(buildPasswordResetEmailContent(resetUrl))
                                .build();

                        CreateEmailResponse response = resend.emails().send(email);
                        log.info("Password reset email sent to: {} with ID: {}", toEmail, response.getId());
                        return null;
                    } catch (ResendException e) {
                        log.error("Failed to send password reset email to: {}", toEmail, e);
                        throw new RuntimeException("Failed to send email", e);
                    }
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    private String buildWaitlistEmailContent() {
        return """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>On Winged Feet</title>
                </head>
                <body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f8f9fa;">
                    <table role="presentation" style="width: 100%%; border-collapse: collapse; background-color: #f8f9fa;">
                        <tr>
                            <td style="padding: 40px 20px;">
                                <table role="presentation" style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 2px 12px rgba(0,0,0,0.08);">
                                    <tr>
                                        <td style="background: linear-gradient(135deg, #6B2D5F 0%%, #9F2B68 100%%); padding: 40px 40px 30px;">
                                            <h1 style="color: #ffffff; margin: 0; font-size: 28px; font-weight: 600;">Welcome to Hermez</h1>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 40px;">
                                            <p style="color: #333; font-size: 16px; line-height: 1.6; margin: 0 0 20px;">You're on the waitlist! We'll notify you when Hermez is ready.</p>
                                            <p style="color: #666; font-size: 14px; line-height: 1.6; margin: 0;">Bridge worlds at divine speed.</p>
                                        </td>
                                    </tr>
                                </table>
                            </td>
                        </tr>
                    </table>
                </body>
                </html>
                """;
    }

    private String buildVerificationEmailContent(String verificationUrl) {
        return """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Verify your email</title>
                </head>
                <body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f8f9fa;">
                    <table role="presentation" style="width: 100%%; border-collapse: collapse; background-color: #f8f9fa;">
                        <tr>
                            <td style="padding: 40px 20px;">
                                <table role="presentation" style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 2px 12px rgba(0,0,0,0.08);">
                                    <tr>
                                        <td style="background: linear-gradient(135deg, #6B2D5F 0%%, #9F2B68 100%%); padding: 40px 40px 30px;">
                                            <h1 style="color: #ffffff; margin: 0; font-size: 28px; font-weight: 600;">Verify your email</h1>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 40px;">
                                            <p style="color: #333; font-size: 16px; line-height: 1.6; margin: 0 0 20px;">Click the button below to verify your email address and activate your Hermez account.</p>
                                            <a href="%s" style="display: inline-block; background: linear-gradient(135deg, #6B2D5F 0%%, #9F2B68 100%%); color: #ffffff; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-weight: 600; font-size: 16px;">Verify Email</a>
                                            <p style="color: #666; font-size: 14px; line-height: 1.6; margin: 30px 0 0;">This link will expire in 24 hours. If you didn't create an account, you can ignore this email.</p>
                                        </td>
                                    </tr>
                                </table>
                            </td>
                        </tr>
                    </table>
                </body>
                </html>
                """.formatted(verificationUrl);
    }

    private String buildPasswordResetEmailContent(String resetUrl) {
        return """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Reset your password</title>
                </head>
                <body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f8f9fa;">
                    <table role="presentation" style="width: 100%%; border-collapse: collapse; background-color: #f8f9fa;">
                        <tr>
                            <td style="padding: 40px 20px;">
                                <table role="presentation" style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 2px 12px rgba(0,0,0,0.08);">
                                    <tr>
                                        <td style="background: linear-gradient(135deg, #6B2D5F 0%%, #9F2B68 100%%); padding: 40px 40px 30px;">
                                            <h1 style="color: #ffffff; margin: 0; font-size: 28px; font-weight: 600;">Reset your password</h1>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 40px;">
                                            <p style="color: #333; font-size: 16px; line-height: 1.6; margin: 0 0 20px;">We received a request to reset your password. Click the button below to create a new password.</p>
                                            <a href="%s" style="display: inline-block; background: linear-gradient(135deg, #6B2D5F 0%%, #9F2B68 100%%); color: #ffffff; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-weight: 600; font-size: 16px;">Reset Password</a>
                                            <p style="color: #666; font-size: 14px; line-height: 1.6; margin: 30px 0 0;">This link will expire in 5 minutes. If you didn't request a password reset, you can safely ignore this email.</p>
                                        </td>
                                    </tr>
                                </table>
                            </td>
                        </tr>
                    </table>
                </body>
                </html>
                """.formatted(resetUrl);
    }
}