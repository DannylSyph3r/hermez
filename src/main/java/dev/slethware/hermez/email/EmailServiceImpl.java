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

    @Override
    public Mono<Void> sendWaitlistConfirmationEmail(String toEmail) {
        if (!emailEnabled) {
            log.info("Email service disabled - skipping confirmation email for: {}", toEmail);
            return Mono.empty();
        }

        return Mono.fromCallable(() -> {
                    try {
                        CreateEmailOptions email = CreateEmailOptions.builder()
                                .from(fromEmail)
                                .to(toEmail)
                                .subject("Welcome to the Hermez Order")
                                .html(buildEmailContent())
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

    private String buildEmailContent() {
        return """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Welcome to Hermez</title>
                </head>
                <body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f8f9fa;">
                    <table role="presentation" style="width: 100%%; border-collapse: collapse; background-color: #f8f9fa;">
                        <tr>
                            <td style="padding: 40px 20px;">
                                <table role="presentation" style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);">
                                    
                                    <!-- Header -->
                                    <tr>
                                        <td style="background: linear-gradient(135deg, #9F2B68 0%%, #6B2D5F 50%%, #431C53 100%%); padding: 48px 40px; text-align: center;">
                                            <img src="https://hermez.one/email/hermez_banner.png" alt="Hermez" style="max-width: 240px; width: 100%%; height: auto; display: block; margin: 0 auto;" />
                                        </td>
                                    </tr>
                                    
                                    <!-- Content -->
                                    <tr>
                                        <td style="padding: 48px 40px;">
                                            <h2 style="margin: 0 0 24px; font-size: 24px; font-weight: 600; color: #1a1a1a; line-height: 1.3;">
                                                Welcome to the Hermez Order!
                                            </h2>
                                            
                                            <p style="margin: 0 0 20px; font-size: 16px; line-height: 1.6; color: #4a4a4a;">
                                                Thank you for joining our waitlist. We're excited to have you on board as we build the future of tunneling infrastructure.
                                            </p>
                                            
                                            <p style="margin: 0 0 24px; font-size: 16px; line-height: 1.6; color: #4a4a4a;">
                                                You'll be among the first to know when Hermez launches. We'll keep you updated with:
                                            </p>
                                            
                                            <!-- Features -->
                                            <table role="presentation" style="width: 100%%; margin: 0 0 32px;">
                                                <tr>
                                                    <td style="padding: 14px 0;">
                                                        <table role="presentation">
                                                            <tr>
                                                                <td style="width: 32px; vertical-align: top; padding-top: 2px;">
                                                                    <div style="width: 20px; height: 20px; background: linear-gradient(135deg, #9F2B68, #6B2D5F); border-radius: 6px;">
                                                                        <span style="color: white; font-size: 14px; font-weight: bold; line-height: 20px; display: block; text-align: center;">✓</span>
                                                                    </div>
                                                                </td>
                                                                <td style="font-size: 16px; color: #2d2d2d; line-height: 1.5; padding-left: 12px;">
                                                                    <strong style="color: #1a1a1a;">Early access opportunities</strong>
                                                                </td>
                                                            </tr>
                                                        </table>
                                                    </td>
                                                </tr>
                                                <tr>
                                                    <td style="padding: 14px 0;">
                                                        <table role="presentation">
                                                            <tr>
                                                                <td style="width: 32px; vertical-align: top; padding-top: 2px;">
                                                                    <div style="width: 20px; height: 20px; background: linear-gradient(135deg, #9F2B68, #6B2D5F); border-radius: 6px;">
                                                                        <span style="color: white; font-size: 14px; font-weight: bold; line-height: 20px; display: block; text-align: center;">✓</span>
                                                                    </div>
                                                                </td>
                                                                <td style="font-size: 16px; color: #2d2d2d; line-height: 1.5; padding-left: 12px;">
                                                                    <strong style="color: #1a1a1a;">Product updates and features</strong>
                                                                </td>
                                                            </tr>
                                                        </table>
                                                    </td>
                                                </tr>
                                                <tr>
                                                    <td style="padding: 14px 0;">
                                                        <table role="presentation">
                                                            <tr>
                                                                <td style="width: 32px; vertical-align: top; padding-top: 2px;">
                                                                    <div style="width: 20px; height: 20px; background: linear-gradient(135deg, #9F2B68, #6B2D5F); border-radius: 6px;">
                                                                        <span style="color: white; font-size: 14px; font-weight: bold; line-height: 20px; display: block; text-align: center;">✓</span>
                                                                    </div>
                                                                </td>
                                                                <td style="font-size: 16px; color: #2d2d2d; line-height: 1.5; padding-left: 12px;">
                                                                    <strong style="color: #1a1a1a;">Launch announcements</strong>
                                                                </td>
                                                            </tr>
                                                        </table>
                                                    </td>
                                                </tr>
                                            </table>
                                            
                                            <!-- CTA Button -->
                                            <table role="presentation" style="margin: 0 0 32px;">
                                                <tr>
                                                    <td>
                                                        <a href="https://hermez.one" style="display: inline-block; padding: 16px 32px; background: linear-gradient(135deg, #9F2B68, #6B2D5F); color: #ffffff; text-decoration: none; border-radius: 8px; font-size: 16px; font-weight: 600; box-shadow: 0 4px 12px rgba(159, 43, 104, 0.25);">
                                                            Visit Hermez →
                                                        </a>
                                                    </td>
                                                </tr>
                                            </table>
                                            
                                            <p style="margin: 24px 0 0; font-size: 16px; line-height: 1.6; color: #4a4a4a;">
                                                Stay tuned for more updates!
                                            </p>
                                            
                                            <p style="margin: 32px 0 0; font-size: 16px; line-height: 1.6; color: #4a4a4a;">
                                                Best regards,<br>
                                                <strong style="color: #9F2B68;">The Hermez Team</strong>
                                            </p>
                                        </td>
                                    </tr>
                                    
                                    <!-- Footer -->
                                    <tr>
                                        <td style="background-color: #fafbfc; padding: 32px 40px; border-top: 1px solid #e8eaed;">
                                            <!-- Logo Icon -->
                                            <div style="text-align: center; margin-bottom: 20px;">
                                                <img src="https://hermez.one/email/hermez_mono.png" alt="Hermez" style="width: 48px; height: auto; opacity: 0.7;" />
                                            </div>
                                            
                                            <!-- Tagline -->
                                            <p style="margin: 0 0 20px; text-align: center; font-size: 14px; font-style: italic; color: #6B2D5F; font-weight: 500;">
                                                As above, so below. As local, so global.
                                            </p>
                                            
                                            <!-- Links -->
                                            <table role="presentation" style="width: 100%%; margin: 0 0 20px;">
                                                <tr>
                                                    <td style="text-align: center;">
                                                        <a href="https://hermez.one" style="color: #6B2D5F; text-decoration: none; font-size: 14px; margin: 0 12px; font-weight: 500;">Website</a>
                                                        <span style="color: #d0d0d0;">|</span>
                                                        <a href="https://github.com/hermez" style="color: #6B2D5F; text-decoration: none; font-size: 14px; margin: 0 12px; font-weight: 500;">GitHub</a>
                                                        <span style="color: #d0d0d0;">|</span>
                                                        <a href="https://hermez.one/docs" style="color: #6B2D5F; text-decoration: none; font-size: 14px; margin: 0 12px; font-weight: 500;">Docs</a>
                                                    </td>
                                                </tr>
                                            </table>
                                            
                                            <!-- Copyright -->
                                            <p style="margin: 0 0 8px; text-align: center; font-size: 13px; color: #888888;">
                                                © 2025 Hermez Inc. All rights reserved.
                                            </p>
                                            
                                            <!-- Disclaimer -->
                                            <p style="margin: 0; text-align: center; font-size: 12px; color: #aaaaaa;">
                                                This is an automated message. Please do not reply to this email.
                                            </p>
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
}