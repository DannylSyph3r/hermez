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
                                .subject("On Winged Feet")
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
                    <title>On Winged Feet</title>
                </head>
                <body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f8f9fa;">
                    <table role="presentation" style="width: 100%%; border-collapse: collapse; background-color: #f8f9fa;">
                        <tr>
                            <td style="padding: 40px 20px;">
                                <table role="presentation" style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 2px 12px rgba(0, 0, 0, 0.08);">
                                    
                                    <!-- Header with Gradient Background and Logo -->
                                    <tr>
                                        <td style="background: linear-gradient(135deg, #9F2B68 0%%, #6B2D5F 50%%, #431C53 100%%); padding: 50px 40px; text-align: center;">
                                            <img src="https://hermez.one/email/hermez.png" alt="Hermez" style="max-width: 120px; width: 120px; height: auto; display: block; margin: 0 auto;" />
                                        </td>
                                    </tr>
                                    
                                    <!-- Content -->
                                    <tr>
                                        <td style="padding: 50px 40px;">
                                            <h1 style="margin: 0 0 28px; font-size: 28px; font-weight: 700; color: transparent; background: linear-gradient(135deg, #9F2B68, #6B2D5F); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; line-height: 1.2;">
                                                On Winged Feet
                                            </h1>
                                            
                                            <p style="margin: 0 0 24px; font-size: 17px; line-height: 1.7; color: #2d2d2d;">
                                                Your message has been received. Thank you for joining the Hermez waitlist—you're now among the first to experience the future of tunneling infrastructure.
                                            </p>
                                            
                                            <p style="margin: 0 0 32px; font-size: 17px; line-height: 1.7; color: #2d2d2d;">
                                                When Hermez launches, you'll be at the front of the line. Expect updates on:
                                            </p>
                                            
                                            <!-- Features List -->
                                            <table role="presentation" style="width: 100%%; margin: 0 0 40px;">
                                                <tr>
                                                    <td style="padding: 14px 0;">
                                                        <table role="presentation" style="width: 100%%;">
                                                            <tr>
                                                                <td style="width: 36px; vertical-align: middle;">
                                                                    <div style="width: 20px; height: 20px; background: linear-gradient(135deg, #9F2B68, #6B2D5F); border-radius: 4px; display: table; text-align: center;">
                                                                        <span style="color: white; font-size: 14px; font-weight: bold; display: table-cell; vertical-align: middle;">✓</span>
                                                                    </div>
                                                                </td>
                                                                <td style="font-size: 17px; color: #1a1a1a; line-height: 1.5; font-weight: 500; vertical-align: middle;">
                                                                    Early access opportunities
                                                                </td>
                                                            </tr>
                                                        </table>
                                                    </td>
                                                </tr>
                                                <tr>
                                                    <td style="padding: 14px 0;">
                                                        <table role="presentation" style="width: 100%%;">
                                                            <tr>
                                                                <td style="width: 36px; vertical-align: middle;">
                                                                    <div style="width: 20px; height: 20px; background: linear-gradient(135deg, #9F2B68, #6B2D5F); border-radius: 4px; display: table; text-align: center;">
                                                                        <span style="color: white; font-size: 14px; font-weight: bold; display: table-cell; vertical-align: middle;">✓</span>
                                                                    </div>
                                                                </td>
                                                                <td style="font-size: 17px; color: #1a1a1a; line-height: 1.5; font-weight: 500; vertical-align: middle;">
                                                                    Product updates and features
                                                                </td>
                                                            </tr>
                                                        </table>
                                                    </td>
                                                </tr>
                                                <tr>
                                                    <td style="padding: 14px 0;">
                                                        <table role="presentation" style="width: 100%%;">
                                                            <tr>
                                                                <td style="width: 36px; vertical-align: middle;">
                                                                    <div style="width: 20px; height: 20px; background: linear-gradient(135deg, #9F2B68, #6B2D5F); border-radius: 4px; display: table; text-align: center;">
                                                                        <span style="color: white; font-size: 14px; font-weight: bold; display: table-cell; vertical-align: middle;">✓</span>
                                                                    </div>
                                                                </td>
                                                                <td style="font-size: 17px; color: #1a1a1a; line-height: 1.5; font-weight: 500; vertical-align: middle;">
                                                                    Launch announcements
                                                                </td>
                                                            </tr>
                                                        </table>
                                                    </td>
                                                </tr>
                                            </table>
                                            
                                            <!-- CTA Button -->
                                            <table role="presentation" style="margin: 0 0 40px; width: 100%%;">
                                                <tr>
                                                    <td style="text-align: center;">
                                                        <a href="https://hermez.one" style="display: inline-block; padding: 16px 40px; background: linear-gradient(135deg, #9F2B68, #6B2D5F); color: #ffffff; text-decoration: none; border-radius: 10px; font-size: 16px; font-weight: 600; box-shadow: 0 4px 16px rgba(159, 43, 104, 0.25);">
                                                            Visit Hermez →
                                                        </a>
                                                    </td>
                                                </tr>
                                            </table>
                                            
                                            <p style="margin: 32px 0 0; font-size: 17px; line-height: 1.7; color: #2d2d2d;">
                                                The messenger moves swiftly. Stay ready.
                                            </p>
                                            
                                            <p style="margin: 40px 0 0; font-size: 17px; line-height: 1.7; color: #4a4a4a;">
                                                Best regards,<br>
                                                <strong style="color: #9F2B68; font-size: 18px;">The Hermez Team</strong>
                                            </p>
                                        </td>
                                    </tr>
                                    
                                    <!-- Footer -->
                                    <tr>
                                        <td style="background: linear-gradient(135deg, #fafbfc 0%%, #f5f6f8 100%%); padding: 40px 40px; border-top: 1px solid #e8eaed;">
                                            
                                            <!-- Tagline -->
                                            <p style="margin: 0 0 28px; text-align: center; font-size: 15px; font-style: italic; color: #6B2D5F; font-weight: 500; letter-spacing: 0.3px;">
                                                As above, so below. As local, so global.
                                            </p>
                                            
                                            <!-- Copyright -->
                                            <p style="margin: 0 0 12px; text-align: center; font-size: 14px; color: #888888;">
                                                © 2025 Hermez Inc. All rights reserved.
                                            </p>
                                            
                                            <!-- Disclaimer -->
                                            <p style="margin: 0; text-align: center; font-size: 13px; color: #aaaaaa; line-height: 1.5;">
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