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

    @Override
    public Mono<Void> sendWaitlistConfirmationEmail(String toEmail) {
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
                <html>
                <head>
                    <meta charset="UTF-8">
                </head>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h1 style="color: #9F2B68;">Welcome to the Hermez Order!</h1>
                        
                        <p>Thank you for joining our waitlist. We're excited to have you on board as we build the future of tunneling infrastructure.</p>
                        
                        <p>You'll be among the first to know when Hermez launches. We'll keep you updated with:</p>
                        <ul>
                            <li>Early access opportunities</li>
                            <li>Product updates and features</li>
                            <li>Launch announcements</li>
                        </ul>
                        
                        <p>Stay tuned for more updates!</p>
                        
                        <p style="margin-top: 30px;">
                            Best regards,<br>
                            <strong>The Hermez Team</strong>
                        </p>
                        
                        <hr style="margin-top: 40px; border: none; border-top: 1px solid #eee;">
                        <p style="font-size: 12px; color: #999;">
                            This is an automated message. Please do not reply to this email.
                        </p>
                    </div>
                </body>
                </html>
                """;
    }
}