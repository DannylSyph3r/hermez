package dev.slethware.hermez.mail;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String fromEmail;

    @Override
    public Mono<Void> sendWaitlistConfirmationEmail(String toEmail) {
        return Mono.fromRunnable(() -> {
            try {
                SimpleMailMessage message = new SimpleMailMessage();
                message.setFrom(fromEmail);
                message.setTo(toEmail);
                message.setSubject("Welcome to the Hermez Order");
                message.setText(buildEmailContent());

                mailSender.send(message);
                log.info("Waitlist confirmation email sent to: {}", toEmail);
            } catch (Exception e) {
                log.error("Failed to send waitlist confirmation email to: {}", toEmail, e);
                throw new RuntimeException("Failed to send email", e);
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    private String buildEmailContent() {
        return """
                Welcome to the Hermez Order!
                
                Thank you for joining our waitlist. We're excited to have you on board as we build the future of tunneling infrastructure.
                
                You'll be among the first to know when Hermez launches. We'll keep you updated with:
                - Early access opportunities
                - Product updates and features
                - Launch announcements
                
                Stay tuned for more updates!
                
                Best regards,
                The Hermez Team
                
                ---
                This is an automated message. Please do not reply to this email.
                """;
    }
}