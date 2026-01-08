package dev.slethware.hermez.subdomain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table("subdomain_reservations")
public class SubdomainReservation {

    @Id
    private String subdomain;
    private UUID userId;
    private LocalDateTime createdAt;
    private LocalDateTime expiresAt;
}