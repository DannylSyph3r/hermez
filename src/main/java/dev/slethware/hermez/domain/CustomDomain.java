package dev.slethware.hermez.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table("custom_domains")
public class CustomDomain {

    @Id
    private UUID   id;
    private UUID   userId;
    private String domain;
    private String linkedSubdomain;
    private String status;
    private String verificationToken;
    private Instant verifiedAt;
    private Instant createdAt;
    private Instant updatedAt;
}