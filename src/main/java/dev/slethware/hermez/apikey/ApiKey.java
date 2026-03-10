package dev.slethware.hermez.apikey;

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
@Table("api_keys")
public class ApiKey {

    @Id
    private UUID id;
    private UUID userId;
    private String name;
    private String keyHash;
    private String keyPreview;
    private Instant createdAt;
    private Instant lastUsedAt;
    private Instant revokedAt;
}