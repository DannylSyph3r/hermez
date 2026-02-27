package dev.slethware.hermez.domain.api;

import dev.slethware.hermez.domain.CustomDomain;

import java.time.LocalDateTime;
import java.util.UUID;

public record CustomDomainResponse(
        UUID          id,
        String        domain,
        String        linkedSubdomain,
        String        status,
        String        txtRecordName,
        String        txtRecordValue,
        String        cnameTarget,
        LocalDateTime verifiedAt,
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) {
    public static CustomDomainResponse from(CustomDomain domain,
                                            String txtRecordName,
                                            String txtRecordValue,
                                            String cnameTarget) {
        return new CustomDomainResponse(
                domain.getId(),
                domain.getDomain(),
                domain.getLinkedSubdomain(),
                domain.getStatus(),
                txtRecordName,
                txtRecordValue,
                cnameTarget,
                domain.getVerifiedAt(),
                domain.getCreatedAt(),
                domain.getUpdatedAt()
        );
    }
}