package dev.slethware.hermez.domain;

public enum DomainStatus {
    PENDING,
    VERIFIED,
    ACTIVE,
    FAILED;

    public String value() {
        return name().toLowerCase();
    }
}