package dev.slethware.hermez.domain;

public enum DomainStatus {
    PENDING,
    ACTIVE,
    FAILED;

    public String value() {
        return name().toLowerCase();
    }
}