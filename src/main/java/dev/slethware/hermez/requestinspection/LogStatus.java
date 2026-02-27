package dev.slethware.hermez.requestinspection;

public enum LogStatus {
    PENDING,
    COMPLETED,
    TIMEOUT,
    ERROR;

    public String value() {
        return name().toLowerCase();
    }
}