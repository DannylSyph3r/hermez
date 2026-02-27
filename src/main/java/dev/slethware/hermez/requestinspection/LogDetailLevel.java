package dev.slethware.hermez.requestinspection;

public enum LogDetailLevel {
    BASIC,
    FULL;

    public String value() {
        return name().toLowerCase();
    }
}