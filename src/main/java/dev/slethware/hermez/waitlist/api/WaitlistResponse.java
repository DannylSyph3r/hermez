package dev.slethware.hermez.waitlist.api;

public record WaitlistResponse(
        String email,
        String message
) {}