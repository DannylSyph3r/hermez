package dev.slethware.hermez.apikey;

import java.util.UUID;

public record ApiKeyPrincipal(UUID userId, String tier) {}