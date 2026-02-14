package dev.slethware.hermez.subdomain.validation;

import java.util.UUID;

public sealed interface ValidationResult {

    record Valid(String subdomain) implements ValidationResult {}
    record InvalidFormat(String subdomain, String reason) implements ValidationResult {}
    record Blocked(String subdomain) implements ValidationResult {}
    record InUse(String subdomain, UUID ownerId) implements ValidationResult {}
    record Reserved(String subdomain, UUID ownerId) implements ValidationResult {}
}