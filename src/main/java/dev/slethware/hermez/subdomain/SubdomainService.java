package dev.slethware.hermez.subdomain;

import dev.slethware.hermez.subdomain.api.AvailabilityResponse;
import dev.slethware.hermez.subdomain.api.SubdomainListResponse;
import dev.slethware.hermez.subdomain.api.SubdomainResponse;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface SubdomainService {

    Mono<SubdomainResponse> reserveSubdomain(String subdomain, UUID userId);
    Mono<SubdomainListResponse> getReservations(UUID userId);
    Mono<Void> releaseSubdomain(String subdomain, UUID userId);
    Mono<AvailabilityResponse> checkAvailability(String subdomain, UUID userId);
}