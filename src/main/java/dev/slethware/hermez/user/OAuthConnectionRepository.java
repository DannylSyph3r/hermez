package dev.slethware.hermez.user;

import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Repository
public interface OAuthConnectionRepository extends ReactiveCrudRepository<OAuthConnection, UUID> {

    Flux<OAuthConnection> findByUserId(UUID userId);
    Mono<OAuthConnection> findByProviderAndProviderId(String provider, String providerId);
    Mono<Boolean> existsByProviderAndProviderId(String provider, String providerId);
    @Query("SELECT * FROM oauth_connections WHERE user_id = :userId AND provider = :provider")
    Mono<OAuthConnection> findByUserIdAndProvider(UUID userId, String provider);
}