package dev.slethware.hermez.waitlist;

import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Repository
public interface WaitlistRepository extends ReactiveCrudRepository<Waitlist, UUID> {

    Mono<Boolean> existsByEmail(String email);
}