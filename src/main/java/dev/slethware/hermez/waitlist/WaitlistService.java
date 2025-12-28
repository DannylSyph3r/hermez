package dev.slethware.hermez.waitlist;

import dev.slethware.hermez.waitlist.api.WaitlistRequest;
import dev.slethware.hermez.waitlist.api.WaitlistResponse;
import reactor.core.publisher.Mono;

public interface WaitlistService {

    Mono<WaitlistResponse> register(WaitlistRequest request);
}