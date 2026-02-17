package dev.slethware.hermez.tunnel;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.Disposable;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Component
public class HeartbeatManager {

    private static final Duration PING_INTERVAL  = Duration.ofSeconds(5);
    private static final Duration PONG_DEADLINE  = Duration.ofSeconds(3);

    private final ConcurrentHashMap<String, Disposable> tasks = new ConcurrentHashMap<>();

    public void start(String subdomain, TunnelConnection connection, TunnelRegistry registry) {
        Disposable task = Flux.interval(PING_INTERVAL)
                .flatMap(tick -> {
                    // Record the time the PING was sent
                    long pingSentAt = System.currentTimeMillis();
                    // send PING
                    connection.sendPing();
                    log.debug("PING sent to tunnel: {}", subdomain);

                    return Mono.delay(PONG_DEADLINE)
                            .flatMap(ignored -> {
                                // After 3 seconds, check if a PONG arrived since the PING
                                boolean pongReceived = connection.getLastPongTime() >= pingSentAt;
                                if (!pongReceived) {
                                    // If not, close the connection (dead client)
                                    log.warn("Pong timeout for tunnel: {} — closing connection", subdomain);
                                    return connection.close();
                                }
                                // If yes, refresh the Redis TTL
                                log.debug("Pong confirmed for tunnel: {}, refreshing TTL", subdomain);
                                return registry.refreshTtl(subdomain);
                            });
                })
                .doOnError(e -> log.error("Heartbeat error for tunnel {}: {}", subdomain, e.getMessage()))
                .subscribe();

        tasks.put(subdomain, task);
        log.debug("Heartbeat started for tunnel: {}", subdomain);
    }

    public void stop(String subdomain) {
        Disposable task = tasks.remove(subdomain);
        if (task != null && !task.isDisposed()) {
            task.dispose();
            log.debug("Heartbeat stopped for tunnel: {}", subdomain);
        }
    }
}