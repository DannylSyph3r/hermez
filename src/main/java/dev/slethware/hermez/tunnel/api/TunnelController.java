package dev.slethware.hermez.tunnel.api;

import dev.slethware.hermez.common.models.response.ApiResponse;
import dev.slethware.hermez.common.util.ApiResponseUtil;
import dev.slethware.hermez.common.util.SecurityContextUtil;
import dev.slethware.hermez.tunnel.TunnelService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/v1/tunnels")
@RequiredArgsConstructor
@Tag(name = "Tunnel Management", description = "Active tunnel listing and management endpoints")
public class TunnelController {

    private final TunnelService tunnelService;

    @GetMapping
    @Operation(
            summary = "List active tunnels",
            description = "Retrieves all active tunnels for the authenticated user with tier limits"
    )
    public Mono<ApiResponse<TunnelListResponse>> listTunnels() {
        return SecurityContextUtil.getCurrentUserId()
                .flatMap(tunnelService::listTunnels)
                .map(response -> ApiResponseUtil.successFull("Tunnels retrieved successfully", response));
    }

    @DeleteMapping("/{tunnelId}")
    @Operation(
            summary = "Force close a tunnel",
            description = "Sends a TUNNEL_CLOSE message to the CLI and terminates the connection"
    )
    public Mono<ApiResponse<Void>> closeTunnel(@PathVariable UUID tunnelId) {
        return SecurityContextUtil.getCurrentUserId()
                .flatMap(userId -> tunnelService.closeTunnel(tunnelId, userId))
                .then(Mono.fromCallable(() -> ApiResponseUtil.successFullVoid("Tunnel closed successfully")));
    }
}