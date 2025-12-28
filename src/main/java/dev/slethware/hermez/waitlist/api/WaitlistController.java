package dev.slethware.hermez.waitlist.api;

import dev.slethware.hermez.common.models.response.ApiResponse;
import dev.slethware.hermez.common.util.ApiResponseUtil;
import dev.slethware.hermez.waitlist.WaitlistService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/v1/waitlist")
@RequiredArgsConstructor
@Tag(name = "Waitlist", description = "Waitlist management endpoints")
public class WaitlistController {

    private final WaitlistService waitlistService;

    @PostMapping("/subscribe")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(
            summary = "Subscribe to the waitlist",
            description = "Registers a user for the waitlist. Validates email and sends confirmation. Returns confirmation details."
    )
    @io.swagger.v3.oas.annotations.responses.ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "201", description = "Successfully subscribed to waitlist"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Invalid request data or email already registered"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "500", description = "Internal server error")
    })
    public Mono<ApiResponse<WaitlistResponse>> subscribe(@Valid @RequestBody WaitlistRequest request) {
        return waitlistService.register(request)
                .map(response -> ApiResponseUtil.created("Confirmation successful", response));
    }
}