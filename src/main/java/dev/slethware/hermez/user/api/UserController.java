package dev.slethware.hermez.user.api;

import dev.slethware.hermez.common.models.response.ApiResponse;
import dev.slethware.hermez.common.util.ApiResponseUtil;
import dev.slethware.hermez.user.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Tag(name = "User Management", description = "User profile and account management endpoints")
public class UserController {

    private final UserService userService;

    @GetMapping("/me")
    @Operation(
            summary = "Get current user profile",
            description = "Retrieves the authenticated user's complete profile"
    )
    public Mono<ApiResponse<UserProfileResponse>> getCurrentUser() {
        return userService.getCurrentUser()
                .map(user -> ApiResponseUtil.successFull("User retrieved successfully", user));
    }

    @PutMapping("/me/name")
    @Operation(
            summary = "Update user name",
            description = "Updates the authenticated user's name"
    )
    public Mono<ApiResponse<UserProfileResponse>> updateName(@Valid @RequestBody UpdateNameRequest request) {
        return userService.updateName(request)
                .map(user -> ApiResponseUtil.successFull("Name updated successfully", user));
    }

    @PutMapping("/me/avatar")
    @Operation(
            summary = "Update user avatar",
            description = "Updates the authenticated user's avatar URL"
    )
    public Mono<ApiResponse<UserProfileResponse>> updateAvatar(@Valid @RequestBody UpdateAvatarRequest request) {
        return userService.updateAvatar(request)
                .map(user -> ApiResponseUtil.successFull("Avatar updated successfully", user));
    }

    @PutMapping("/me/password")
    @Operation(
            summary = "Change password",
            description = "Changes the authenticated user's password. Requires current password for verification. Not available for OAuth-only accounts."
    )
    public Mono<ApiResponse<Void>> changePassword(@Valid @RequestBody ChangePasswordRequest request) {
        return userService.changePassword(request)
                .then(Mono.fromCallable(() -> ApiResponseUtil.successFullVoid("Password changed successfully")));
    }

    @DeleteMapping("/me")
    @Operation(
            summary = "Delete account",
            description = "Soft deletes the authenticated user's account. Account can be recovered by contacting support within 30 days."
    )
    public Mono<ApiResponse<Void>> deleteAccount() {
        return userService.deleteAccount()
                .then(Mono.fromCallable(() -> ApiResponseUtil.successFullVoid(
                        "Account deleted successfully. Contact support within 30 days to recover."
                )));
    }
}