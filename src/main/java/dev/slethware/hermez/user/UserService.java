package dev.slethware.hermez.user;

import dev.slethware.hermez.auth.api.UserResponse;
import dev.slethware.hermez.user.api.ChangePasswordRequest;
import dev.slethware.hermez.user.api.UpdateAvatarRequest;
import dev.slethware.hermez.user.api.UpdateNameRequest;
import reactor.core.publisher.Mono;

public interface UserService {

    Mono<UserResponse> getCurrentUser();
    Mono<UserResponse> updateName(UpdateNameRequest request);
    Mono<UserResponse> updateAvatar(UpdateAvatarRequest request);
    Mono<Void> changePassword(ChangePasswordRequest request);
    Mono<Void> deleteAccount();
}