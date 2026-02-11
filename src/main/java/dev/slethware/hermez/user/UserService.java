package dev.slethware.hermez.user;

import dev.slethware.hermez.user.api.ChangePasswordRequest;
import dev.slethware.hermez.user.api.UpdateAvatarRequest;
import dev.slethware.hermez.user.api.UpdateNameRequest;
import dev.slethware.hermez.user.api.UserProfileResponse;
import reactor.core.publisher.Mono;

public interface UserService {

    Mono<UserProfileResponse> getCurrentUser();
    Mono<UserProfileResponse> updateName(UpdateNameRequest request);
    Mono<UserProfileResponse> updateAvatar(UpdateAvatarRequest request);
    Mono<Void> changePassword(ChangePasswordRequest request);
    Mono<Void> disconnectOAuth(String provider);
    Mono<Void> deleteAccount();
}