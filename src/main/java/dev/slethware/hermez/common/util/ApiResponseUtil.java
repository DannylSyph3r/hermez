package dev.slethware.hermez.common.util;

import dev.slethware.hermez.common.models.response.ApiResponse;
import org.springframework.http.HttpStatus;

public class ApiResponseUtil {

    private ApiResponseUtil() {}

    public static <T> ApiResponse<T> created(String message, T data) {
        return ApiResponse.<T>builder()
                .message(message)
                .statusCode(HttpStatus.CREATED.value())
                .isSuccessful(true)
                .data(data)
                .build();
    }

    public static ApiResponse<Void> createdVoid(String message) {
        return ApiResponse.<Void>builder()
                .message(message)
                .statusCode(HttpStatus.CREATED.value())
                .isSuccessful(true)
                .build();
    }

    public static <T> ApiResponse<T> successFull(String message, T data) {
        return ApiResponse.<T>builder()
                .message(message)
                .statusCode(HttpStatus.OK.value())
                .isSuccessful(true)
                .data(data)
                .build();
    }

    public static ApiResponse<Void> successFullVoid(String message) {
        return ApiResponse.<Void>builder()
                .message(message)
                .statusCode(HttpStatus.OK.value())
                .isSuccessful(true)
                .build();
    }

    public static int noContent() {
        return HttpStatus.NO_CONTENT.value();
    }
}