package dev.slethware.hermez.exception;

import dev.slethware.hermez.common.models.response.ErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.support.WebExchangeBindException;
import reactor.core.publisher.Mono;

import java.util.stream.Collectors;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(BadRequestException.class)
    public Mono<ResponseEntity<ErrorResponse>> handleBadRequestException(BadRequestException e) {
        log.error("Bad request: {}", e.getMessage(), e);

        ErrorResponse response = ErrorResponse.builder()
                .message(e.getMessage())
                .error("Bad Request")
                .statusCode(HttpStatus.BAD_REQUEST.value())
                .build();

        return Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response));
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public Mono<ResponseEntity<ErrorResponse>> handleResourceNotFoundException(ResourceNotFoundException e) {
        log.error("Resource not found: {}", e.getMessage(), e);

        ErrorResponse response = ErrorResponse.builder()
                .message(e.getMessage())
                .error("Not Found")
                .statusCode(HttpStatus.NOT_FOUND.value())
                .build();

        return Mono.just(ResponseEntity.status(HttpStatus.NOT_FOUND).body(response));
    }

    @ExceptionHandler(UnauthorizedException.class)
    public Mono<ResponseEntity<ErrorResponse>> handleUnauthorizedException(UnauthorizedException e) {
        log.error("Unauthorized: {}", e.getMessage(), e);

        ErrorResponse response = ErrorResponse.builder()
                .message(e.getMessage())
                .error("Unauthorized")
                .statusCode(HttpStatus.UNAUTHORIZED.value())
                .build();

        return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response));
    }

    @ExceptionHandler(ForbiddenException.class)
    public Mono<ResponseEntity<ErrorResponse>> handleForbiddenException(ForbiddenException e) {
        log.error("Forbidden: {}", e.getMessage());

        ErrorResponse response = ErrorResponse.builder()
                .message(e.getMessage())
                .error("Forbidden")
                .statusCode(HttpStatus.FORBIDDEN.value())
                .build();

        return Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).body(response));
    }

    @ExceptionHandler(TooManyRequestsException.class)
    public Mono<ResponseEntity<ErrorResponse>> handleTooManyRequestsException(TooManyRequestsException e) {
        log.warn("Rate limit exceeded: {}", e.getMessage());

        ErrorResponse response = ErrorResponse.builder()
                .message(e.getMessage())
                .error("Too Many Requests")
                .statusCode(HttpStatus.TOO_MANY_REQUESTS.value())
                .build();

        return Mono.just(ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(response));
    }

    @ExceptionHandler(InternalServerException.class)
    public Mono<ResponseEntity<ErrorResponse>> handleInternalServerException(InternalServerException e) {
        log.error("Internal server error: {}", e.getMessage(), e);

        ErrorResponse response = ErrorResponse.builder()
                .message("Internal server error")
                .error("Internal Server Error")
                .statusCode(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .build();

        return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response));
    }

    @ExceptionHandler(WebExchangeBindException.class)
    public Mono<ResponseEntity<ErrorResponse>> handleValidationException(WebExchangeBindException ex) {
        log.error("Validation error: {}", ex.getMessage());

        String errorMessage = ex.getBindingResult().getFieldErrors().stream()
                .map(DefaultMessageSourceResolvable::getDefaultMessage)
                .collect(Collectors.joining("; "));

        ErrorResponse response = ErrorResponse.builder()
                .message(errorMessage)
                .error("Validation Failed")
                .statusCode(HttpStatus.BAD_REQUEST.value())
                .build();

        return Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response));
    }

    @ExceptionHandler(Exception.class)
    public Mono<ResponseEntity<ErrorResponse>> handleUnexpectedException(Exception ex) {
        log.error("Unexpected error occurred: {}", ex.getMessage(), ex);

        ErrorResponse response = ErrorResponse.builder()
                .message("An unexpected error occurred")
                .error("Internal Server Error")
                .statusCode(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .build();

        return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response));
    }
}