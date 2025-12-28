package dev.slethware.hermez.exception;

import dev.slethware.hermez.common.models.response.ErrorResponse;
import lombok.extern.slf4j.Slf4j;
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
        log.error(e.getMessage(), e);

        ErrorResponse response = ErrorResponse.builder()
                .message(e.getMessage())
                .error("Bad Request")
                .statusCode(HttpStatus.BAD_REQUEST.value())
                .build();

        return Mono.just(new ResponseEntity<>(response, HttpStatus.BAD_REQUEST));
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public Mono<ResponseEntity<ErrorResponse>> handleResourceNotFoundException(ResourceNotFoundException e) {
        log.error(e.getMessage(), e);

        ErrorResponse response = ErrorResponse.builder()
                .message(e.getMessage())
                .error("Not Found")
                .statusCode(HttpStatus.NOT_FOUND.value())
                .build();

        return Mono.just(new ResponseEntity<>(response, HttpStatus.NOT_FOUND));
    }

    @ExceptionHandler(UnauthorizedException.class)
    public Mono<ResponseEntity<ErrorResponse>> handleUnauthorizedException(UnauthorizedException ex) {
        log.error(ex.getMessage(), ex);

        ErrorResponse response = ErrorResponse.builder()
                .message(ex.getMessage())
                .error("Unauthorized")
                .statusCode(HttpStatus.UNAUTHORIZED.value())
                .build();

        return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response));
    }

    @ExceptionHandler(InternalServerException.class)
    public Mono<ResponseEntity<ErrorResponse>> handleInternalServerException(InternalServerException e) {
        log.error(e.getMessage(), e);

        ErrorResponse response = ErrorResponse.builder()
                .message("Internal server error")
                .error("Internal Server Error")
                .statusCode(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .build();

        return Mono.just(new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR));
    }

    @ExceptionHandler(WebExchangeBindException.class)
    public Mono<ResponseEntity<ErrorResponse>> handleValidationException(WebExchangeBindException ex) {
        log.error("Validation error: {}", ex.getMessage());

        String errorMessage = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getDefaultMessage())
                .collect(Collectors.joining("; "));

        ErrorResponse response = ErrorResponse.builder()
                .message(errorMessage)
                .error("Validation Failed")
                .statusCode(HttpStatus.BAD_REQUEST.value())
                .build();

        return Mono.just(new ResponseEntity<>(response, HttpStatus.BAD_REQUEST));
    }

    @ExceptionHandler(Exception.class)
    public Mono<ResponseEntity<ErrorResponse>> handleUnpredictableException(Exception ex) {
        log.error(ex.getMessage(), ex);

        ErrorResponse response = ErrorResponse.builder()
                .message("An unexpected error occurred")
                .error("Internal Server Error")
                .statusCode(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .build();

        return Mono.just(new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR));
    }
}