package dev.slethware.hermez.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.TOO_MANY_REQUESTS)
public class TooManyRequestsException extends RuntimeException {

    public TooManyRequestsException() {
        super("Too many requests. Please try again later.");
    }

    public TooManyRequestsException(String message) {
        super(message);
    }
}