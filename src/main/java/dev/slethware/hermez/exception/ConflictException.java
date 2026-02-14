package dev.slethware.hermez.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
public class ConflictException extends RuntimeException {

    public ConflictException() {
        super("Resource conflict");
    }

    public ConflictException(String message) {
        super(message);
    }
}