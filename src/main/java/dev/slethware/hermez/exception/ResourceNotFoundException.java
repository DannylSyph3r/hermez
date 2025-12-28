package dev.slethware.hermez.exception;

import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@Getter
@Setter
@ResponseStatus(HttpStatus.NOT_FOUND)
public class ResourceNotFoundException extends RuntimeException {

  private HttpStatus status = HttpStatus.NOT_FOUND;

  public ResourceNotFoundException(String message) {
    super(message);
  }
}