package com.phishguard.exception;

import com.phishguard.dto.ApiResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.server.ResponseStatusException;
import jakarta.servlet.http.HttpServletRequest;

import java.util.HashMap;
import java.util.Map;

/**
 * Centralized REST API Exception Handler.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> handleValidationExceptions(
        MethodArgumentNotValidException ex,
        HttpServletRequest request
    ) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error ->
            errors.put(error.getField(), error.getDefaultMessage())
        );
        log.warn("Input validation failed for {}: {}", request.getRequestURI(), errors);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .body(ApiResponse.error("Validation error: " + errors));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiResponse<String>> handleIllegalArgumentException(IllegalArgumentException ex) {
        log.warn("Illegal argument encountered: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .body(ApiResponse.error(ex.getMessage()));
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiResponse<String>> handleAuthenticationException(AuthenticationException ex) {
        log.warn("Authentication failed");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(ApiResponse.error("Authentication required or invalid credentials"));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<String>> handleAccessDeniedException(AccessDeniedException ex) {
        log.warn("Authorization denied");
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body(ApiResponse.error("You do not have permission to perform this operation"));
    }

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<ApiResponse<String>> handleResponseStatusException(
        ResponseStatusException ex
    ) {
        HttpStatus status = HttpStatus.valueOf(ex.getStatusCode().value());
        return ResponseEntity.status(status)
            .body(ApiResponse.error(ex.getReason() == null ? "Request failed" : ex.getReason()));
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ApiResponse<String>> handleNoResourceFoundException() {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
            .body(ApiResponse.error("Resource not found"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<String>> handleGenericException(Exception ex) {
        log.error("Unhandled server error: ", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(ApiResponse.error("An internal security or processing error occurred."));
    }
}
