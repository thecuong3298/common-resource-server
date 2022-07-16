package com.common.resourceserver.config;

import com.common.dto.ResponseWrapper;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import static com.common.rest.response.CommonErrorCode.FORBIDDEN;

@Log4j2
@RestControllerAdvice
public class ResourceServerControllerAdvice {

    @ResponseStatus(value = HttpStatus.FORBIDDEN)
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseWrapper<Object> handleAuthorizationException(AccessDeniedException ex) {
        log.error("Authorization Error: ", ex);
        return new ResponseWrapper<>(FORBIDDEN);
    }
}
