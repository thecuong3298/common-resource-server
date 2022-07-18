package com.common.resourceserver.controller;

import com.common.resourceserver.config.CorsProperties;
import com.common.resourceserver.dto.Token;
import com.common.resourceserver.dto.User;
import com.common.resourceserver.service.TokenService;
import com.common.rest.error.CommonException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.apache.logging.log4j.util.Strings;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.WebUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static com.common.rest.response.CommonErrorCode.INVALID_TOKEN;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.ACCESS_TOKEN;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.REFRESH_TOKEN;

@Log4j2
@Tag(name = "Authentication")
@RequiredArgsConstructor
@RestController
@RequestMapping("oauth")
public class TokenController {

    private final TokenService tokenService;

    private final CorsProperties corsProperties;

    @Operation(summary = "Create token (Auto set cookie with http only)")
    @PostMapping(value = "token")
    public Token getToken(
            HttpServletRequest request, HttpServletResponse response,
            @RequestBody User user) {
        Token token = tokenService.getToken(user, request.getHeader("Authorization"));
        setCookie(response, token);
        return token;
    }

    private void setCookie(HttpServletResponse response, Token token) {
        String cookie = "%s=%s; Path=/; Max-Age=%s; HttpOnly; SameSite=None; Secure=%s";
        response.addHeader(HttpHeaders.SET_COOKIE,
                String.format(cookie, ACCESS_TOKEN, token.getAccessToken(), token.getExpiresIn(), corsProperties.getCookieSecure()));
        response.addHeader(HttpHeaders.SET_COOKIE,
                String.format(cookie, REFRESH_TOKEN, token.getRefreshToken(), token.getRefreshTokenExpiresIn(), corsProperties.getCookieSecure()));
    }

    @Operation(summary = "Refresh token (Auto set cookie with http only)")
    @PostMapping("token/refresh")
    public Token refreshToken(HttpServletRequest request, HttpServletResponse response,
                              @Parameter(schema = @Schema(description = "refresh token", example = "132asd4f65asd1f2"), required = true)
                              @RequestParam("refresh_token") String refreshToken) {
        if (Strings.isBlank(refreshToken)) {
            Cookie cookie = WebUtils.getCookie(request, REFRESH_TOKEN);
            if (cookie == null) {
                log.error("can't found refresh token");
                throw new CommonException(HttpStatus.UNAUTHORIZED, INVALID_TOKEN.getCode(), INVALID_TOKEN.getMessage());
            }
            refreshToken = cookie.getValue();
        }
        Token token = tokenService.refreshToken(refreshToken, request.getHeader("Authorization"));
        setCookie(response, token);
        return token;
    }

    @Operation(summary = "Revoke token")
    @DeleteMapping("revoke/{token:.*}")
    public void getToken(HttpServletRequest request,
                         @Parameter(schema = @Schema(description = "Token", example = "132asd4f65asd1f2"))
                         @PathVariable("token") String token) {
        if (Strings.isBlank(token)) {
            Cookie cookie = WebUtils.getCookie(request, ACCESS_TOKEN);
            if (cookie == null) {
                log.error("can't found access token");
                throw new CommonException(HttpStatus.UNAUTHORIZED, INVALID_TOKEN.getCode(), INVALID_TOKEN.getMessage());
            }
            token = cookie.getValue();
        }
        tokenService.revokeToken(token);
    }
}
