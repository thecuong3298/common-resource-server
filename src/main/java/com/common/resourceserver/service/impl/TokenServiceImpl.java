package com.common.resourceserver.service.impl;

import com.common.resourceserver.config.CorsProperties;
import com.common.resourceserver.dto.Token;
import com.common.resourceserver.dto.User;
import com.common.resourceserver.service.TokenService;
import com.common.rest.CustomRestTemplate;
import com.common.rest.error.CommonException;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;

import static com.common.rest.response.CommonErrorCode.INVALID_TOKEN;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.ACCESS_TOKEN;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.REFRESH_TOKEN;

@Log4j2
@RequiredArgsConstructor
@Service
public class TokenServiceImpl implements TokenService {

    private final CustomRestTemplate customRestTemplate;

    private final CorsProperties corsProperties;

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.introspection-uri}")
    private String introspectionUri;

    /**
     * get token from authorization server
     *
     * @param user          User dto
     * @param authorization Basic auth
     * @param response      HttpServletResponse
     * @return Token
     */
    @Override
    public Token getToken(User user, String authorization, HttpServletResponse response) {
        log.info("call authorization service to get token for username: {}", user.getUsername());
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("username", user.getUsername());
        form.add("password", user.getPassword());
        Token token = customRestTemplate.post(this.introspectionUri + "/oauth/token", form, new ParameterizedTypeReference<>() {
                },
                new HashMap<>(), createHeader(authorization));
        this.setCookie(response, token);
        return token;
    }

    /**
     * call authorization server for refresh token
     *
     * @param refreshToken refresh token
     * @param response     HttpServletResponse
     * @return new Token
     */
    @Override
    public Token refreshToken(String refreshToken, String authorization, HttpServletResponse response) {
        log.info("call authorization service to refresh token refreshToken: {}", refreshToken);
        try {
            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("grant_type", "refresh_token");
            form.add("refresh_token", refreshToken);
            Token token = customRestTemplate.post(this.introspectionUri + "/oauth/token", form, new ParameterizedTypeReference<>() {
                    },
                    new HashMap<>(), createHeader(authorization));
            this.setCookie(response, token);
            return token;
        } catch (Exception e) {
            log.error("refresh token fail: " + e.getMessage(), e);
            throw new CommonException(HttpStatus.UNAUTHORIZED, INVALID_TOKEN.getCode(), INVALID_TOKEN.getMessage());
        }
    }

    /**
     * call authorizations server for revoke token
     *
     * @param token    token to revoke
     * @param response HttpServletResponse
     */
    @Override
    public void revokeToken(String token, HttpServletResponse response) {
        log.info("call authorization service to revoke token: {}", token);
        customRestTemplate.delete(this.introspectionUri + "/oauth/token/revoke/" + token, new ParameterizedTypeReference<>() {
        }, new HashMap<>());
        this.setCookie(response, new Token(), true);
    }

    private void setCookie(HttpServletResponse response, Token token) {
        this.setCookie(response, token, false);
    }

    private void setCookie(HttpServletResponse response, Token token, boolean clear) {
        String cookie = "%s=%s; Path=/; Max-Age=%s; HttpOnly; SameSite=None; Secure=%s";
        response.addHeader(HttpHeaders.SET_COOKIE,
                String.format(cookie, ACCESS_TOKEN, token.getAccessToken(), clear ? 0 : token.getExpiresIn(), corsProperties.getCookieSecure()));
        response.addHeader(HttpHeaders.SET_COOKIE,
                String.format(cookie, REFRESH_TOKEN, token.getRefreshToken(), clear ? 0 : token.getRefreshTokenExpiresIn(), corsProperties.getCookieSecure()));
    }

    private HttpHeaders createHeader(String authorization) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("authorization", authorization);
        return headers;
    }
}
