package com.common.resourceserver.service.impl;

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

import java.util.HashMap;

import static com.common.rest.response.CommonErrorCode.INVALID_TOKEN;

@Log4j2
@RequiredArgsConstructor
@Service
public class TokenServiceImpl implements TokenService {

    private final CustomRestTemplate customRestTemplate;

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.introspection-uri}")
    private String introspectionUri;

    /**
     * get token from authorization server
     *
     * @param user User dto
     * @param authorization Basic auth
     * @return Token
     */
    @Override
    public Token getToken(User user, String authorization) {
        log.info("call authorization service to get token for username: {}", user.getUsername());
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("username", user.getUsername());
        form.add("password", user.getPassword());
        return customRestTemplate.post(this.introspectionUri + "/oauth/token", form, new ParameterizedTypeReference<>() {},
                new HashMap<>(), createHeader(authorization));
    }

    /**
     * call authorizations server for revoke token
     * @param token token to revoke
     */
    @Override
    public void revokeToken(String token) {
        log.info("call authorization service to revoke token: {}", token);
        customRestTemplate.delete(this.introspectionUri + "/oauth/token/revoke/" +  token, new ParameterizedTypeReference<>() {
        }, new HashMap<>());
    }

    /**
     * call authorization server for refresh token
     * @param refreshToken refresh token
     * @return new Token
     */
    @Override
    public Token refreshToken(String refreshToken, String authorization) {
        log.info("call authorization service to refresh token refreshToken: {}", refreshToken);
        try{
            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("grant_type", "refresh_token");
            form.add("refresh_token", refreshToken);
            return customRestTemplate.post(this.introspectionUri + "/oauth/token", form, new ParameterizedTypeReference<>() {},
                    new HashMap<>(), createHeader(authorization));
        } catch (Exception e) {
            log.error("refresh token fail: " + e.getMessage(), e);
            throw new CommonException(HttpStatus.UNAUTHORIZED, INVALID_TOKEN.getCode(), INVALID_TOKEN.getMessage());
        }
    }

    private HttpHeaders createHeader(String authorization) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth(authorization);
        return headers;
    }
}
