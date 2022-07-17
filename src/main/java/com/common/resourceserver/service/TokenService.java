package com.common.resourceserver.service;


import com.common.resourceserver.dto.Token;
import com.common.resourceserver.dto.User;

public interface TokenService {

    Token getToken(User user, String authorization);

    void revokeToken(String token);

    Token refreshToken(String refreshToken, String authorization);
}
