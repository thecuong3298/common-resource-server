package com.common.resourceserver.service;


import com.common.resourceserver.dto.Token;
import com.common.resourceserver.dto.User;

import javax.servlet.http.HttpServletResponse;

public interface TokenService {

    Token getToken(User user, String authorization, HttpServletResponse response);

    void revokeToken(String token, HttpServletResponse response);

    Token refreshToken(String refreshToken, String authorization, HttpServletResponse response);
}
