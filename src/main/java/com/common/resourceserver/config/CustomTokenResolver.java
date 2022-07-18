package com.common.resourceserver.config;


import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.util.StringUtils;
import org.springframework.web.util.WebUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@NoArgsConstructor
public final class CustomTokenResolver implements BearerTokenResolver {
    private static final Pattern authorizationPattern = Pattern.compile("^Bearer (?<token>[a-zA-Z0-9-._~+/]+=*)$", 2);
    private boolean allowFormEncodedBodyParameter = false;
    private boolean allowUriQueryParameter = false;
    private String bearerTokenHeaderName = "Authorization";

    public String resolve(final HttpServletRequest request) {
        String authorizationHeaderToken = this.resolveFromAuthorizationHeader(request);
        String parameterToken = this.isParameterTokenSupportedForRequest(request) ? resolveFromRequestParameters(request) : null;
        if (authorizationHeaderToken != null) {
            if (parameterToken != null) {
                BearerTokenError error = BearerTokenErrors.invalidRequest("Found multiple bearer tokens in the request");
                throw new OAuth2AuthenticationException(error);
            } else {
                return authorizationHeaderToken;
            }
        } else {
            return parameterToken != null && this.isParameterTokenEnabledForRequest(request) ? parameterToken : null;
        }
    }

    public void setAllowFormEncodedBodyParameter(boolean allowFormEncodedBodyParameter) {
        this.allowFormEncodedBodyParameter = allowFormEncodedBodyParameter;
    }

    public void setAllowUriQueryParameter(boolean allowUriQueryParameter) {
        this.allowUriQueryParameter = allowUriQueryParameter;
    }

    public void setBearerTokenHeaderName(String bearerTokenHeaderName) {
        this.bearerTokenHeaderName = bearerTokenHeaderName;
    }

    private String resolveFromAuthorizationHeader(HttpServletRequest request) {
        String authorization = request.getHeader(this.bearerTokenHeaderName);
        if (authorization == null) {
            Cookie cookie = WebUtils.getCookie(request, "access_token");
            return cookie != null ? cookie.getValue() : null;
        }
        if (!StringUtils.startsWithIgnoreCase(authorization, "bearer")) {
            return null;
        } else {
            Matcher matcher = authorizationPattern.matcher(authorization);
            if (!matcher.matches()) {
                BearerTokenError error = BearerTokenErrors.invalidToken("Bearer token is malformed");
                throw new OAuth2AuthenticationException(error);
            } else {
                return matcher.group("token");
            }
        }
    }

    private static String resolveFromRequestParameters(HttpServletRequest request) {
        String[] values = request.getParameterValues("access_token");
        if (values != null && values.length != 0) {
            if (values.length == 1) {
                return values[0];
            } else {
                BearerTokenError error = BearerTokenErrors.invalidRequest("Found multiple bearer tokens in the request");
                throw new OAuth2AuthenticationException(error);
            }
        } else {
            return null;
        }
    }

    private boolean isParameterTokenSupportedForRequest(final HttpServletRequest request) {
        return "POST".equals(request.getMethod()) && "application/x-www-form-urlencoded".equals(request.getContentType()) || "GET".equals(request.getMethod());
    }

    private boolean isParameterTokenEnabledForRequest(final HttpServletRequest request) {
        return this.allowFormEncodedBodyParameter && "POST".equals(request.getMethod()) && "application/x-www-form-urlencoded".equals(request.getContentType()) || this.allowUriQueryParameter && "GET".equals(request.getMethod());
    }
}
