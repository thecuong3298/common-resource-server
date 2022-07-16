package com.common.resourceserver.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
public class CommonIntrospector {

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.introspection-uri}")
    private String introspectionUri;

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-secret}")
    private String clientSecret;

    @Bean
    public OpaqueTokenIntrospector introspection() {
        OpaqueTokenIntrospector delegate = new NimbusOpaqueTokenIntrospector(this.introspectionUri, this.clientId, this.clientSecret);

        return token -> {
            OAuth2AuthenticatedPrincipal principal = delegate.introspect(token);
            List<String> authorities = principal.getAttribute("authorities");
            if (authorities == null) authorities = new ArrayList<>();
            return new DefaultOAuth2AuthenticatedPrincipal(
                    principal.getAttribute("user_name"), principal.getAttributes(), authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet()));
        };
    }
}
