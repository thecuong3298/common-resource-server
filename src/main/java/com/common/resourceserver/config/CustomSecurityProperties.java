package com.common.resourceserver.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Data
@Configuration
@ConfigurationProperties(prefix = "spring.security.oauth2")
public class CustomSecurityProperties {

    /**
     * configure the authorization so that all requests are allowed on that particular path
     */
    private List<String> permitPattern;
}
