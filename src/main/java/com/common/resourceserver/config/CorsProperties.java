package com.common.resourceserver.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.Collections;
import java.util.List;

@Data
@Configuration
@ConfigurationProperties(prefix = "cors")
public class CorsProperties {

    private List<String> allowedOrigins = Collections.singletonList("*");

    private List<String> allowedOriginPatterns;

    private List<String> allowedMethods = Collections.singletonList("*");

    private List<String> allowedHeaders = Collections.singletonList("*");

    private List<String> sourceRegister = Collections.singletonList("/**");
}
