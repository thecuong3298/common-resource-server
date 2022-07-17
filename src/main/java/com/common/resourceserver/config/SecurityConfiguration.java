package com.common.resourceserver.config;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.CollectionUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.servlet.http.HttpServletResponse;
import java.util.List;


@Configuration
@EnableWebSecurity
@Order(SecurityProperties.BASIC_AUTH_ORDER)
@RequiredArgsConstructor
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final OpaqueTokenIntrospector introspection;

    private final CorsProperties corsProperties;

    private final CustomSecurityProperties customSecurityProperties;

    private final BearerTokenResolver bearerTokenResolver;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        List<String> permitPatterns = customSecurityProperties.getPermitPattern();
        if (!CollectionUtils.isEmpty(permitPatterns)) {
            for (String pattern : permitPatterns) {
                http.authorizeRequests().antMatchers(pattern).permitAll();
            }
        }
        http.authorizeRequests()
                .antMatchers("/oauth/**").permitAll()
                .antMatchers("/v3/api-docs/**").permitAll()
                .antMatchers("/swagger-ui.html").permitAll()
                .antMatchers("/swagger-ui/**").permitAll()
                .anyRequest().authenticated();
        http.csrf().disable()
                .cors()
                .and().sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(resourceServerConfigurer -> {
                    resourceServerConfigurer.authenticationEntryPoint(unauthorizedEntryPoint());
                    resourceServerConfigurer.bearerTokenResolver(bearerTokenResolver);
                    resourceServerConfigurer.opaqueToken(configurer -> configurer.introspector(introspection));
                });
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(corsProperties.getAllowedOrigins());
        configuration.setAllowedOriginPatterns(corsProperties.getAllowedOriginPatterns());
        configuration.setAllowedMethods(corsProperties.getAllowedMethods());
        configuration.setAllowedHeaders(corsProperties.getAllowedHeaders());
        configuration.setAllowCredentials(corsProperties.getAllowCredentials());
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        List<String> sourcesRegisters = corsProperties.getSourceRegister();
        if (!CollectionUtils.isEmpty(sourcesRegisters))
            sourcesRegisters.forEach(sourcesRegister -> source.registerCorsConfiguration(sourcesRegister, configuration));
        return source;
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManager() {
        return new BasedAuthenticationManager();
    }

    @Bean
    public AuthenticationEntryPoint unauthorizedEntryPoint() {
        return (request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED, HttpStatus.UNAUTHORIZED.getReasonPhrase());
    }


}
