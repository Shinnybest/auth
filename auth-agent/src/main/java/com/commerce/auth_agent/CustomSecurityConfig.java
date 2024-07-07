package com.commerce.auth_agent;

import com.commerce.auth_agent.authentication.after.AuthenticationSuccessHandler;
import com.commerce.auth_agent.authorization.after.HttpCookieOAuth2AuthorizationRequestRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@RequiredArgsConstructor
public class CustomSecurityConfig {

    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final HttpCookieOAuth2AuthorizationRequestRepository authorizationRequestRepository;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .oauth2Login(oauth2 -> oauth2
                .authorizationEndpoint(endpoint -> endpoint
                        .authorizationRequestRepository(authorizationRequestRepository))
                .successHandler(authenticationSuccessHandler));

        return http.build();
    }
}
