package com.commerce.auth_agent.authentication.after;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @Value("${spring.security.oauth2.client.registration.shinnybest.client-id}")
    private String clientId;

    public AuthenticationSuccessHandler() {
        super();
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        var client = authorizedClientService.loadAuthorizedClient(clientId, authentication.getName());
        OAuth2AccessToken accessToken = client.getAccessToken();
        DefaultOidcUser user = (DefaultOidcUser) authentication.getPrincipal();
        OidcIdToken idToken = user.getIdToken();
        String idTokenValue = idToken.getTokenValue();
        response.addHeader("Set-Cookie", "access_token=" + accessToken.getTokenValue() + "; Path=/; HttpOnly; Secure; SameSite=None");
        response.addHeader("Set-Cookie", "id_token=" + idTokenValue + "; Path=/; HttpOnly; Secure; SameSite=None");
        super.onAuthenticationSuccess(request, response, authentication);
    }
}
