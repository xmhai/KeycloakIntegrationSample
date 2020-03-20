package com.cl.stlucia.portal;

import java.io.IOException;
import java.util.List;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationSuccessHandler;
import org.keycloak.adapters.springsecurity.authentication.KeycloakCookieBasedRedirect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

// This is an example class to override KeycloakAuthenticationSuccessHandler
// in security context, set the successHandler to this class
//<bean id="keycloakAuthenticationProcessingFilter" class="org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticationProcessingFilter">
//<constructor-arg name="authenticationManager" ref="authenticationManager" />
//<property name="authenticationSuccessHandler" ref="keycloakSuccessHandler" />
//</bean>
//<bean id="keycloakSuccessHandler" class="com.cl.stlucia.portal.MyKeycloakAuthenticationSuccessHandler"/>

public class MyKeycloakAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger LOG = LoggerFactory.getLogger(KeycloakAuthenticationSuccessHandler.class);

    private final AuthenticationSuccessHandler fallback;

    public MyKeycloakAuthenticationSuccessHandler() {
        this.fallback = new SavedRequestAwareAuthenticationSuccessHandler();
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
    	// TO-DO
    	//((List<SimpleGrantedAuthority>)authentication.getAuthorities()).add(new SimpleGrantedAuthority("TEST"));
        Set<String> roles = AuthorityUtils.authorityListToSet(authentication.getAuthorities());
        System.out.println(roles);
        
        String location = KeycloakCookieBasedRedirect.getRedirectUrlFromCookie(request);
        if (location == null) {
            if (fallback != null) {
                fallback.onAuthenticationSuccess(request, response, authentication);
            }
        } else {
            try {
                response.addCookie(KeycloakCookieBasedRedirect.createCookieFromRedirectUrl(null));
                response.sendRedirect(location);
            } catch (IOException e) {
                LOG.warn("Unable to redirect user after login", e);
            }
        }
    }
}
