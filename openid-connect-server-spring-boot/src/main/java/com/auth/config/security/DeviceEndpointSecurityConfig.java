package com.auth.config.security;

import static com.auth.util.Constants.ANY;
import static com.auth.util.Constants.URL_SEPARATOR;

import org.mitre.oauth2.web.DeviceEndpoint;
import org.mitre.openid.connect.assertion.JWTBearerClientAssertionTokenEndpointFilter;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;


@Configuration
@Order(4)
public class DeviceEndpointSecurityConfig extends WebSecurityConfigurerAdapter {

    private final OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint;

    private final AuthenticationManager authenticationManager;

    private final ClientCredentialsTokenEndpointFilter clientCredentialsEndpointFilter;

    private final JWTBearerClientAssertionTokenEndpointFilter clientAssertionEndpointFilter;

    private final OAuth2AccessDeniedHandler oAuth2AccessDeniedHandler;

    public DeviceEndpointSecurityConfig(
            OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint,
            @Qualifier("clientAuthenticationManager") AuthenticationManager authenticationManager,
            ClientCredentialsTokenEndpointFilter clientCredentialsEndpointFilter,
            JWTBearerClientAssertionTokenEndpointFilter clientAssertionEndpointFilter, OAuth2AccessDeniedHandler oAuth2AccessDeniedHandler) {
        this.oauthAuthenticationEntryPoint = oauthAuthenticationEntryPoint;
        this.authenticationManager = authenticationManager;
        this.clientCredentialsEndpointFilter = clientCredentialsEndpointFilter;
        this.clientAssertionEndpointFilter = clientAssertionEndpointFilter;
        this.oAuth2AccessDeniedHandler = oAuth2AccessDeniedHandler;
    }

    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return this.authenticationManager;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.requestMatchers()
                .antMatchers(URL_SEPARATOR + DeviceEndpoint.URL + URL_SEPARATOR + ANY)
                .and()
                .exceptionHandling().accessDeniedHandler(this.oAuth2AccessDeniedHandler).authenticationEntryPoint(this.oauthAuthenticationEntryPoint)
                .and()
                .addFilterAfter(this.clientAssertionEndpointFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .addFilterAfter(this.clientCredentialsEndpointFilter, BasicAuthenticationFilter.class)
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

}
