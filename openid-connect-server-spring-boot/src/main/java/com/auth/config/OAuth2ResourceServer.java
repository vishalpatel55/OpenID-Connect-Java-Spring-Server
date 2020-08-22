package com.auth.config;

import static com.auth.util.Constants.ANY;
import static com.auth.util.Constants.URL_SEPARATOR;

import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.mitre.oauth2.web.IntrospectionEndpoint;
import org.mitre.oauth2.web.RevocationEndpoint;
import org.mitre.openid.connect.assertion.JWTBearerClientAssertionTokenEndpointFilter;
import org.mitre.openid.connect.web.DynamicClientRegistrationEndpoint;
import org.mitre.openid.connect.web.ProtectedResourceRegistrationEndpoint;
import org.mitre.openid.connect.web.RootController;
import org.mitre.openid.connect.web.UserInfoEndpoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableResourceServer
@Order(Ordered.HIGHEST_PRECEDENCE)
public class OAuth2ResourceServer extends ResourceServerConfigurerAdapter {

    private final DefaultOAuth2ProviderTokenService defaultOAuth2ProviderTokenService;

    private final OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint;

    private final AuthenticationManager authenticationManager;

    private final ClientCredentialsTokenEndpointFilter clientCredentialsEndpointFilter;

    private final JWTBearerClientAssertionTokenEndpointFilter clientAssertionEndpointFilter;

    @Autowired
    public OAuth2ResourceServer(
            DefaultOAuth2ProviderTokenService defaultOAuth2ProviderTokenService,
            OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint,
            @Qualifier("clientAuthenticationManager") AuthenticationManager authenticationManager,
            ClientCredentialsTokenEndpointFilter clientCredentialsEndpointFilter,
            JWTBearerClientAssertionTokenEndpointFilter clientAssertionEndpointFilter ) {
        this.defaultOAuth2ProviderTokenService = defaultOAuth2ProviderTokenService;
        this.oauthAuthenticationEntryPoint = oauthAuthenticationEntryPoint;
        this.authenticationManager = authenticationManager;
        this.clientCredentialsEndpointFilter = clientCredentialsEndpointFilter;
        this.clientAssertionEndpointFilter = clientAssertionEndpointFilter;
    }

    @Override
    public void configure(final ResourceServerSecurityConfigurer resources) {
        //resources.tokenServices(this.defaultOAuth2ProviderTokenService);
        resources.authenticationManager(this.authenticationManager);

    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.requestMatchers()
                    .antMatchers(
                            URL_SEPARATOR + DynamicClientRegistrationEndpoint.URL + URL_SEPARATOR + ANY,
                            URL_SEPARATOR + ProtectedResourceRegistrationEndpoint.URL + URL_SEPARATOR + ANY,
                            URL_SEPARATOR + UserInfoEndpoint.URL + ANY
                    )
                    .and()
                    .exceptionHandling()
                    .authenticationEntryPoint(this.oauthAuthenticationEntryPoint)
                    .and()
                    .authorizeRequests().expressionHandler(oauthWebExpressionHandler())
                    .antMatchers(
                            URL_SEPARATOR + DynamicClientRegistrationEndpoint.URL + URL_SEPARATOR + ANY,
                            URL_SEPARATOR + ProtectedResourceRegistrationEndpoint.URL + URL_SEPARATOR + ANY
                    )
                    .permitAll()
                    .and()
                    .csrf().disable()
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .requestMatchers()
                    .antMatchers(
                            URL_SEPARATOR + RootController.API_URL + URL_SEPARATOR + ANY
                    )
                    .and()
                    .authorizeRequests().expressionHandler(oauthWebExpressionHandler())
                    .and()
                    .csrf().disable()
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER)
                .and()
                .requestMatchers()
                    .antMatchers(
                            URL_SEPARATOR + IntrospectionEndpoint.URL + ANY,
                            URL_SEPARATOR + RevocationEndpoint.URL + ANY
                    )
                    .and()
                    .exceptionHandling()
                    .authenticationEntryPoint(this.oauthAuthenticationEntryPoint)
                    .and().httpBasic().authenticationEntryPoint(this.oauthAuthenticationEntryPoint)
                    .and()
                    .addFilterAfter(this.clientAssertionEndpointFilter, AbstractPreAuthenticatedProcessingFilter.class)
                    .addFilterAfter(this.clientCredentialsEndpointFilter, BasicAuthenticationFilter.class)
                    .csrf().disable()
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    @Bean
    public OAuth2WebSecurityExpressionHandler oauthWebExpressionHandler() {
        return new OAuth2WebSecurityExpressionHandler();
    }

}
