package com.auth.config.security;

import org.mitre.oauth2.service.impl.DefaultClientUserDetailsService;
import org.mitre.oauth2.web.CorsFilter;
import org.mitre.openid.connect.assertion.JWTBearerAuthenticationProvider;
import org.mitre.openid.connect.assertion.JWTBearerClientAssertionTokenEndpointFilter;
import org.mitre.openid.connect.filter.MultiUrlRequestMatcher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.sql.DataSource;

@Configuration
@Order(1)
public class AuthenticationConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter;

    private final DefaultClientUserDetailsService defaultClientUserDetailsService;
    
    private final DataSource dataSource;

    @Autowired
    public AuthenticationConfig(
            CorsFilter corsFilter, 
            DefaultClientUserDetailsService defaultClientUserDetailsService,
            DataSource dataSource) {
        this.corsFilter = corsFilter;
        this.defaultClientUserDetailsService = defaultClientUserDetailsService;
        this.dataSource = dataSource;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requestMatchers().antMatchers("/token")
                .and()
                .exceptionHandling().accessDeniedHandler(oAuth2AccessDeniedHandler())
                .authenticationEntryPoint(oauthAuthenticationEntryPoint())
                .and()
                .authorizeRequests()
                .antMatchers(HttpMethod.OPTIONS, "/token").permitAll()
                .antMatchers("/token").access("isAuthenticated()")
                .and()
                .httpBasic()
                .authenticationEntryPoint(oauthAuthenticationEntryPoint())
                .and()
                .addFilterAfter(clientAssertionEndpointFilter(clientAssertionAuthenticationManager()),
                        AbstractPreAuthenticatedProcessingFilter.class)
                .addFilterAfter(clientCredentialsEndpointFilter(authenticationManagerBean()),
                        BasicAuthenticationFilter.class)
                .addFilterAfter(this.corsFilter,
                        SecurityContextPersistenceFilter.class)
                .csrf().disable()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }

    @Bean
    public ClientCredentialsTokenEndpointFilter clientCredentialsEndpointFilter(@Qualifier("clientAuthenticationManager") AuthenticationManager authenticationManager) {

        ClientCredentialsTokenEndpointFilter clientCredentialsTokenEndpointFilter = new ClientCredentialsTokenEndpointFilter();
        clientCredentialsTokenEndpointFilter.setAuthenticationManager(authenticationManager);
        clientCredentialsTokenEndpointFilter.setRequiresAuthenticationRequestMatcher(urlMatchers());
        clientCredentialsTokenEndpointFilter.setFilterProcessesUrl("/token");
        return clientCredentialsTokenEndpointFilter;
    }

    @Bean
    public JWTBearerClientAssertionTokenEndpointFilter clientAssertionEndpointFilter(@Qualifier("clientAssertionAuthenticationManager") AuthenticationManager authenticationManager) {
        JWTBearerClientAssertionTokenEndpointFilter jwtBearerClientAssertionTokenEndpointFilter
                = new JWTBearerClientAssertionTokenEndpointFilter(urlMatchers());
        jwtBearerClientAssertionTokenEndpointFilter.setAuthenticationManager(clientAssertionAuthenticationManager());
        return jwtBearerClientAssertionTokenEndpointFilter;
    }


    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(this.defaultClientUserDetailsService).passwordEncoder(passwordEncoder());
    }

    @Bean
    public AuthenticationManager clientAssertionAuthenticationManager() {
        List<AuthenticationProvider> providers = new ArrayList<>();
        providers.add(clientAssertionAuthenticationProvider());
        return new ProviderManager(providers);
    }


    @Bean(name = "clientAuthenticationManager")
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManager();
    }

    @Bean
    public AuthenticationProvider clientAssertionAuthenticationProvider() {
        return new JWTBearerAuthenticationProvider();
    }

    private MultiUrlRequestMatcher urlMatchers() {
        Set<String> urls = new HashSet<>();
        urls.add("/introspect");
        urls.add("/revoke");
        urls.add("/token");
        return new MultiUrlRequestMatcher(urls);
    }

    @Bean
    public OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint() {
        OAuth2AuthenticationEntryPoint oAuth2AuthenticationEntryPoint = new OAuth2AuthenticationEntryPoint();
        oAuth2AuthenticationEntryPoint.setRealmName("openidconnect");
        return oAuth2AuthenticationEntryPoint;
    }

    @Bean
    public Http403ForbiddenEntryPoint http403EntryPoint() {
        return new Http403ForbiddenEntryPoint();
    }

    @Bean
    public OAuth2AccessDeniedHandler oAuth2AccessDeniedHandler() {
        return new OAuth2AccessDeniedHandler();
    }
    
    
    @Bean
	public UserDetailsService userDetailsService() {
		return new JdbcUserDetailsManager(this.dataSource);
	}
	

    /**
     * public UserDetailsService uriEncodedClientUserDetailsService(){
     * return new UriEncodedClientUserDetailsService();}
     **/

}
