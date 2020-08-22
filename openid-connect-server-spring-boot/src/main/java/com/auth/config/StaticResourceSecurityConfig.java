package com.auth.config;

import org.mitre.oauth2.web.CorsFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

@Configuration
@Order(5)
public class StaticResourceSecurityConfig extends WebSecurityConfigurerAdapter  {

    private final CorsFilter corsFilter;

    private final Http403ForbiddenEntryPoint http403EntryPoint;

    @Autowired
    public StaticResourceSecurityConfig(CorsFilter corsFilter, Http403ForbiddenEntryPoint http403EntryPoint) {
        this.corsFilter = corsFilter;
        this.http403EntryPoint = http403EntryPoint;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requestMatchers().antMatchers("/resources/**")
                .and().exceptionHandling()
                .authenticationEntryPoint(this.http403EntryPoint)
                .and()
                .authorizeRequests()
                .antMatchers("/resources/**")
                .permitAll()
                .and()
                .addFilterAfter(this.corsFilter,
                        SecurityContextPersistenceFilter.class)
                .csrf().disable()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }
}
