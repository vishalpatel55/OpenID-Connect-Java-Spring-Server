package com.auth.config.security;

import org.mitre.openid.connect.filter.AuthorizationRequestFilter;
import org.mitre.openid.connect.web.AuthenticationTimeStamper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.security.authentication.AuthenticationManager;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;

import org.springframework.security.web.context.SecurityContextPersistenceFilter;



@Configuration
@EnableWebSecurity
@DependsOn({ "connectOAuth2RequestFactory", "oAuth2AuthorizationServer" })
public class UserContextConfig extends WebSecurityConfigurerAdapter {

	

	private final OAuth2WebSecurityExpressionHandler oauthWebExpressionHandler;

	private final AuthenticationTimeStamper authenticationTimeStamper;

	private final AuthorizationRequestFilter authRequestFilter;

	private final PasswordEncoder passwordEncoder;
	
	private final UserDetailsService userDetailsService;
	

	@Autowired
	public UserContextConfig(OAuth2WebSecurityExpressionHandler oauthWebExpressionHandler,
			AuthenticationTimeStamper authenticationTimeStamper,
			AuthorizationRequestFilter authRequestFilter,
			PasswordEncoder passwordEncoder,
			UserDetailsService userDetailsService) {
		this.oauthWebExpressionHandler = oauthWebExpressionHandler;
		this.authenticationTimeStamper = authenticationTimeStamper;
		this.authRequestFilter = authRequestFilter;
		this.passwordEncoder = passwordEncoder;
		this.userDetailsService = userDetailsService;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.exceptionHandling().and().authorizeRequests().expressionHandler(this.oauthWebExpressionHandler)
				.antMatchers("/authorize").access("hasRole('ROLE_USER')").antMatchers("/**").permitAll().and()
				.formLogin().loginPage("/login").failureUrl("/login?error=failure")
				.successHandler(this.authenticationTimeStamper).and()
				.addFilterAfter(this.authRequestFilter, SecurityContextPersistenceFilter.class).logout()
				.logoutUrl("/logout").and().anonymous().and().headers().frameOptions().deny().and().csrf();
	}

	@Override
	protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(this.userDetailsService).passwordEncoder(this.passwordEncoder);
	}

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	
	
}
