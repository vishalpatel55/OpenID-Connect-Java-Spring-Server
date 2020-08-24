package com.auth.config.security;

import org.mitre.oauth2.service.impl.BlacklistAwareRedirectResolver;
import org.mitre.oauth2.service.impl.DefaultOAuth2AuthorizationCodeService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ClientDetailsEntityService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.mitre.oauth2.token.ScopeServiceAwareOAuth2RequestValidator;
import org.mitre.openid.connect.request.ConnectOAuth2RequestFactory;
import org.mitre.openid.connect.token.TofuUserApprovalHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint;

import com.auth.granttypes.custom.CustomGrantTypeCollection;

@Configuration("oAuth2AuthorizationServer")
@EnableAuthorizationServer
public class OAuth2AuthorizationServer extends AuthorizationServerConfigurerAdapter {

    private final ConnectOAuth2RequestFactory connectOAuth2RequestFactory;

    private final DefaultOAuth2ClientDetailsEntityService defaultOAuth2ClientDetailsEntityService;

    private final DefaultOAuth2ProviderTokenService defaultOAuth2ProviderTokenService;

    private final TofuUserApprovalHandler tofuUserApprovalHandler;

    private final BlacklistAwareRedirectResolver blacklistAwareRedirectResolver;

    private  final DefaultOAuth2AuthorizationCodeService defaultOAuth2AuthorizationCodeService;

    private final CustomGrantTypeCollection tokenGranter;
    
    @Autowired
    public OAuth2AuthorizationServer(
            ConnectOAuth2RequestFactory connectOAuth2RequestFactory,
            DefaultOAuth2ClientDetailsEntityService defaultOAuth2ClientDetailsEntityService,
            DefaultOAuth2ProviderTokenService defaultOAuth2ProviderTokenService,
            TofuUserApprovalHandler tofuUserApprovalHandler,
            BlacklistAwareRedirectResolver blacklistAwareRedirectResolver,
            DefaultOAuth2AuthorizationCodeService defaultOAuth2AuthorizationCodeService,
            CustomGrantTypeCollection tokenGranter) {
        this.connectOAuth2RequestFactory = connectOAuth2RequestFactory;
        this.defaultOAuth2ClientDetailsEntityService = defaultOAuth2ClientDetailsEntityService;
        this.defaultOAuth2ProviderTokenService = defaultOAuth2ProviderTokenService;
        this.tofuUserApprovalHandler = tofuUserApprovalHandler;
        this.blacklistAwareRedirectResolver = blacklistAwareRedirectResolver;
        this.defaultOAuth2AuthorizationCodeService = defaultOAuth2AuthorizationCodeService;
        this.tokenGranter = tokenGranter;
    }

  @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(this.defaultOAuth2ClientDetailsEntityService);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.requestFactory(this.connectOAuth2RequestFactory);
        endpoints.tokenServices(this.defaultOAuth2ProviderTokenService);
        endpoints.userApprovalHandler(this.tofuUserApprovalHandler);
        endpoints.requestValidator(oauthRequestValidator());
        endpoints.setClientDetailsService(this.defaultOAuth2ClientDetailsEntityService);
        endpoints.authorizationCodeServices(this.defaultOAuth2AuthorizationCodeService);
        endpoints.tokenGranter(this.tokenGranter.customGrants(endpoints));
        endpoints.pathMapping("/oauth/authorize", "/authorize");
        
        
    }


    @Bean
    public ScopeServiceAwareOAuth2RequestValidator oauthRequestValidator(){
        return new ScopeServiceAwareOAuth2RequestValidator();
    }
    
    @Autowired
	public void configureAuthorizationEndpoint(AuthorizationEndpoint authorizationEndpoint) {

		authorizationEndpoint.setRedirectResolver(this.blacklistAwareRedirectResolver);
	}

}
