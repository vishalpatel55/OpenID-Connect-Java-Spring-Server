package com.auth.config.security;

import org.mitre.jwt.assertion.impl.NullAssertionValidator;
import org.mitre.jwt.assertion.impl.WhitelistedIssuerAssertionValidator;
import org.mitre.oauth2.assertion.impl.DirectCopyRequestFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class AssertionConfig {

    @Bean
    public NullAssertionValidator jwtAssertionValidator(){
        return new NullAssertionValidator();
    }

    @Bean
    public DirectCopyRequestFactory jwtAssertionTokenFactory(){
        return new DirectCopyRequestFactory();
    }

    @Bean
    public WhitelistedIssuerAssertionValidator clientAssertionValidator(){
        WhitelistedIssuerAssertionValidator assertionValidator = new WhitelistedIssuerAssertionValidator();
        assertionValidator.setWhitelist(whiteLists());
        return assertionValidator;
    }

    private Map<String, String> whiteLists(){
        Map<String, String> whiteLists = new HashMap<>();
        whiteLists.put("http://artemesia.local","http://localhost:8080/jwk");
        return whiteLists;
    }

}
