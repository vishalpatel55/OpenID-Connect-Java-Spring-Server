package com.auth.granttypes.custom;

import org.mitre.oauth2.token.ChainedTokenGranter;
import org.mitre.oauth2.token.JWTAssertionTokenGranter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Component
public class CustomGrantTypeCollection {

    private final ChainedTokenGranter chainedTokenGranter;

    private final JWTAssertionTokenGranter jwtAssertionTokenGranter;

    private final CustomDeviceTokenGranter customDeviceTokenGranter;

    @Autowired
    public CustomGrantTypeCollection(ChainedTokenGranter chainedTokenGranter, JWTAssertionTokenGranter jwtAssertionTokenGranter, CustomDeviceTokenGranter customDeviceTokenGranter) {
        this.chainedTokenGranter = chainedTokenGranter;
        this.jwtAssertionTokenGranter = jwtAssertionTokenGranter;
        this.customDeviceTokenGranter = customDeviceTokenGranter;
    }

    public TokenGranter customGrants(final AuthorizationServerEndpointsConfigurer endpoints){
        List<TokenGranter> granters = new ArrayList<>(Arrays.asList(endpoints.getTokenGranter()));
        granters.add(this.chainedTokenGranter);
        granters.add(this.jwtAssertionTokenGranter);
        granters.add(this.customDeviceTokenGranter);
        return new CompositeTokenGranter(granters);
    }
}
