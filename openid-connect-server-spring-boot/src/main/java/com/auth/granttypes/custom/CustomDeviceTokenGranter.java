package com.auth.granttypes.custom;

import org.mitre.oauth2.exception.AuthorizationPendingException;
import org.mitre.oauth2.exception.DeviceCodeExpiredException;
import org.mitre.oauth2.model.DeviceCode;
import org.mitre.oauth2.service.DeviceCodeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class CustomDeviceTokenGranter extends AbstractTokenGranter {

    public static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

    private final DeviceCodeService deviceCodeService;

    /**
     * @param tokenServices
     * @param clientDetailsService
     * @param requestFactory
     * @param deviceCodeService
     */
    @Autowired
    protected CustomDeviceTokenGranter(@Qualifier("defaultOAuth2ProviderTokenService") AuthorizationServerTokenServices tokenServices, ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory, DeviceCodeService deviceCodeService) {
        super(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE);
        this.deviceCodeService = deviceCodeService;
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {

        String deviceCode = tokenRequest.getRequestParameters().get("device_code");

        // look up the device code and consume it
        DeviceCode dc = deviceCodeService.findDeviceCode(deviceCode, client);

        if (dc != null) {

            // make sure the code hasn't expired yet
            if (dc.getExpiration() != null && dc.getExpiration().before(new Date())) {

                deviceCodeService.clearDeviceCode(deviceCode, client);

                throw new DeviceCodeExpiredException("Device code has expired " + deviceCode);

            } else if (!dc.isApproved()) {

                // still waiting for approval
                throw new AuthorizationPendingException("Authorization pending for code " + deviceCode);

            } else {
                // inherit the (approved) scopes from the original request
                tokenRequest.setScope(dc.getScope());

                OAuth2Authentication auth = new OAuth2Authentication(getRequestFactory().createOAuth2Request(client, tokenRequest), dc.getAuthenticationHolder().getUserAuth());

                deviceCodeService.clearDeviceCode(deviceCode, client);

                return auth;
            }
        } else {
            throw new InvalidGrantException("Invalid device code: " + deviceCode);
        }

    }

}
