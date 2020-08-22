package com.auth.scheduled;

import org.mitre.oauth2.service.impl.DefaultDeviceCodeService;
import org.mitre.oauth2.service.impl.DefaultOAuth2AuthorizationCodeService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.mitre.openid.connect.service.impl.DefaultApprovedSiteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
@EnableAsync
public class CleaningJobs {

    private final DefaultOAuth2ProviderTokenService defaultOAuth2ProviderTokenService;

    private final DefaultApprovedSiteService defaultApprovedSiteService;

    private final DefaultOAuth2AuthorizationCodeService defaultOAuth2AuthorizationCodeService;

    private final DefaultDeviceCodeService defaultDeviceCodeService;

    @Autowired
    public CleaningJobs(DefaultOAuth2ProviderTokenService defaultOAuth2ProviderTokenService, DefaultApprovedSiteService defaultApprovedSiteService, DefaultOAuth2AuthorizationCodeService defaultOAuth2AuthorizationCodeService, DefaultDeviceCodeService defaultDeviceCodeService) {
        this.defaultOAuth2ProviderTokenService = defaultOAuth2ProviderTokenService;
        this.defaultApprovedSiteService = defaultApprovedSiteService;
        this.defaultOAuth2AuthorizationCodeService = defaultOAuth2AuthorizationCodeService;
        this.defaultDeviceCodeService = defaultDeviceCodeService;
    }

    @Async
    @Scheduled(initialDelay = 600000, fixedDelay = 300000)
    public void clearExpiredTokens(){
        this.defaultOAuth2ProviderTokenService.clearExpiredTokens();
    }

    @Async
    @Scheduled(initialDelay = 600000, fixedDelay = 300000)
    public void clearExpiredSites(){
        this.defaultApprovedSiteService.clearExpiredSites();
    }

    @Async
    @Scheduled(initialDelay = 600000, fixedDelay = 300000)
    public void clearExpiredAuthorizationCodes(){
        this.defaultOAuth2AuthorizationCodeService.clearExpiredAuthorizationCodes();
    }

    @Async
    @Scheduled(initialDelay = 600000, fixedDelay = 300000)
    public void clearExpiredDeviceCodes(){
        this.defaultDeviceCodeService.clearExpiredDeviceCodes();
    }
}
