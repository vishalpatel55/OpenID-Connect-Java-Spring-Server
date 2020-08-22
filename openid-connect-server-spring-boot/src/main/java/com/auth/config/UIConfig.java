package com.auth.config;

import org.mitre.openid.connect.config.UIConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashSet;
import java.util.Set;

@Configuration
public class UIConfig {

    private String jsResources = "resources/js/";

    @Bean
    public UIConfiguration uiConfiguration() {
        UIConfiguration uiConfiguration = new UIConfiguration();
        uiConfiguration.setJsFiles(jsFiles());
        return uiConfiguration;
    }

    private Set<String> jsFiles() {
        Set<String> jsFiles = new HashSet<>();
        jsFiles.add(jsResources + "client.js");
        jsFiles.add(jsResources + "grant.js");
        jsFiles.add(jsResources + "scope.js");
        jsFiles.add(jsResources + "whitelist.js");
        jsFiles.add(jsResources + "dynreg.js");
        jsFiles.add(jsResources + "rsreg.js");
        jsFiles.add(jsResources + "token.js");
        jsFiles.add(jsResources + "blacklist.js");
        jsFiles.add(jsResources + "profile.js");
        return jsFiles;
    }
}
