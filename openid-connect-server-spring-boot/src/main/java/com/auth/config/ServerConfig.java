package com.auth.config;

import org.mitre.openid.connect.config.ConfigurationPropertiesBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ServerConfig {


    @Bean
    public ConfigurationPropertiesBean configurationPropertiesBean() {
        ConfigurationPropertiesBean configurationPropertiesBean = new ConfigurationPropertiesBean();
        configurationPropertiesBean.setIssuer("http://localhost:8080/");
        configurationPropertiesBean.setLogoImageUrl("resources/images/openid_connect_small.png");
        configurationPropertiesBean.setTopbarTitle("OpenID Connect Server");
        return configurationPropertiesBean;
    }


}
