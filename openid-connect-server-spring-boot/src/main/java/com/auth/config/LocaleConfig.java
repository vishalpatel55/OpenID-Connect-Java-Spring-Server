package com.auth.config;

import org.mitre.openid.connect.config.ConfigurationBeanLocaleResolver;
import org.mitre.openid.connect.config.JsonMessageSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import java.net.MalformedURLException;


@Configuration
public class LocaleConfig {
	
	@Value("classpath:/js/locale/")
	Resource resourceFile;

   @Bean("localeResolver")
    public ConfigurationBeanLocaleResolver localeResolver() {
        return new ConfigurationBeanLocaleResolver();
    }

   @Bean
    public JsonMessageSource messageSource() throws MalformedURLException {
        JsonMessageSource messageSource = new JsonMessageSource();
        messageSource.setBaseDirectory(resourceFile);
        messageSource.setUseCodeAsDefaultMessage(true);
        return messageSource;
    }

}
