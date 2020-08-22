package com.auth;


import org.mitre.oauth2.token.DeviceTokenGranter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;


@ComponentScan(basePackages = {"com.auth", "org.mitre"},excludeFilters = {
        @ComponentScan.Filter(type=FilterType.ASSIGNABLE_TYPE, value= {DeviceTokenGranter.class})})
@SpringBootApplication
public class OpenidAuthServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(OpenidAuthServerApplication.class, args);
    }

    @Bean
    public DefaultWebResponseExceptionTranslator oauth2ExceptionTranslator(){
        return new DefaultWebResponseExceptionTranslator();
    }

}
