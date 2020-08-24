package com.auth.config.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import org.mitre.jose.keystore.JWKSetKeyStore;
import org.mitre.jwt.encryption.service.impl.DefaultJWTEncryptionAndDecryptionService;
import org.mitre.jwt.signer.service.impl.DefaultJWTSigningAndValidationService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.UrlResource;

import java.net.MalformedURLException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@Configuration
public class CryptoConfig {

    @Bean
    public JWKSetKeyStore defaultKeyStore() throws MalformedURLException {
        JWKSetKeyStore defaultKeyStore = new JWKSetKeyStore();
        defaultKeyStore.setLocation(new UrlResource("classpath:keystore.jwks"));
        return defaultKeyStore;
    }

    @Bean
    public DefaultJWTSigningAndValidationService defaultsignerService() throws MalformedURLException, InvalidKeySpecException, NoSuchAlgorithmException {
        DefaultJWTSigningAndValidationService defaultsignerService = new DefaultJWTSigningAndValidationService(defaultKeyStore());
        defaultsignerService.setDefaultSignerKeyId("rsa1");
        defaultsignerService.setDefaultSigningAlgorithmName("RS256");
        return defaultsignerService;
    }

    @Bean
    public DefaultJWTEncryptionAndDecryptionService defaultEncryptionService() throws MalformedURLException, NoSuchAlgorithmException, JOSEException, InvalidKeySpecException {
        DefaultJWTEncryptionAndDecryptionService defaultEncryptionService = new DefaultJWTEncryptionAndDecryptionService(defaultKeyStore());
        defaultEncryptionService.setDefaultAlgorithm(JWEAlgorithm.PBES2_HS512_A256KW);
        defaultEncryptionService.setDefaultDecryptionKeyId("rsa1");
        defaultEncryptionService.setDefaultEncryptionKeyId("rsa1");
        return defaultEncryptionService;
    }
}
