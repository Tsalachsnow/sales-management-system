package com.zohorecruit.config;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Slf4j
@Configuration
@EnableCaching
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class BeanConfig {
    @Value("${public.key.name}")
    private String publicKeyName;
    private String getPublicKeyString()
    {
        String publicKey="";
        if (StringUtils.isEmpty(publicKey)) {
            try  {
                final Resource resource= new ClassPathResource(publicKeyName);
                // String fileString = new String(Files.readAllBytes(Paths.get(publicKeyPath)));
                String fileString= IOUtils.toString(resource.getInputStream(), StandardCharsets.UTF_8);
                publicKey = fileString.replace("-----BEGIN PUBLIC KEY-----", "")
                        .replaceAll(System.lineSeparator(), "")
                        .replace("-----END PUBLIC KEY-----", "");
            } catch (IOException ex) {
                log.error(ex.getMessage(), ex);
                throw new RuntimeException(ex);
            }
        }
        log.info("Public Key: {}", publicKey);
        return publicKey;
    }
    @Bean("beanPublicKey")
    public PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        log.debug("JWT PUBKEY");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(getPublicKeyString()));
        return keyFactory.generatePublic(keySpec);
    }

    @Bean
    public LocalValidatorFactoryBean validator() {
        return new LocalValidatorFactoryBean();
    }
}
