package com.zohorecruit.util;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;


@Configuration
@Slf4j
public class RohoRecruitPrivateKey {
    @Value("${private.key.name}")
    private String privateKeyName;
    private String getPrivateKeyString()
    {
        String privateKey="";
        if (StringUtils.isEmpty(privateKey)) {
            try  {
                final Resource resource= new ClassPathResource(privateKeyName);
                String fileString= IOUtils.toString(resource.getInputStream(), StandardCharsets.UTF_8);
                privateKey = fileString.replace("-----BEGIN PRIVATE KEY-----", "")
                        .replaceAll(System.lineSeparator(), "")
                        .replace("-----END PRIVATE KEY-----", "");
            } catch (IOException ex) {
                log.error(ex.getMessage(), ex);
                throw new RuntimeException(ex);
            }
        }
        log.info("Private Key: {}", privateKey);
        return privateKey;
    }

    @Bean("beanPrivateKey")
    public PrivateKey readPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        log.debug("JWT PRIVATE KEY");

        byte[] encoded = Base64.decodeBase64(getPrivateKeyString());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return (PrivateKey) keyFactory.generatePrivate(keySpec);
    }
}
