package com.eternal.security.security;

import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.charset.StandardCharsets;

@Configuration
public class SecurityConfiguration {
    @Value("${security.token.secret}")
    private String secret;

    @Bean
    public Algorithm algorithm() {
        return Algorithm.HMAC256(secret.getBytes(StandardCharsets.UTF_8));
    }
}
