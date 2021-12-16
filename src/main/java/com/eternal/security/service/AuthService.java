package com.eternal.security.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.eternal.security.domain.model.Role;
import com.eternal.security.domain.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {
    private final UserService userService;
    private final Algorithm algorithm;

    public void validateToken(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        org.springframework.security.core.userdetails.User user = (org.springframework.security.core.userdetails.User) authentication.getPrincipal();
        String accessToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithm);
        String refreshToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 30 * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithm);
        writeTokensToResponse(accessToken, refreshToken, response);
    }

    public void validateToken(HttpServletRequest request, HttpServletResponse response, String authHeader) throws IOException {
        try {
            String refreshToken = authHeader.substring("Bearer ".length());
            DecodedJWT decodedJWT = getDecodedJWT(refreshToken);
            String username = decodedJWT.getSubject();
            User user = userService.getUser(username);
            String accessToken = JWT.create()
                    .withSubject(user.getUsername())
                    .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                    .withIssuer(request.getRequestURL().toString())
                    .withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                    .sign(algorithm);
            writeTokensToResponse(accessToken, refreshToken, response);
        } catch (Exception e) {
            processException(e, response);
        }
    }

    public void validateToken(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, String authHeader) throws IOException {
        try {
            DecodedJWT decodedJWT = getDecodedJWT(authHeader.substring("Bearer ".length()));
            String username = decodedJWT.getSubject();
            String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
            Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
            Arrays.stream(roles).forEach(s -> authorities.add(new SimpleGrantedAuthority(s)));
            var authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            processException(e, response);
        }
    }

    private void writeTokensToResponse(String accessToken, String refreshToken, HttpServletResponse response) throws IOException {
        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", accessToken);
        tokens.put("refresh_token", refreshToken);
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
    }

    private DecodedJWT getDecodedJWT(String refreshToken) {
        JWTVerifier verifier = JWT.require(algorithm).build();
        return verifier.verify(refreshToken);
    }

    private void processException(Exception e, HttpServletResponse response) throws IOException {
        log.error("Error logging in : {}", e.getMessage());
        response.setStatus(FORBIDDEN.value());
        Map<String, String> error = new HashMap<>();
        error.put("error_message", e.getMessage());
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), error);
    }
}
