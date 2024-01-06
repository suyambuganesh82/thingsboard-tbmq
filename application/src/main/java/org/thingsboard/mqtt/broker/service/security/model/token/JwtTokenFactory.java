/**
 * Copyright © 2016-2023 The Thingsboard Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.thingsboard.mqtt.broker.service.security.model.token;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import org.thingsboard.mqtt.broker.common.data.security.Authority;
import org.thingsboard.mqtt.broker.config.JwtSettings;
import org.thingsboard.mqtt.broker.service.security.model.SecurityUser;

import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class JwtTokenFactory {
    private static final String SCOPES = "scopes";
    private static final String USER_ID = "userId";
    private static final String FIRST_NAME = "firstName";
    private static final String LAST_NAME = "lastName";
    private static final String ENABLED = "enabled";

    private final JwtSettings settings;

    @Autowired
    public JwtTokenFactory(JwtSettings settings) {
        this.settings = settings;
    }

    /**
     * Factory method for issuing new JWT Tokens.
     */
    public AccessJwtToken createAccessJwtToken(SecurityUser securityUser) {
        if (StringUtils.isBlank(securityUser.getEmail()))
            throw new IllegalArgumentException("Cannot create JWT Token without username/email");

        if (securityUser.getAuthority() == null)
            throw new IllegalArgumentException("User doesn't have any privileges");

        Claims claims = Jwts.claims().subject(securityUser.getEmail())
                .add(SCOPES, securityUser.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .add(USER_ID, securityUser.getId().toString())
                .add(FIRST_NAME, securityUser.getFirstName())
                .add(LAST_NAME, securityUser.getLastName())
                .add(ENABLED, securityUser.isEnabled())
                .build();

        ZonedDateTime currentTime = ZonedDateTime.now();

        String token = Jwts.builder()
                .claims(claims)
                .issuer(settings.getTokenIssuer())
                .issuedAt(Date.from(currentTime.toInstant()))
                .expiration(Date.from(currentTime.plusSeconds(settings.getTokenExpirationTime()).toInstant()))
                .signWith(SignatureAlgorithm.HS512, settings.getTokenSigningKey())
                .compact();

        return new AccessJwtToken(token, claims);
    }

    public SecurityUser parseAccessJwtToken(RawAccessJwtToken rawAccessToken) {
        Jws<Claims> jwsClaims = rawAccessToken.parseClaims(settings.getTokenSigningKey());
        Claims claims = jwsClaims.getPayload();
        String subject = claims.getSubject();
        List<String> scopes = claims.get(SCOPES, List.class);
        if (scopes == null || scopes.isEmpty()) {
            throw new IllegalArgumentException("JWT Token doesn't have any scopes");
        }

        SecurityUser securityUser = new SecurityUser(UUID.fromString(claims.get(USER_ID, String.class)));
        securityUser.setEmail(subject);
        securityUser.setAuthority(Authority.parse(scopes.get(0)));
        securityUser.setFirstName(claims.get(FIRST_NAME, String.class));
        securityUser.setLastName(claims.get(LAST_NAME, String.class));
        securityUser.setEnabled(claims.get(ENABLED, Boolean.class));

        return securityUser;
    }

    public JwtToken createRefreshToken(SecurityUser securityUser) {
        if (StringUtils.isBlank(securityUser.getEmail())) {
            throw new IllegalArgumentException("Cannot create JWT Token without username/email");
        }

        ZonedDateTime currentTime = ZonedDateTime.now();

        Claims claims = Jwts.claims().subject(securityUser.getEmail())
                .add(SCOPES, Collections.singletonList(Authority.REFRESH_TOKEN.name()))
                .add(USER_ID, securityUser.getId().toString())
                .build();

        String token = Jwts.builder()
                .claims(claims)
                .issuer(settings.getTokenIssuer())
                .id(UUID.randomUUID().toString())
                .issuedAt(Date.from(currentTime.toInstant()))
                .expiration(Date.from(currentTime.plusSeconds(settings.getRefreshTokenExpTime()).toInstant()))
                .signWith(SignatureAlgorithm.HS512, settings.getTokenSigningKey())
                .compact();

        return new AccessJwtToken(token, claims);
    }

    public SecurityUser parseRefreshToken(RawAccessJwtToken rawAccessToken) {
        Jws<Claims> jwsClaims = rawAccessToken.parseClaims(settings.getTokenSigningKey());
        Claims claims = jwsClaims.getPayload();
        List<String> scopes = claims.get(SCOPES, List.class);
        if (scopes == null || scopes.isEmpty()) {
            throw new IllegalArgumentException("Refresh Token doesn't have any scopes");
        }
        if (!scopes.get(0).equals(Authority.REFRESH_TOKEN.name())) {
            throw new IllegalArgumentException("Invalid Refresh Token scope");
        }
        return new SecurityUser(UUID.fromString(claims.get(USER_ID, String.class)));
    }
}
