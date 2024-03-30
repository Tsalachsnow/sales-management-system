package com.zohorecruit.config;

import com.zohorecruit.models.UserDetails;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@Slf4j
public class JwtTokenUtil {
    @Qualifier("beanPublicKey")
    @Autowired
    private PublicKey publicKey;

    public String extractUsername(String token) {
        log.debug("JWT Extract Name");
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        log.trace("Claims JWT ::: {}", claims);
        return claimsResolver.apply(claims);
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token).getBody();
    }

    public List<String> extractRoles(String token) {
        Claims claims = extractAllClaims(token);
        return claims.get("roles", List.class);
    }

    public UserDetails extractAppUserDetails(String token) {
        Claims claims = extractAllClaims(token);
        UserDetails userDetails;
        try {

            HashMap hashMap = claims.get("userDetails", HashMap.class);
            log.trace("UserDetail hashMap: {}", hashMap);
            if (null != hashMap && !hashMap.isEmpty()) {
                Long id = Long.valueOf(hashMap.get("id").toString());
                String emailAddress = (String) hashMap.get("emailAddress");
                String country = (String) hashMap.get("country");
                String username = (String) hashMap.get("username");
                String firstName = (String) hashMap.get("firstName");
                String lastName = (String) hashMap.get("lastName");
                String middleName = (String) hashMap.get("middleName");

                userDetails = new UserDetails(id, username, emailAddress, firstName, middleName, lastName, country);
            } else return null;
        } catch (Exception e) {
            log.error("Sorry, Error occurred", e);
            throw new RuntimeException(e);
        }
        return userDetails;
    }

    public Boolean validateToken(String token) {
        return (!isTokenExpired(token));
    }

    public Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public Collection<GrantedAuthority> extractAuthorities(String token) {
        List<String> roles = extractRoles(token);

        return roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}
