package com.zohorecruit.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zohorecruit.models.AuthUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@Slf4j
public class JwtUtil {

    @Qualifier("beanPrivateKey")
    @Autowired
    private PrivateKey privateKey;
    @Qualifier("beanPublicKey")
    @Autowired
    private PublicKey publicKey;
    @Value("${jwt.expiry.minutes}")
    private long expiry;
    @Value("${jwt.refresh.expiry.minutes}")
    private long refreshExpiry;
    @Value("${jwt.secret}")
    private String secretKey;

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        log.info("Claims JWT ::: " + claims);
        return claimsResolver.apply(claims);
    }
    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token).getBody();
    }

    public Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, username);
    }
    public String generateToken(Map<String, Object> claims, String username) {
//        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, username);
    }

    public String generateRefreshToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        return createRefreshToken(claims, username);
    }
    public String generateRefreshToken(String username, Map<String, Object> claims) {
        return createRefreshToken(claims, username);
    }

    private String createToken(Map<String, Object> claims, String subject) {

        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * expiry))
                .signWith(SignatureAlgorithm.RS256, privateKey).compact();
    }

    private String createRefreshToken(Map<String, Object> claims, String subject) {

        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * refreshExpiry))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256).compact();
    }

    private Claims extractAllClaimsRefresh(String token) {
        return Jwts
                .parserBuilder()
        .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    public boolean isTokenExpiredRefresh(String token) {
        return extractExpirationRefresh(token).before(new Date());
    }

    private Date extractExpirationRefresh(String token) {
        return extractClaimRefresh(token, Claims::getExpiration);
    }
    public <T> T extractClaimRefresh(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaimsRefresh(token);
        return claimsResolver.apply(claims);
    }
    public String extractUsernameRefresh(String token) {
        return extractClaimRefresh(token, Claims::getSubject);
    }


    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
    public Boolean validateToken(String token) {
        return (!isTokenExpired(token));
    }
    public String getUsernameFromHttpServletRequest(HttpServletRequest httpServletRequest){
        String token = httpServletRequest.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
           token = token.substring(7);
        }

        return extractUsername(token);
    }
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public Map<String, Object> convertCommaSeparatedStringToMap(String commaSeparatedString) {
        String[] roles = commaSeparatedString.split(",");
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", roles);
        return claims;
    }
    public List<String> extractRoles(String token) {
        Claims claims = extractAllClaims(token);
        return claims.get("roles", List.class);
    }

    public List<String> extractRolesRefresh(String token) {
        Claims claims = extractAllClaimsRefresh(token);
        return claims.get("roles", List.class);
    }
    public Map<String, Object> extractClaimsRefresh(String token) {
        Claims claims = extractAllClaimsRefresh(token);
        Map<String, Object> tokenClaims = new HashMap<>();

        tokenClaims.put("roles", claims.get("roles", List.class));
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            String userDetailsJson = claims.get("userDetails", String.class);
            AuthUser userDetails = objectMapper.readValue(userDetailsJson, AuthUser.class);
            tokenClaims.put("userDetails", userDetails);
        }catch (Exception e){
            tokenClaims.put("userDetails", claims.get("userDetails"));
        }
        return tokenClaims;
    }
    public Map<String, Object> convertRoleListToMap(List<String> roles) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", roles);
        return claims;
    }

    public Collection<GrantedAuthority> extractAuthorities(String token) {
        List<String> roles = extractRoles(token);

        return roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}

