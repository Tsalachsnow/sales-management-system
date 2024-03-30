package com.zohorecruit.config;

import com.zohorecruit.models.UserDetails;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;

@Slf4j
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.debug("Checking Token Validation");
        final String requestTokenHeader = request.getHeader("Authorization");
        String username = null;
        String jwtToken = null;
        if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
            jwtToken = requestTokenHeader.substring(7);
            try {
                username = jwtTokenUtil.extractUsername(jwtToken);
            } catch (IllegalArgumentException e) {
                log.error("Unable to get JWT Token");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            } catch (ExpiredJwtException e) {
                log.error("JWT Token has expired");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
        } else {
            log.error("JWT Token does not begin with Bearer String");
        }
        log.info("Destination Url {}", request.getRequestURI());
//        log.info("Extracted Username {}", username);

        if (StringUtils.isNotEmpty(username) && SecurityContextHolder.getContext().getAuthentication() == null) {
            Collection<? extends GrantedAuthority> userAuthorities = jwtTokenUtil.extractAuthorities(jwtToken);
// if token is valid configure Spring Security to manually set
// authentication
            // Check if the user has the required authority
            if (!userAuthorities.isEmpty()) {
                // User has the required authority, create an authentication token
                UserDetails userDetails = jwtTokenUtil.extractAppUserDetails(jwtToken);
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken;
                if (userDetails != null) {
                    usernamePasswordAuthenticationToken =
                            new UsernamePasswordAuthenticationToken(userDetails, null, userAuthorities);
                } else {
                    usernamePasswordAuthenticationToken =
                            new UsernamePasswordAuthenticationToken(username, null, userAuthorities);
                }

                usernamePasswordAuthenticationToken
                        .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            } else {
                // Throw an exception if the user does not have the required authority
                throw new AccessDeniedException("User does not have the required authority");
            }
        }
        log.info("Moving Down JWT Filter Lane...");
        filterChain.doFilter(request, response);
    }
}
