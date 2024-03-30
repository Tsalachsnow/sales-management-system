package com.zohorecruit.config;

import com.zohorecruit.models.AuthUser;
import com.zohorecruit.models.MyAuthentication;
import com.zohorecruit.repositories.AuthRepository;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Component
public class AuthenticationManagerImpl implements AuthenticationManager {
    @Autowired
    private AuthRepository repository;
    private static final Logger logger
            = LoggerFactory.getLogger(AuthenticationManagerImpl.class);
    @Autowired
    BCryptPasswordEncoder passwordEncoder;


    public MyAuthentication authenticate(Authentication authentication) throws AuthenticationException {
        String[] logins = authentication.getPrincipal().toString().split("\\|");
        String username1 = logins[0];
        Optional<AuthUser> userDetail = null;
        try {
            userDetail = repository.findByUsername(username1.trim().toUpperCase());
        } catch (Exception e) {
            logger.error("Error loading user, not found: {}", e);
        }

        if (!userDetail.isPresent()) {
            throw new UsernameNotFoundException(String.format("security violation: invalid credentials", authentication.getPrincipal()));
        }

        if (StringUtils.isBlank(authentication.getCredentials().toString())
                || !passwordEncoder.matches(authentication.getCredentials().toString() + "." + userDetail.get().getUsername(), userDetail.get().getPassword())) {
            throw new BadCredentialsException("security violation: invalid credentials");
        }

        String rolesString = userDetail.get().getRoles();
        logger.info("rolesString ::: {}", rolesString);
        String[] rolesArray = rolesString.split(",");
        logger.info("rolesArray ::: {}", rolesArray);

        List<GrantedAuthority> authorities = Arrays.stream(rolesArray)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        userDetail.get().setPassword(null).setRoles(null);

        return new MyAuthentication(userDetail.get().getUsername(), authentication.getCredentials(), authorities, userDetail.get());
    }

}


