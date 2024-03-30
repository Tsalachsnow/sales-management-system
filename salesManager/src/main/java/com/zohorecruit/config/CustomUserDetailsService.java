package com.zohorecruit.config;


import com.zohorecruit.models.AuthUser;
import com.zohorecruit.repositories.AuthRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {
    private final AuthRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        AuthUser user = repository.findByUsername(username.trim().toUpperCase())
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        log.info("CUSTOM USER DETAILS ::: username and pass");


        return User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .roles(user.getRoles().split(","))
                .build();
    }
}
