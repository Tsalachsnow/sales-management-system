package com.zohorecruit.models;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;

public class MyAuthentication extends UsernamePasswordAuthenticationToken {
    private AuthUser userDetails;

    public MyAuthentication(String principal, Object credentials, List<GrantedAuthority> authorities, AuthUser userDetails) {
        super(principal, credentials, authorities);
        this.userDetails = userDetails;
    }
    public AuthUser getUserDetails() {
        return userDetails;
    }

    public void setUserDetails(AuthUser userDetails) {
        this.userDetails = userDetails;
    }
}
