package com.zohorecruit.services.interfaces;

import com.zohorecruit.dto.AuthenticationRequest;
import com.zohorecruit.dto.AuthenticationResponse;
import org.springframework.http.ResponseEntity;

public interface AuthService {
    ResponseEntity<AuthenticationResponse> generateToken(AuthenticationRequest authRequest);
}
