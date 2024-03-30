package com.zohorecruit.controllers;

import com.zohorecruit.dto.AuthenticationRequest;
import com.zohorecruit.dto.AuthenticationResponse;
import com.zohorecruit.services.interfaces.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import javax.validation.Valid;

@Validated
@RequestMapping("/v1/roho-recruit")
@RequiredArgsConstructor
@RestController
public class SystemsManagerController {
    private final AuthService service;

    @PostMapping(value ="/login", consumes = {MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE}, produces = {MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE})
    public ResponseEntity<AuthenticationResponse> generateToken(@RequestBody AuthenticationRequest request){
        return ResponseEntity.ok(service.generateToken(request).getBody());
    }
}
