package com.zohorecruit.services.serviceImplimentation;

import com.zohorecruit.config.AuthenticationManagerImpl;
import com.zohorecruit.dto.AuthenticationRequest;
import com.zohorecruit.dto.AuthenticationResponse;
import com.zohorecruit.models.*;
import com.zohorecruit.repositories.AuthRepository;
import com.zohorecruit.services.interfaces.AuthService;
import com.zohorecruit.util.JsonConverter;
import com.zohorecruit.util.JwtUtil;
import com.zohorecruit.util.ResponseCodes;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.sql.Date;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    private final JwtUtil jwtUtil;
    private final AuthenticationManagerImpl authenticationManager;
    private final AuthRepository repository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public ResponseEntity<AuthenticationResponse> generateToken(AuthenticationRequest authRequest){

        log.info("Generate token service");
        AuthenticationResponse response = new AuthenticationResponse();
        ResponseHeader responseHeader = new ResponseHeader();

        try {
            MyAuthentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getUsername().trim().toUpperCase(), authRequest.getPassword())
            );
            log.info("Credentials authenticated");

            // Get the user's roles from the authentication object.
            log.info("authentication {}", authentication);
            List<String> roles = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
            log.info("Get grantedAuthorities roles :: {}",roles);


            // Generate the access and refresh tokens.
            String username = authentication.getName();
            log.info("Get Username from Auth :: {}",username);
            log.info("Generate a new access token");
            Map<String, Object> tokenClaims = jwtUtil.convertRoleListToMap(roles);
            tokenClaims.put("userDetails", authentication.getUserDetails());

            log.info("Claims Map for JWT ::: {}",tokenClaims);
            String accessToken = jwtUtil.generateToken(tokenClaims, username);
            String refreshToken = jwtUtil.generateRefreshToken(username, tokenClaims);

            // Set the response body.
            response.setToken(accessToken)
                    .setRefreshToken(refreshToken);
            responseHeader.setResponseCode(ResponseCodes.SUCCESSFUL)
                    .setResponseMessage("SUCCESS");
            response.setResponseHeader(responseHeader);

            authRequest.setUsername(String.valueOf(authentication.getUserDetails().getId()));

//            This is to save user last login in the db using different thread
            ExecutorService executorService = Executors.newFixedThreadPool(1);
            executorService.execute(() -> {
                updateUserLastLogin(authRequest);
            });
            executorService.shutdown();

            return ResponseEntity.ok(response);
        } catch (AuthenticationException ex) {
            // Handle authentication exceptions.
            log.info("AUTH-SERVICE ::: EXCEPTION ::: {}", ex.getMessage());
            response.setToken(null);
            responseHeader.setResponseCode(ResponseCodes.FAILED)
                    .setResponseMessage("Invalid username/password");
            response.setResponseHeader(responseHeader);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(response);
        } catch (Exception ex) {
            // Handle other exceptions.
            log.info("AUTH-SERVICE ::: EXCEPTION ::: {}", ex.getMessage());
            response.setToken(null);
            responseHeader.setResponseCode(ResponseCodes.FAILED)
                    .setResponseMessage("Unexpected error occurred");
            response.setResponseHeader(responseHeader);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(response);
        }
    }
    void updateUserLastLogin(AuthenticationRequest authRequest){
        log.info("Auth service : updateUserLastLogin ::: {}", JsonConverter.toJson(authRequest, true));
        Optional<AuthUser> user = repository.findByUsername(authRequest.getUsername());
            AuthUser authUser = user.get();
            LocalDate localDate = LocalDate.now();
            Date date = java.sql.Date.valueOf(localDate);
            authUser.setLastLoginDate(date);
            repository.save(authUser);

    }
}
