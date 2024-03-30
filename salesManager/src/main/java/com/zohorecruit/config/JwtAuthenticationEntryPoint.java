package com.zohorecruit.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zohorecruit.models.ResponseBase;
import com.zohorecruit.models.ResponseHeader;
import com.zohorecruit.util.ResponseCodes;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint, AccessDeniedHandler {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        ResponseBase responseBase = new ResponseBase() {
            /**
             * @param responseHeader
             */
            @Override
            public void setResponseHeader(ResponseHeader responseHeader) {
                super.setResponseHeader(responseHeader);
            }
        };

        ResponseHeader errorResponse = new ResponseHeader();

        responseBase.setResponseHeader(errorResponse);

        errorResponse.setResponseMessage("Authentication failed. " + authException.getMessage());
        errorResponse.setResponseCode(ResponseCodes.FAILED);


        if (authException instanceof UsernameNotFoundException) {
            errorResponse.setResponseMessage("User not found.");
        }
        if (authException instanceof BadCredentialsException) {
            errorResponse.setResponseMessage("Invalid username or password.");
        }
        if (authException instanceof LockedException) {
            errorResponse.setResponseMessage("Your account is locked.");
        }
        if (authException instanceof DisabledException) {
            errorResponse.setResponseMessage("Your account is disabled.");
        }
        if (authException instanceof AccountExpiredException) {
            errorResponse.setResponseMessage("Your account has expired.");
        }
        if (authException instanceof CredentialsExpiredException) {
            errorResponse.setResponseMessage("Your credentials have expired.");
        }

        sendErrorResponse(response, responseBase);
    }

    private void sendErrorResponse(HttpServletResponse response, ResponseBase errorResponse) throws IOException {
        response.setContentType("application/json");
        response.getWriter().write(new ObjectMapper().writeValueAsString(errorResponse));
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        response.setStatus(HttpStatus.FORBIDDEN.value());

        ResponseBase responseBase = new ResponseBase() {

            @Override
            public void setResponseHeader(ResponseHeader responseHeader) {
                super.setResponseHeader(responseHeader);
            }
        };

        ResponseHeader errorResponse = new ResponseHeader();

        responseBase.setResponseHeader(errorResponse);
        errorResponse.setResponseMessage( "Access to this resource is denied. " + accessDeniedException.getMessage());
        errorResponse.setResponseCode(ResponseCodes.FAILED);

        sendErrorResponse(response, responseBase);
    }
}
