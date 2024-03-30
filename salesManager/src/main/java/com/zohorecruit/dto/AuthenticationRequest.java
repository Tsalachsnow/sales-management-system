package com.zohorecruit.dto;

import lombok.Data;
import lombok.experimental.Accessors;


@Data
@Accessors(chain = true)
public class AuthenticationRequest{
    private String username;
    private String password;
}
