package com.zohorecruit.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.zohorecruit.models.ResponseBase;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;

@EqualsAndHashCode(callSuper = true)
@Data
@Accessors(chain = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthenticationResponse extends ResponseBase {
    private String token;
    private String refreshToken;
}
