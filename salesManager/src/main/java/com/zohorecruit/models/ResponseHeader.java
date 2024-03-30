package com.zohorecruit.models;

import lombok.Data;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
public class ResponseHeader {
    private String responseCode;
    private String responseMessage;
}
