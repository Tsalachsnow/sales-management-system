package com.zohorecruit.models;

import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
public class UserDetails {
    private Long id;
    private String username;
    private String emailAddress;
    private String firstName;
    private String middleName;
    private String lastName;
    private String country;

    public String getMobileNumber() {
        return username;
    }

    public UserDetails(Long id, String username, String emailAddress, String firstName, String middleName, String lastName, String country) {
        this.id = id;
        this.username = username;
        this.emailAddress = emailAddress;
        this.firstName = firstName;
        this.middleName = middleName;
        this.lastName = lastName;
        this.country = country;
    }
}
