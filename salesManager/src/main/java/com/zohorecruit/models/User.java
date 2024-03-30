package com.zohorecruit.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import javax.persistence.Column;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.util.Date;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class User {
    private String customerId;
    private String emailAddress;
    private String mobileNumber;
    private String firstName;
    private String lastName;
    private String middleName;
    private String dob;
    private String address;
    private Date createdDate;
    private String createdBy;
    private Date updatedDate;
    private String updatedBy;
    private String nationality;
    private String country;
    private String passwordEncrypt;
    private String pinEncrypt;
    private Date lastLoginDate;
    private String lastLoginSource;
}
