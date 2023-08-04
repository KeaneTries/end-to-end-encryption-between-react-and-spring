package com.dmi.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;

public class User {
    private String id;
    private String name;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String rsaPublicKey;

    //we do not want to expose private RSA key in API responses
    @JsonIgnore
    private String rsaPrivateKey;

    //we do not want to expose AES primary key in API responses
    @JsonIgnore
    private String aesKey;

    public User(String id, String name) {
        this.id = id;
        this.name = name;
    }
    //getters and setters
}