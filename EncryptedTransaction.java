package com.dmi.model;

public class EncryptedTransaction {
    String userId;
    //AES encrypted transaction information
    String payload;
    //RSA encypted AES key
    String encAesKey;
    
    //getters and setters...
}