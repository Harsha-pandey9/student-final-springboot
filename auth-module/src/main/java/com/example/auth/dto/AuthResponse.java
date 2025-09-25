package com.example.auth.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

/**
 * DTO for authentication responses
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@Data
public class AuthResponse {

    private boolean success;
    private String message;
    private String accessToken;
    private String refreshToken;
    private String tokenType = "Bearer";
    private Long expiresIn; // in seconds
    private UserInfo user;

    // Default constructor
    public AuthResponse() {}

    // Constructor for success response
    public AuthResponse(boolean success, String message, String accessToken, String refreshToken, Long expiresIn, UserInfo user) {
        this.success = success;
        this.message = message;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
        this.user = user;
    }

    // Constructor for error response
    public AuthResponse(boolean success, String message) {
        this.success = success;
        this.message = message;
    }

    // Static factory methods
    public static AuthResponse success(String message, String accessToken, String refreshToken, Long expiresIn, UserInfo user) {
        return new AuthResponse(true, message, accessToken, refreshToken, expiresIn, user);
    }

    public static AuthResponse error(String message) {
        return new AuthResponse(false, message);
    }

//    // Getters and Setters
//    public boolean isSuccess() { return success; }
//    public void setSuccess(boolean success) { this.success = success; }
//
//    public String getMessage() { return message; }
//    public void setMessage(String message) { this.message = message; }
//
//    public String getAccessToken() { return accessToken; }
//    public void setAccessToken(String accessToken) { this.accessToken = accessToken; }
//
//    public String getRefreshToken() { return refreshToken; }
//    public void setRefreshToken(String refreshToken) { this.refreshToken = refreshToken; }
//
//    public String getTokenType() { return tokenType; }
//    public void setTokenType(String tokenType) { this.tokenType = tokenType; }
//
//    public Long getExpiresIn() { return expiresIn; }
//    public void setExpiresIn(Long expiresIn) { this.expiresIn = expiresIn; }
//
//    public UserInfo getUser() { return user; }
//    public void setUser(UserInfo user) { this.user = user; }

//    @Override
//    public String toString() {
//        return "AuthResponse{" +
//                "success=" + success +
//                ", message='" + message + '\'' +
//                ", tokenType='" + tokenType + '\'' +
//                ", expiresIn=" + expiresIn +
//                ", user=" + user +
//                '}';
//    }
}