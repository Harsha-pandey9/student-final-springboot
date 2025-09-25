package com.example.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * DTO for refresh token requests
 */
@Data
public class RefreshTokenRequest {

    @NotBlank(message = "Refresh token is required")
    private String refreshToken;
    private String accessToken;

    // Default constructor
    public RefreshTokenRequest() {}

    // Constructor
    public RefreshTokenRequest(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    // Getters and Setters
//    public String getRefreshToken() { return refreshToken; }
//    public void setRefreshToken(String refreshToken) { this.refreshToken = refreshToken; }
//    public String getAccessToken() { return accessToken; }
//    public void setAccessToken(String accessToken) { this.accessToken = accessToken; }
//
//    @Override
//    public String toString() {
//        return "RefreshTokenRequest{" +
//                "refreshToken='" + (refreshToken != null ? refreshToken.substring(0, Math.min(refreshToken.length(), 20)) + "..." : null) + '\'' +
//                '}';
//    }
}