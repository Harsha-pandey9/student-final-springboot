package com.example.auth.controller;

import com.example.auth.dto.*;
import com.example.auth.service.AuthService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * REST Controller for authentication operations
 */
@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*", maxAge = 3600)
public class AuthController {
    
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    
    @Autowired
    private AuthService authService;
    
    /**
     * Register a new user
     */
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        logger.info("Registration request received for username: {}", request.getUsername());
        
        AuthResponse response = authService.register(request);
        
        if (response.isSuccess()) {
            logger.info("Registration successful for username: {}", request.getUsername());
            return ResponseEntity.ok(response);
        } else {
            logger.warn("Registration failed for username: {} - {}", request.getUsername(), response.getMessage());
            return ResponseEntity.badRequest().body(response);
        }
    }
    
    /**
     * Authenticate user
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        logger.info("Login request received for username: {}", request.getUsername());
        
        AuthResponse response = authService.login(request);
        
        if (response.isSuccess()) {
            logger.info("Login successful for username: {}", request.getUsername());
            return ResponseEntity.ok(response);
        } else {
            logger.warn("Login failed for username: {} - {}", request.getUsername(), response.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }
    
    /**
     * Refresh access token
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        logger.info("Token refresh request received");
        
        AuthResponse response = authService.refreshToken(request);
        
        if (response.isSuccess()) {
            logger.info("Token refresh successful");
            return ResponseEntity.ok(response);
        } else {
            logger.warn("Token refresh failed - {}", response.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }
    
    /**
     * Logout user
     */
    @PostMapping("/logout")
    public ResponseEntity<AuthResponse> logout(@RequestBody(required = false) RefreshTokenRequest request) {
        logger.info("Logout request received");
        
        String refreshToken = null;
        if (request != null) {
            refreshToken = request.getRefreshToken();
        }
        
        AuthResponse response = authService.logout(refreshToken);
        
        logger.info("Logout completed");
        return ResponseEntity.ok(response);
    }
    
    /**
     * Get current user profile
     */
    @GetMapping("/profile")
    public ResponseEntity<?> getProfile() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = authentication.getName();
            
            logger.info("Profile request for user: {}", username);
            
            UserInfo userInfo = authService.getUserProfile(username);
            
            if (userInfo != null) {
                return ResponseEntity.ok(userInfo);
            } else {
                return ResponseEntity.notFound().build();
            }
            
        } catch (Exception e) {
            logger.error("Error getting user profile", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(AuthResponse.error("Error retrieving profile"));
        }
    }
    
    /**
     * Validate token (for other microservices)
     */
    @GetMapping("/validate")
    public ResponseEntity<AuthResponse> validateToken() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            
            if (authentication != null && authentication.isAuthenticated()) {
                String username = authentication.getName();
                UserInfo userInfo = authService.getUserProfile(username);
                
                return ResponseEntity.ok(AuthResponse.success("Token is valid", null, null, null, userInfo));
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(AuthResponse.error("Token is invalid"));
            }
            
        } catch (Exception e) {
            logger.error("Error validating token", e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(AuthResponse.error("Token validation failed"));
        }
    }
    
    /**
     * Health check endpoint - comprehensive health status
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "UP");
        response.put("module", "Auth Module");
        response.put("timestamp", LocalDateTime.now());
        response.put("message", "Auth module is running successfully");
        response.put("service", "Authentication Service");
        return ResponseEntity.ok(response);
    }
    
    /**
     * Simple health check endpoint for backward compatibility
     */
    @GetMapping("/status")
    public ResponseEntity<String> simpleHealth() {
        return ResponseEntity.ok("Auth Service is running");
    }
}