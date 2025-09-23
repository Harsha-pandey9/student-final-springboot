package com.example.auth.service;

import com.example.auth.dto.*;
import com.example.auth.model.RefreshToken;
import com.example.auth.model.Role;
import com.example.auth.model.User;
import com.example.auth.repository.RefreshTokenRepository;
import com.example.auth.repository.authRepo;
import com.example.auth.util.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Service for authentication operations
 */
@Service
@Transactional
public class AuthService {
    
    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);
    
    @Autowired
    private authRepo userRepository;
    
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Autowired
    private AuthenticationManager authenticationManager;
    
    @Autowired
    private JwtUtil jwtUtil;
    
    /**
     * Register a new user
     * Note: For multi-module setup, student validation should be handled via API call or shared service
     */
    public AuthResponse register(RegisterRequest request) {
        try {
            logger.info("Attempting to register user: {}", request.getUsername());
            
            // Check if username already exists
            if (userRepository.existsByUsername(request.getUsername())) {
                return AuthResponse.error("Username is already taken!");
            }
            
            // Check if email already exists
            if (request.getEmail() != null && userRepository.existsByEmail(request.getEmail())) {
                return AuthResponse.error("Email is already in use!");
            }
            
            // Check if roll number already exists in users table
            if (userRepository.existsByRollNo(request.getRollNo())) {
                return AuthResponse.error("Roll number is already registered!");
            }
            
            // TODO: In multi-module setup, validate roll number exists in student records via API call
            // For now, we'll skip this validation
            
            // Create new user
            User user = new User();
            user.setUsername(request.getUsername());
            user.setPassword(passwordEncoder.encode(request.getPassword()));
            user.setEmail(request.getEmail());
            user.setRollNo(request.getRollNo());
            
            // Set role based on request, default to STUDENT
            Role userRole = Role.STUDENT;
            if (request.getRole() != null) {
                try {
                    userRole = Role.valueOf(request.getRole().toUpperCase());
                } catch (IllegalArgumentException e) {
                    logger.warn("Invalid role provided: {}, defaulting to STUDENT", request.getRole());
                }
            }
            user.setRole(userRole);
            
            logger.info("Creating user with role: {}", userRole);
            
            // Save user
            user = userRepository.save(user);
            
            // Generate tokens
            String accessToken = jwtUtil.generateAccessToken(user);
            String refreshToken = jwtUtil.generateRefreshToken(user);
            
            logger.debug("Generated access token for user {}: {}...", user.getUsername(), 
                        accessToken.substring(0, Math.min(50, accessToken.length())));
            logger.debug("Access token is valid: {}", jwtUtil.isValidToken(accessToken));
            logger.debug("Access token is access type: {}", jwtUtil.isAccessToken(accessToken));
            
            // Save refresh token
            saveRefreshToken(user, refreshToken);
            
            // Create user info
            UserInfo userInfo = new UserInfo(user.getId(), user.getUsername(), 
                                           user.getEmail(), user.getRollNo(), user.getRole(),
                                           user.isEnabled(), user.isAccountNonExpired(),
                                           user.isAccountNonLocked(), user.isCredentialsNonExpired(),
                                           user.getCreatedAt(), user.getUpdatedAt());
            
            logger.info("Successfully registered user: {}", user.getUsername());
            
            return AuthResponse.success("User registered successfully", accessToken, refreshToken, 
                                      jwtUtil.getAccessTokenExpirationInSeconds(), userInfo);
            
        } catch (Exception e) {
            logger.error("Registration failed for user: {}", request.getUsername(), e);
            return AuthResponse.error("Registration failed: " + e.getMessage());
        }
    }
    
    /**
     * Authenticate user and generate tokens
     */
    public AuthResponse login(LoginRequest request) {
        try {
            logger.info("Attempting to authenticate user: {}", request.getUsername());
            
            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );
            
            User user = (User) authentication.getPrincipal();
            
            // Generate tokens
            String accessToken = jwtUtil.generateAccessToken(user);
            String refreshToken = jwtUtil.generateRefreshToken(user);
            
            logger.debug("Generated access token for login user {}: {}...", user.getUsername(), 
                        accessToken.substring(0, Math.min(50, accessToken.length())));
            logger.debug("Login access token is valid: {}", jwtUtil.isValidToken(accessToken));
            logger.debug("Login access token is access type: {}", jwtUtil.isAccessToken(accessToken));
            
            // Revoke old refresh tokens and save new one
            refreshTokenRepository.revokeAllTokensByUser(user);
            saveRefreshToken(user, refreshToken);
            
            // Create user info
            UserInfo userInfo = new UserInfo(user.getId(), user.getUsername(), 
                                           user.getEmail(), user.getRollNo(), user.getRole(),
                                           user.isEnabled(), user.isAccountNonExpired(),
                                           user.isAccountNonLocked(), user.isCredentialsNonExpired(),
                                           user.getCreatedAt(), user.getUpdatedAt());
            
            logger.info("Successfully authenticated user: {}", user.getUsername());
            
            return AuthResponse.success("Login successful", accessToken, refreshToken, 
                                      jwtUtil.getAccessTokenExpirationInSeconds(), userInfo);
            
        } catch (AuthenticationException e) {
            logger.error("Authentication failed for user: {}", request.getUsername(), e);
            return AuthResponse.error("Invalid username or password");
        } catch (Exception e) {
            logger.error("Login failed for user: {}", request.getUsername(), e);
            return AuthResponse.error("Login failed: " + e.getMessage());
        }
    }
    
    /**
     * Refresh access token using refresh token
     */
    public AuthResponse refreshToken(RefreshTokenRequest request) {
        try {
            String refreshTokenValue = request.getRefreshToken();
            
            // Validate refresh token format
            if (!jwtUtil.isValidToken(refreshTokenValue) || !jwtUtil.isRefreshToken(refreshTokenValue)) {
                return AuthResponse.error("Invalid refresh token");
            }
            
            // Find refresh token in database
            Optional<RefreshToken> refreshTokenOpt = refreshTokenRepository.findByToken(refreshTokenValue);
            if (refreshTokenOpt.isEmpty()) {
                return AuthResponse.error("Refresh token not found");
            }
            
            RefreshToken refreshToken = refreshTokenOpt.get();
            
            // Check if token is valid
            if (!refreshToken.isValid()) {
                return AuthResponse.error("Refresh token is expired or revoked");
            }
            
            User user = refreshToken.getUser();
            
            // Generate new access token
            String newAccessToken = jwtUtil.generateAccessToken(user);
            
            // Create user info
            UserInfo userInfo = new UserInfo(user.getId(), user.getUsername(), 
                                           user.getEmail(), user.getRollNo(), user.getRole(),
                                           user.isEnabled(), user.isAccountNonExpired(),
                                           user.isAccountNonLocked(), user.isCredentialsNonExpired(),
                                           user.getCreatedAt(), user.getUpdatedAt());
            
            logger.info("Successfully refreshed token for user: {}", user.getUsername());
            
            return AuthResponse.success("Token refreshed successfully", newAccessToken, refreshTokenValue, 
                                      jwtUtil.getAccessTokenExpirationInSeconds(), userInfo);
            
        } catch (Exception e) {
            logger.error("Token refresh failed", e);
            return AuthResponse.error("Token refresh failed: " + e.getMessage());
        }
    }
    
    /**
     * Logout user by revoking refresh tokens
     */
    public AuthResponse logout(String refreshTokenValue) {
        try {
            logger.info("Processing logout request with refresh token: {}", 
                       refreshTokenValue != null ? "present" : "null");
            
            if (refreshTokenValue != null && !refreshTokenValue.trim().isEmpty()) {
                logger.info("Attempting to revoke refresh token");
                refreshTokenRepository.revokeToken(refreshTokenValue.trim());
                logger.info("Refresh token revoked successfully");
            } else {
                logger.info("No refresh token provided, skipping token revocation");
            }
            
            logger.info("User logged out successfully");
            return AuthResponse.success("Logout successful", null, null, null, null);
            
        } catch (Exception e) {
            logger.error("Logout failed", e);
            // Return success even if token revocation fails
            logger.warn("Logout completed with errors, but treating as successful");
            return AuthResponse.success("Logout completed", null, null, null, null);
        }
    }
    
    /**
     * Get user profile information
     */
    public UserInfo getUserProfile(String username) {
        try {
            logger.info("Getting user profile for username: {}", username);
            
            if (username == null || username.trim().isEmpty()) {
                logger.warn("Username is null or empty");
                return null;
            }
            
            Optional<User> userOpt = userRepository.findByUsername(username.trim());
            if (userOpt.isPresent()) {
                User user = userOpt.get();
                logger.info("User found: {}", user.getUsername());
                
                UserInfo userInfo = new UserInfo(user.getId(), user.getUsername(), 
                                  user.getEmail(), user.getRollNo(), user.getRole(),
                                  user.isEnabled(), user.isAccountNonExpired(),
                                  user.isAccountNonLocked(), user.isCredentialsNonExpired(),
                                  user.getCreatedAt(), user.getUpdatedAt());
                
                logger.info("UserInfo created successfully for user: {}", username);
                return userInfo;
            } else {
                logger.warn("User not found with username: {}", username);
                return null;
            }
        } catch (Exception e) {
            logger.error("Error getting user profile for username: {}", username, e);
            return null;
        }
    }
    
    /**
     * Save refresh token to database
     */
    private void saveRefreshToken(User user, String tokenValue) {
        LocalDateTime expiresAt = LocalDateTime.now().plusSeconds(jwtUtil.getRefreshTokenExpirationInSeconds());
        RefreshToken refreshToken = new RefreshToken(tokenValue, user, expiresAt);
        refreshTokenRepository.save(refreshToken);
    }
    
    /**
     * Clean up expired tokens (can be called by a scheduled task)
     */
    public void cleanupExpiredTokens() {
        refreshTokenRepository.deleteExpiredTokens(LocalDateTime.now());
        logger.info("Cleaned up expired refresh tokens");
    }
}