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

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
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

    private static final SecureRandom secureRandom = new SecureRandom();
    private static final Base64.Encoder base64Encoder = Base64.getUrlEncoder().withoutPadding();

    /**
     * Generate a 32-character random refresh token
     */
    public String generateRandomRefreshToken() {
        byte[] randomBytes = new byte[24]; // 24 bytes → ~32 chars in Base64 URL encoding
        secureRandom.nextBytes(randomBytes);
        return base64Encoder.encodeToString(randomBytes);
    }

    /**
     * Register a new user
     */
    public AuthResponse register(RegisterRequest request) {
        try {
            logger.info("Attempting to register user: {}", request.getUsername());

            if (userRepository.existsByUsername(request.getUsername())) {
                return AuthResponse.error("Username is already taken!");
            }

            if (request.getEmail() != null && userRepository.existsByEmail(request.getEmail())) {
                return AuthResponse.error("Email is already in use!");
            }

            if (userRepository.existsByRollNo(request.getRollNo())) {
                return AuthResponse.error("Roll number is already registered!");
            }

            User user = new User();
            user.setUsername(request.getUsername());
            user.setPassword(passwordEncoder.encode(request.getPassword()));
            user.setEmail(request.getEmail());
            user.setRollNo(request.getRollNo());

            Role userRole = Role.STUDENT;
            if (request.getRole() != null) {
                try {
                    userRole = Role.valueOf(request.getRole().toUpperCase());
                } catch (IllegalArgumentException e) {
                    logger.warn("Invalid role provided: {}, defaulting to STUDENT", request.getRole());
                }
            }
            user.setRole(userRole);

            user = userRepository.save(user);

            String accessToken = jwtUtil.generateAccessToken(user);
            String refreshToken = generateRandomRefreshToken();

            saveRefreshToken(user, refreshToken);

            UserInfo userInfo = new UserInfo(user.getId(), user.getUsername(),
                    user.getEmail(), user.getRollNo(), user.getRole(),
                    user.isEnabled(), user.isAccountNonExpired(),
                    user.isAccountNonLocked(), user.isCredentialsNonExpired(),
                    user.getCreatedAt(), user.getUpdatedAt());

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
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );

            User user = (User) authentication.getPrincipal();

            String accessToken = jwtUtil.generateAccessToken(user);
            String refreshToken = generateRandomRefreshToken();

            refreshTokenRepository.revokeAllTokensByUser(user);
            saveRefreshToken(user, refreshToken);

            UserInfo userInfo = new UserInfo(user.getId(), user.getUsername(),
                    user.getEmail(), user.getRollNo(), user.getRole(),
                    user.isEnabled(), user.isAccountNonExpired(),
                    user.isAccountNonLocked(), user.isCredentialsNonExpired(),
                    user.getCreatedAt(), user.getUpdatedAt());

            return AuthResponse.success("Login successful", accessToken, refreshToken,
                    jwtUtil.getAccessTokenExpirationInSeconds(), userInfo);

        } catch (AuthenticationException e) {
            return AuthResponse.error("Invalid username or password");
        } catch (Exception e) {
            return AuthResponse.error("Login failed: " + e.getMessage());
        }
    }

    /**
     * Refresh access token using refresh token
     */
    public AuthResponse refreshToken(RefreshTokenRequest request) {
        try {
            Optional<RefreshToken> refreshTokenOpt = refreshTokenRepository.findByToken(request.getRefreshToken());
            if (refreshTokenOpt.isEmpty() || !refreshTokenOpt.get().isValid()) {
                return AuthResponse.error("Refresh token is invalid or expired");
            }

            User user = refreshTokenOpt.get().getUser();
            String oldAccessToken = request.getAccessToken();
            if (oldAccessToken != null && jwtUtil.validateToken(oldAccessToken, user)) {
                // Old token is still valid, return it
                UserInfo userInfo = new UserInfo(user.getId(), user.getUsername(),
                        user.getEmail(), user.getRollNo(), user.getRole(),
                        user.isEnabled(), user.isAccountNonExpired(),
                        user.isAccountNonLocked(), user.isCredentialsNonExpired(),
                        user.getCreatedAt(), user.getUpdatedAt());

                return AuthResponse.success(
                        "Token still valid, returning old token",
                        oldAccessToken,
                        request.getRefreshToken(),
                        jwtUtil.getAccessTokenExpirationInSeconds(),
                        userInfo
                );
            }

            // Old token is missing or expired → generate a new one
            String newAccessToken = jwtUtil.generateAccessToken(user);

            UserInfo userInfo = new UserInfo(user.getId(), user.getUsername(),
                    user.getEmail(), user.getRollNo(), user.getRole(),
                    user.isEnabled(), user.isAccountNonExpired(),
                    user.isAccountNonLocked(), user.isCredentialsNonExpired(),
                    user.getCreatedAt(), user.getUpdatedAt());

            return AuthResponse.success(
                    "Token refreshed successfully",
                    newAccessToken,
                    request.getRefreshToken(),
                    jwtUtil.getAccessTokenExpirationInSeconds(),
                    userInfo
            );

        } catch (Exception e) {
            return AuthResponse.error("Token refresh failed: " + e.getMessage());
        }
    }


    /**
     * Get user profile information
     */
    public UserInfo getUserProfile(String username) {
        Optional<User> userOpt = userRepository.findByUsername(username.trim());
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            return new UserInfo(user.getId(), user.getUsername(),
                    user.getEmail(), user.getRollNo(), user.getRole(),
                    user.isEnabled(), user.isAccountNonExpired(),
                    user.isAccountNonLocked(), user.isCredentialsNonExpired(),
                    user.getCreatedAt(), user.getUpdatedAt());
        }
        return null;
    }

    /**
     * Save refresh token to DB
     */
    private void saveRefreshToken(User user, String refreshTokenValue) {
        LocalDateTime expiresAt = LocalDateTime.now().plusDays(30);
        RefreshToken refreshToken = new RefreshToken(refreshTokenValue, user, expiresAt);
        refreshTokenRepository.save(refreshToken);
    }



    /**
     * Cleanup expired tokens
     */
    public void cleanupExpiredTokens() {
        refreshTokenRepository.deleteExpiredTokens(LocalDateTime.now());
    }
    public AuthResponse logout(String refreshTokenValue) {
        try {
            if (refreshTokenValue != null && !refreshTokenValue.trim().isEmpty()) {
                refreshTokenRepository.revokeToken(refreshTokenValue.trim());
            }
            return AuthResponse.success("Logout successful", null, null, null, null);
        } catch (Exception e) {
            return AuthResponse.success("Logout completed", null, null, null, null);
        }
    }


}
