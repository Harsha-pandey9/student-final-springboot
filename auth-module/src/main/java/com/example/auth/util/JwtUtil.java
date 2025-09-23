package com.example.auth.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Utility class for JWT operations
 */
@Component
public class JwtUtil {
    
    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);
    
    @Value("${jwt.secret:mySecretKey123456789012345678901234567890}")
    private String jwtSecret;
    
    @Value("${jwt.access-token-expiration:1800000}") // 30 minutes
    private Long accessTokenExpiration;
    
    @Value("${jwt.refresh-token-expiration:2592000000}") // 30 days
    private Long refreshTokenExpiration;
    
    /**
     * Get signing key for JWT
     */
    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }
    
    /**
     * Generate access token
     */
    public String generateAccessToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("tokenType", "ACCESS");
        
        // Add user details if UserDetails is our custom User class
        if (userDetails instanceof com.example.auth.model.User) {
            com.example.auth.model.User user = (com.example.auth.model.User) userDetails;
            claims.put("userId", user.getId());
            claims.put("role", user.getRole().name());
            claims.put("rollNo", user.getRollNo());
        }
        
        return createToken(claims, userDetails.getUsername(), accessTokenExpiration);
    }
    
    /**
     * Generate refresh token
     */
    public String generateRefreshToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("tokenType", "REFRESH");
        claims.put("type", "refresh"); // Keep for backward compatibility
        return createToken(claims, userDetails.getUsername(), refreshTokenExpiration);
    }
    
    /**
     * Create JWT token
     */
    private String createToken(Map<String, Object> claims, String subject, Long expiration) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);
        
        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey())
                .compact();
    }
    
    /**
     * Extract username from token
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }
    
    /**
     * Extract expiration date from token
     */
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
    
    /**
     * Extract user ID from JWT token
     */
    public Long extractUserId(String token) {
        try {
            Claims claims = extractAllClaims(token);
            return claims.get("userId", Long.class);
        } catch (Exception e) {
            logger.error("Error extracting user ID from token", e);
            return null;
        }
    }
    
    /**
     * Extract user role from JWT token
     */
    public String extractRole(String token) {
        try {
            Claims claims = extractAllClaims(token);
            return claims.get("role", String.class);
        } catch (Exception e) {
            logger.error("Error extracting role from token", e);
            return null;
        }
    }
    
    /**
     * Extract user roll number from JWT token
     */
    public Integer extractRollNo(String token) {
        try {
            Claims claims = extractAllClaims(token);
            return claims.get("rollNo", Integer.class);
        } catch (Exception e) {
            logger.error("Error extracting roll number from token", e);
            return null;
        }
    }
    
    /**
     * Extract specific claim from token
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    
    /**
     * Extract all claims from token
     */
    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException e) {
            logger.error("Failed to parse JWT token: {}", e.getMessage());
            throw e;
        }
    }
    
    /**
     * Check if token is expired
     */
    public Boolean isTokenExpired(String token) {
        try {
            return extractExpiration(token).before(new Date());
        } catch (JwtException e) {
            logger.error("Error checking token expiration: {}", e.getMessage());
            return true;
        }
    }
    
    /**
     * Validate token against user details
     */
    public Boolean validateToken(String token, UserDetails userDetails) {
        try {
            final String username = extractUsername(token);
            return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
        } catch (JwtException e) {
            logger.error("Token validation failed: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * Validate token format and signature
     */
    public Boolean isValidToken(String token) {
        try {
            if (token == null || token.trim().isEmpty()) {
                return false;
            }
            
            extractAllClaims(token);
            return !isTokenExpired(token);
        } catch (ExpiredJwtException e) {
            logger.warn("JWT token is expired: {}", e.getMessage());
            return false;
        } catch (UnsupportedJwtException e) {
            logger.warn("JWT token is unsupported: {}", e.getMessage());
            return false;
        } catch (MalformedJwtException e) {
            logger.warn("JWT token is malformed: {}", e.getMessage());
            return false;
        } catch (SecurityException e) {
            logger.warn("JWT signature validation failed: {}", e.getMessage());
            return false;
        } catch (IllegalArgumentException e) {
            logger.warn("JWT token compact of handler are invalid: {}", e.getMessage());
            return false;
        } catch (JwtException e) {
            logger.error("Invalid token: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            logger.error("JWT token validation failed", e);
            return false;
        }
    }
    
    /**
     * Check if token is refresh token
     */
    public Boolean isRefreshToken(String token) {
        try {
            Claims claims = extractAllClaims(token);
            // Check new format first, then fall back to old format
            String tokenType = claims.get("tokenType", String.class);
            if (tokenType != null) {
                return "REFRESH".equals(tokenType);
            }
            // Backward compatibility
            return "refresh".equals(claims.get("type"));
        } catch (JwtException e) {
            logger.error("Error checking token type: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * Check if token is access token
     */
    public Boolean isAccessToken(String token) {
        try {
            Claims claims = extractAllClaims(token);
            
            String tokenType = claims.get("tokenType", String.class);
            if (tokenType != null) {
                return "ACCESS".equals(tokenType);
            }
            
            // Backward compatibility: if no tokenType, check if it's NOT a refresh token
            String type = claims.get("type", String.class);
            if (type != null) {
                return !"refresh".equals(type);
            }
            
            // If no type indicators, assume it's an access token (for older tokens)
            logger.debug("No token type found, assuming access token");
            return true;
        } catch (JwtException e) {
            logger.error("Error checking token type: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            logger.error("Error checking token type", e);
            return false;
        }
    }
    
    /**
     * Get token expiration time in seconds
     */
    public Long getAccessTokenExpirationInSeconds() {
        return accessTokenExpiration / 1000;
    }
    
    /**
     * Get refresh token expiration time in seconds
     */
    public Long getRefreshTokenExpirationInSeconds() {
        return refreshTokenExpiration / 1000;
    }
    
    // ========== USER CONTEXT UTILITY METHODS ==========
    
    /**
     * Get current user's roll number from session or JWT token
     */
    public Integer getCurrentUserRollNo() {
        try {
            HttpServletRequest request = getCurrentRequest();
            if (request == null) {
                return null;
            }
            
            // First try to get from session (set during authentication)
            Object rollNoObj = request.getSession().getAttribute("userRollNo");
            if (rollNoObj instanceof Integer) {
                return (Integer) rollNoObj;
            }
            
            // If not in session, try to extract from JWT token
            String token = getTokenFromRequest(request);
            if (token != null && isValidToken(token)) {
                return extractRollNo(token);
            }
            
            return null;
        } catch (Exception e) {
            logger.error("Error getting current user roll number", e);
            return null;
        }
    }
    
    /**
     * Get current user's username from session or JWT token
     */
    public String getCurrentUsername() {
        try {
            HttpServletRequest request = getCurrentRequest();
            if (request == null) {
                return null;
            }
            
            // First try to get from session
            String sessionUsername = (String) request.getSession().getAttribute("currentUser");
            if (sessionUsername != null) {
                return sessionUsername;
            }
            
            // If not in session, try to extract from JWT token
            String token = getTokenFromRequest(request);
            if (token != null && isValidToken(token)) {
                return extractUsername(token);
            }
            
            return null;
        } catch (Exception e) {
            logger.error("Error getting current username", e);
            return null;
        }
    }
    
    /**
     * Get current user's role from session or JWT token
     */
    public String getCurrentUserRole() {
        try {
            HttpServletRequest request = getCurrentRequest();
            if (request == null) {
                return null;
            }
            
            // First try to get from session
            String sessionRole = (String) request.getSession().getAttribute("currentRole");
            if (sessionRole != null) {
                return sessionRole;
            }
            
            // If not in session, try to extract from JWT token
            String token = getTokenFromRequest(request);
            if (token != null && isValidToken(token)) {
                return extractRole(token);
            }
            
            return null;
        } catch (Exception e) {
            logger.error("Error getting current user role", e);
            return null;
        }
    }
    
    /**
     * Get current user's ID from JWT token
     */
    public Long getCurrentUserId() {
        try {
            HttpServletRequest request = getCurrentRequest();
            if (request == null) {
                return null;
            }
            
            // Try to extract from JWT token
            String token = getTokenFromRequest(request);
            if (token != null && isValidToken(token)) {
                return extractUserId(token);
            }
            
            return null;
        } catch (Exception e) {
            logger.error("Error getting current user ID", e);
            return null;
        }
    }
    
    /**
     * Check if current user is admin
     */
    public boolean isCurrentUserAdmin() {
        String role = getCurrentUserRole();
        return "ADMIN".equals(role);
    }
    
    /**
     * Check if current user is student
     */
    public boolean isCurrentUserStudent() {
        String role = getCurrentUserRole();
        return "STUDENT".equals(role);
    }
    
    /**
     * Get current HTTP request
     */
    private HttpServletRequest getCurrentRequest() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return attributes != null ? attributes.getRequest() : null;
    }
    
    /**
     * Extract JWT token from request
     */
    private String getTokenFromRequest(HttpServletRequest request) {
        // Check session first
        Object sessionToken = request.getSession().getAttribute("accessToken");
        if (sessionToken instanceof String) {
            return (String) sessionToken;
        }
        
        // Check cookies
        if (request.getCookies() != null) {
            for (jakarta.servlet.http.Cookie cookie : request.getCookies()) {
                if ("accessToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        
        return null;
    }
}