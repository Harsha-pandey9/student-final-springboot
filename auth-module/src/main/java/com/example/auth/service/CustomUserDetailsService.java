package com.example.auth.service;

import com.example.auth.model.User;
import com.example.auth.repository.authRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import jakarta.annotation.PostConstruct;

/**
 * Custom UserDetailsService implementation for Spring Security
 */
@Service("authModuleCustomUserDetailsService")
public class CustomUserDetailsService implements UserDetailsService {

    // Constructor to verify bean creation
    public CustomUserDetailsService() {
        System.out.println("✅ CustomUserDetailsService bean created successfully!");
    }

    private static final Logger logger = LoggerFactory.getLogger(CustomUserDetailsService.class);

    @Autowired
    private authRepo authRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        logger.debug("Loading user by username: {}", username);

        User user = authRepository.findByUsernameOrEmail(username)
                .orElseThrow(() -> {
                    logger.error("User not found with username or email: {}", username);
                    return new UsernameNotFoundException("User not found with username or email: " + username);
                });

        logger.debug("Successfully loaded user: {}", user.getUsername());
        return user;
    }

    /**
     * Load user by ID (useful for JWT token validation)
     */
    @Transactional
    public UserDetails loadUserById(Long id) {
        logger.debug("Loading user by ID: {}", id);

        User user = authRepository.findById(id)
                .orElseThrow(() -> {
                    logger.error("User not found with ID: {}", id);
                    return new UsernameNotFoundException("User not found with ID: " + id);
                });

        logger.debug("Successfully loaded user by ID: {}", user.getUsername());
        return user;
    }
}