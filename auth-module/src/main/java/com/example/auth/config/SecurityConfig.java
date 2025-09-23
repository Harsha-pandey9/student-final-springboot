package com.example.auth.config;

import com.example.auth.filter.JwtAuthenticationFilter;
import com.example.auth.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

/**
 * Unified Security Configuration for Auth Module
 * - Single environment (no profiles)
 * - Configures JWT + CORS + Password encoding
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@ComponentScan(basePackages = {
        "com.example.auth.service",
        "com.example.auth.filter",
        "com.example.auth.util",
        "com.example.auth.controller"
})
public class SecurityConfig {

    @Autowired(required = false)
    private CustomUserDetailsService userDetailsService;

    @Autowired(required = false)
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    // ==================== COMMON BEANS ====================

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean(name = "mainAppAuthenticationProvider")
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(List.of("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    // ==================== SECURITY FILTER CHAIN ====================

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Disable CSRF for APIs
                .csrf(AbstractHttpConfigurer::disable)

                // Enable CORS
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // Stateless (because we’re using JWT)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Authorization rules
                .authorizeHttpRequests(authz -> authz
                        // Public endpoints
                        .requestMatchers("/", "/home", "/index").permitAll()
                        .requestMatchers("/api-info").permitAll()

                        // Authentication endpoints
                        .requestMatchers("/api/auth/**").permitAll()

                        // Login pages
                        .requestMatchers("/login", "/login/**").permitAll()
                        .requestMatchers("/jwt-login", "/jwt-login/**").permitAll()

                        // Static resources
                        .requestMatchers("/public/**").permitAll()
                        .requestMatchers("/css/**", "/js/**", "/images/**", "/favicon.ico").permitAll()
                        .requestMatchers("/error").permitAll()

                        // Swagger/OpenAPI endpoints
                        .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()

                        // Admin endpoints
                        .requestMatchers("/admin/**").hasRole("ADMIN")

                        // Everything else needs authentication
                        .anyRequest().authenticated()
                )

                // Register authentication provider
                .authenticationProvider(authenticationProvider());

        // Add JWT filter if available
        if (jwtAuthenticationFilter != null) {
            http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        }

        return http.build();
    }
}