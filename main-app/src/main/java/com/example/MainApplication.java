package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication(scanBasePackages = {
    "com.example.config",      // Main app config
    "com.example.controller",   // Main app controllers  
    "com.example.service",     // Main app services
    "com.example.model",       // Main app models
    "com.example.event",       // Event classes
    "com.example.notification", // Notification services
    "com.example.auth",        // Auth module components
    "com.example.student"      // Student module components
})
@EntityScan(basePackages = {
    "com.example.model",
    "com.example.auth.model",   // Auth module entities
    "com.example.student.model" // Student module entities
})
@EnableJpaRepositories(basePackages = {
    "com.example.auth.repository",   // Auth module repositories
    "com.example.student.repository" // Student module repositories
})
public class MainApplication {
    public static void main(String[] args) {
        SpringApplication.run(MainApplication.class, args);
    }
}