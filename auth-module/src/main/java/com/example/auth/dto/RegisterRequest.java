package com.example.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * DTO for user registration requests
 */
@Data
public class RegisterRequest {

    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String username;

    @NotBlank(message = "Password is required")
    @Size(min = 6, message = "Password must be at least 6 characters long")
    private String password;

    @Email(message = "Email should be valid")
    private String email;

    @NotNull(message = "Roll number is required")
    @Positive(message = "Roll number must be positive")
    private Integer rollNo;

    private String role = "STUDENT"; // Default role

    // Default constructor
    public RegisterRequest() {}

    // Constructor
    public RegisterRequest(String username, String password, String email, Integer rollNo) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.rollNo = rollNo;
        this.role = "STUDENT";
    }

    // Constructor with role
    public RegisterRequest(String username, String password, String email, Integer rollNo, String role) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.rollNo = rollNo;
        this.role = role;
    }

    // Getters and Setters
//    public String getUsername() { return username; }
//    public void setUsername(String username) { this.username = username; }
//
//    public String getPassword() { return password; }
//    public void setPassword(String password) { this.password = password; }
//
//    public String getEmail() { return email; }
//    public void setEmail(String email) { this.email = email; }
//
//    public Integer getRollNo() { return rollNo; }
//    public void setRollNo(Integer rollNo) { this.rollNo = rollNo; }
//
//    public String getRole() { return role; }
//    public void setRole(String role) { this.role = role; }

//    @Override
//    public String toString() {
//        return "RegisterRequest{" +
//                "username='" + username + '\'' +
//                ", password='[PROTECTED]'" +
//                ", email='" + email + '\'' +
//                ", rollNo=" + rollNo +
//                ", role='" + role + '\'' +
//                '}';
//    }
}