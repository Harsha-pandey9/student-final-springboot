package com.example.auth.dto;

import com.example.auth.model.Role;
import java.time.LocalDateTime;

/**
 * DTO for user information in responses
 */
public class UserInfo {
    
    private Long id;
    private String username;
    private String email;
    private Integer rollNo;
    private Role role;
    private boolean enabled;
    private boolean accountNonExpired;
    private boolean accountNonLocked;
    private boolean credentialsNonExpired;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    
    // Default constructor
    public UserInfo() {}
    
    // Constructor with basic fields
    public UserInfo(Long id, String username, String email, Integer rollNo, Role role) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.rollNo = rollNo;
        this.role = role;
    }
    
    // Constructor with all fields
    public UserInfo(Long id, String username, String email, Integer rollNo, Role role,
                   boolean enabled, boolean accountNonExpired, boolean accountNonLocked,
                   boolean credentialsNonExpired, LocalDateTime createdAt, LocalDateTime updatedAt) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.rollNo = rollNo;
        this.role = role;
        this.enabled = enabled;
        this.accountNonExpired = accountNonExpired;
        this.accountNonLocked = accountNonLocked;
        this.credentialsNonExpired = credentialsNonExpired;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    
    public Integer getRollNo() { return rollNo; }
    public void setRollNo(Integer rollNo) { this.rollNo = rollNo; }
    
    public Role getRole() { return role; }
    public void setRole(Role role) { this.role = role; }
    
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    
    public boolean isAccountNonExpired() { return accountNonExpired; }
    public void setAccountNonExpired(boolean accountNonExpired) { this.accountNonExpired = accountNonExpired; }
    
    public boolean isAccountNonLocked() { return accountNonLocked; }
    public void setAccountNonLocked(boolean accountNonLocked) { this.accountNonLocked = accountNonLocked; }
    
    public boolean isCredentialsNonExpired() { return credentialsNonExpired; }
    public void setCredentialsNonExpired(boolean credentialsNonExpired) { this.credentialsNonExpired = credentialsNonExpired; }
    
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }
    
    @Override
    public String toString() {
        return "UserInfo{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", email='" + email + '\'' +
                ", rollNo=" + rollNo +
                ", role=" + role +
                '}';
    }
}