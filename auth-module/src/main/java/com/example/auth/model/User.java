package com.example.auth.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

/**
 * User entity for authentication
 * Implements UserDetails for Spring Security integration
 */
@Entity
@Table(name = "users")
@Data
public class User implements UserDetails {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @NotBlank(message = "Username is required")
    @Column(unique = true, nullable = false)
    private String username;
    
    @NotBlank(message = "Password is required")
    @Column(nullable = false)
    private String password;
    
    @Email(message = "Email should be valid")
    @Column(unique = true)
    private String email;
    
    @NotNull(message = "Roll number is required")
    @Column(name = "roll_no", unique = true, nullable = false)
    private Integer rollNo;
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role = Role.STUDENT;
    
    @Column(name = "account_non_expired")
    private boolean accountNonExpired = true;
    
    @Column(name = "account_non_locked")
    private boolean accountNonLocked = true;
    
    @Column(name = "credentials_non_expired")
    private boolean credentialsNonExpired = true;
    
    @Column(name = "enabled")
    private boolean enabled = true;
    
    @Column(name = "created_at")
    private LocalDateTime createdAt;
    
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    // Default constructor
    public User() {}
    
    // Constructor
    public User(String username, String password, String email, Integer rollNo) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.rollNo = rollNo;
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }
    
    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
    
    // UserDetails implementation
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }
    
    @Override
    public String getPassword() {
        return password;
    }
    
    @Override
    public String getUsername() {
        return username;
    }
    
    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }
    
    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }
    
    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }
    
    @Override
    public boolean isEnabled() {
        return enabled;
    }
    
    // // Getters and Setters
    // public Long getId() { return id; }
    // public void setId(Long id) { this.id = id; }
    
    // public void setUsername(String username) { this.username = username; }
    
    // public void setPassword(String password) { this.password = password; }
    
    // public String getEmail() { return email; }
    // public void setEmail(String email) { this.email = email; }
    
    // public Integer getRollNo() { return rollNo; }
    // public void setRollNo(Integer rollNo) { this.rollNo = rollNo; }
    
    // public Role getRole() { return role; }
    // public void setRole(Role role) { this.role = role; }
    
    // public void setAccountNonExpired(boolean accountNonExpired) { this.accountNonExpired = accountNonExpired; }
    // public void setAccountNonLocked(boolean accountNonLocked) { this.accountNonLocked = accountNonLocked; }
    // public void setCredentialsNonExpired(boolean credentialsNonExpired) { this.credentialsNonExpired = credentialsNonExpired; }
    // public void setEnabled(boolean enabled) { this.enabled = enabled; }
    
    // public LocalDateTime getCreatedAt() { return createdAt; }
    // public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    
    // public LocalDateTime getUpdatedAt() { return updatedAt; }
    // public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }
    
    // @Override
    // public String toString() {
    //     return "User{" +
    //             "id=" + id +
    //             ", username='" + username + '\'' +
    //             ", email='" + email + '\'' +
    //             ", rollNo=" + rollNo +
    //             ", role=" + role +
    //             ", enabled=" + enabled +
    //             ", createdAt=" + createdAt +
    //             '}';
    // }
}