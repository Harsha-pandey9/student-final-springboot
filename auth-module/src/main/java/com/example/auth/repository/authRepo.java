package com.example.auth.repository;

import com.example.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface authRepo extends JpaRepository<User, Long> {
    /**
     * Find user by username or email
     */
    @Query("SELECT u FROM User u WHERE u.username = :usernameOrEmail OR u.email = :usernameOrEmail")
    Optional<User> findByUsernameOrEmail(@Param("usernameOrEmail") String usernameOrEmail);

    /**
     * Find enabled users by username
     */
    Optional<User> findByUsernameAndEnabled(String username, boolean enabled);

    Optional<User> findById(int id);

    /**
     * Find user by username
     */
    Optional<User> findByUsername(String username);

    /**
     * Find user by email
     */
    Optional<User> findByEmail(String email);

    /**
     * Find user by roll number
     */
    Optional<User> findByRollNo(Integer rollNo);

    /**
     * Check if username exists
     */
    boolean existsByUsername(String username);

    /**
     * Check if email exists
     */
    boolean existsByEmail(String email);

    /**
     * Check if roll number exists
     */
    boolean existsByRollNo(Integer rollNo);

    /**
     * Find user by username or email
     */

}
