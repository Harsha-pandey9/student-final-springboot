package com.example.student.repository;

import com.example.student.model.Student;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface StudentRepository extends JpaRepository<Student, Long> {
    
    // Find student by roll number
    Optional<Student> findByRollNo(Integer rollNo);
    
    // Find students by branch
    List<Student> findByBranch(String branch);
    
    // Find students by course
    List<Student> findByCourse(String course);
    
    // Check if student exists by roll number
    boolean existsByRollNo(Integer rollNo);
    
    // Custom query to find students by name containing (case insensitive)
    @Query("SELECT s FROM Student s WHERE LOWER(s.name) LIKE LOWER(CONCAT('%', :name, '%'))")
    List<Student> findByNameContainingIgnoreCase(@Param("name") String name);
}