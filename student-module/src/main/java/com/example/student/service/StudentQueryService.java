package com.example.student.service;

import com.example.student.exception.StudentExceptions.StudentNotFoundException;
import com.example.student.model.Student;
import com.example.student.repository.StudentRepository;
import com.example.auth.util.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class StudentQueryService {

    private static final Logger logger = LoggerFactory.getLogger(StudentQueryService.class);

    @Autowired
    private StudentRepository studentRepository;

    @Autowired
    private JwtUtil jwtUtil;

    @PreAuthorize("hasRole('ADMIN') or hasRole('TEACHER') or hasRole('STUDENT')")
    public List<Student> getAllStudents() {
        if (hasRole("ADMIN") || hasRole("TEACHER")) {
            return studentRepository.findAll();
        } else if (hasRole("STUDENT")) {
            Integer userRollNo = getCurrentUserRollNo();
            return studentRepository.findByRollNo(userRollNo).map(List::of).orElse(List.of());
        }
        throw new AccessDeniedException("You don't have permission to view all students");
    }

    @PreAuthorize("hasRole('ADMIN') or hasRole('TEACHER') or hasRole('STUDENT')")
    public Student getStudentById(Long id) {
        Student student = studentRepository.findById(id)
                .orElseThrow(() -> new StudentNotFoundException(id));
        if (hasRole("STUDENT") && !student.getRollNo().equals(getCurrentUserRollNo())) {
            throw new AccessDeniedException("You don't have permission to view this student");
        }
        return student;
    }

    @PreAuthorize("hasRole('ADMIN') or hasRole('TEACHER')")
    public List<Student> searchStudentsByName(String name) {
        return studentRepository.findByNameContainingIgnoreCase(name);
    }

    @PreAuthorize("hasRole('ADMIN') or hasRole('TEACHER')")
    public List<Student> getStudentsByBranch(String branch) {
        return studentRepository.findByBranch(branch);
    }

    @PreAuthorize("hasRole('ADMIN') or hasRole('TEACHER')")
    public List<Student> getStudentsByCourse(String course) {
        return studentRepository.findByCourse(course);
    }

    private boolean hasRole(String role) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null && auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_" + role));
    }

    private Integer getCurrentUserRollNo() {
        try {
            return jwtUtil.getCurrentUserRollNo();
        } catch (Exception e) {
            logger.error("Error getting current user roll number", e);
            return null;
        }
    }
}
