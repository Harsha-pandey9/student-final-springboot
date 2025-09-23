package com.example.student.controller;

import com.example.auth.util.JwtUtil;
import com.example.student.model.Student;
import com.example.student.service.StudentService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/students")
@CrossOrigin(origins = "*")
public class StudentApiController {

    private static final Logger logger = LoggerFactory.getLogger(StudentApiController.class);

    @Autowired
    private StudentService studentService;

    @Autowired
    private JwtUtil jwtUtil;

    // ==================== CORE CRUD OPERATIONS ====================

    /**
     * GET /api/students
     * ADMIN and TEACHER can view all students, STUDENT can view only their own
     */
    @PreAuthorize("hasAnyRole('ADMIN','TEACHER','STUDENT')")
    @GetMapping
    public ResponseEntity<Map<String, Object>> getAllStudents() {
        try {
            List<Student> students = studentService.getAllStudents();
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            
            if (hasRole("STUDENT")) {
                response.put("message", "Your student record retrieved successfully");
            } else {
                response.put("message", "Students retrieved successfully");
            }
            
            response.put("data", students);
            response.put("count", students.size());
            response.put("userRole", getCurrentUserRole());
            return ResponseEntity.ok(response);
        } catch (AccessDeniedException e) {
            logger.warn("Access denied for user {}: {}", getCurrentUsername(), e.getMessage());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                    "success", false,
                    "message", "Access denied",
                    "error", e.getMessage()
            ));
        } catch (Exception e) {
            logger.error("Error retrieving students for user {}", getCurrentUsername(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "success", false,
                    "message", "Error retrieving students",
                    "error", e.getMessage()
            ));
        }
    }

    /**
     * GET /api/students/{id}
     * ADMIN and TEACHER can view any student
     * STUDENT can only view their own record
     */
    @PreAuthorize("hasAnyRole('ADMIN','TEACHER','STUDENT')")
    @GetMapping("/{id}")
    public ResponseEntity<Map<String, Object>> getStudentById(@PathVariable Long id) {
        try {
            Optional<Student> student = studentService.getStudentById(id);

            if (student.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of(
                        "success", false,
                        "message", "Student not found",
                        "error", "No student exists with ID: " + id
                ));
            }

            // Attribute-based check: STUDENT can only access their own rollNo
            if (hasRole("STUDENT")) {
                Integer userRollNo = getCurrentUserRollNo();
                if (userRollNo == null || !student.get().getRollNo().equals(userRollNo)) {
                    logger.warn("Access denied: Student {} (roll: {}) attempted to access student {} (roll: {})", 
                               getCurrentUsername(), userRollNo, id, student.get().getRollNo());
                    return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                            "success", false,
                            "message", "Access denied",
                            "error", "Students can only access their own record"
                    ));
                }
            }

            logger.debug("User {} accessing student {} (roll: {})", 
                        getCurrentUsername(), id, student.get().getRollNo());
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Student retrieved successfully",
                    "data", student.get()
            ));
        } catch (Exception e) {
            logger.error("Error retrieving student with ID {}: {}", id, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "success", false,
                    "message", "Error retrieving student",
                    "error", e.getMessage()
            ));
        }
    }

    /**
     * POST /api/students
     * Only ADMIN can create students
     */
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping
    public ResponseEntity<Map<String, Object>> createStudent(@Valid @RequestBody Student student) {
        try {
            Student savedStudent = studentService.saveStudent(student);
            logger.info("Student created successfully by admin {}: {} (roll: {})", 
                       getCurrentUsername(), savedStudent.getName(), savedStudent.getRollNo());
            return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                    "success", true,
                    "message", "Student created successfully",
                    "data", savedStudent
            ));
        } catch (AccessDeniedException e) {
            logger.warn("Access denied for user {}: {}", getCurrentUsername(), e.getMessage());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                    "success", false,
                    "message", "Access denied",
                    "error", e.getMessage()
            ));
        } catch (RuntimeException e) {
            logger.error("Error creating student for user {}: {}", getCurrentUsername(), e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                    "success", false,
                    "message", "Error creating student",
                    "error", e.getMessage()
            ));
        }
    }

    /**
     * PUT /api/students/{id}
     * Only ADMIN can fully update student
     */
    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/{id}")
    public ResponseEntity<Map<String, Object>> updateStudent(@PathVariable Long id, @Valid @RequestBody Student studentDetails) {
        try {
            Student updatedStudent = studentService.updateStudent(id, studentDetails);
            logger.info("Student updated successfully by admin {}: {} (ID: {})", 
                       getCurrentUsername(), updatedStudent.getName(), id);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Student updated successfully",
                    "data", updatedStudent
            ));
        } catch (RuntimeException e) {
            logger.error("Error updating student with ID {}: {}", id, e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                    "success", false,
                    "message", "Error updating student",
                    "error", e.getMessage()
            ));
        }
    }
    
    /**
     * PATCH /api/students/{id}
     * Only ADMIN can partially update student
     */
    @PreAuthorize("hasRole('ADMIN')")
    @PatchMapping("/{id}")
    public ResponseEntity<Map<String, Object>> partialUpdateStudent(@PathVariable Long id, @RequestBody Student studentDetails) {
        try {
            Student updatedStudent = studentService.partialUpdateStudent(id, studentDetails);
            logger.info("Student partially updated successfully by admin {}: {} (ID: {})", 
                       getCurrentUsername(), updatedStudent.getName(), id);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Student updated successfully",
                    "data", updatedStudent
            ));
        } catch (RuntimeException e) {
            logger.error("Error partially updating student with ID {}: {}", id, e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                    "success", false,
                    "message", "Error updating student",
                    "error", e.getMessage()
            ));
        }
    }

    /**
     * DELETE /api/students/{id}
     * Only ADMIN can delete student
     */
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{id}")
    public ResponseEntity<Map<String, Object>> deleteStudent(@PathVariable Long id) {
        try {
            Optional<Student> existingStudent = studentService.getStudentById(id);
            if (existingStudent.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of(
                        "success", false,
                        "message", "Student not found",
                        "error", "No student exists with ID: " + id
                ));
            }

            Student studentToDelete = existingStudent.get();
            studentService.deleteStudent(id);
            logger.info("Student deleted successfully by admin {}: {} (ID: {})", 
                       getCurrentUsername(), studentToDelete.getName(), id);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Student '" + studentToDelete.getName() + "' (ID: " + id + ") deleted successfully",
                    "deletedStudent", studentToDelete
            ));
        } catch (Exception e) {
            logger.error("Error deleting student with ID {}: {}", id, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "success", false,
                    "message", "Error deleting student",
                    "error", e.getMessage()
            ));
        }
    }

    // ==================== SEARCH & FILTER ENDPOINTS ====================

    /**
     * GET /api/students/search?name={name}
     * ADMIN and TEACHER only
     */
    @PreAuthorize("hasAnyRole('ADMIN','TEACHER')")
    @GetMapping("/search")
    public ResponseEntity<Map<String, Object>> searchStudentsByName(@RequestParam String name) {
        try {
            if (name == null || name.trim().isEmpty()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                        "success", false,
                        "message", "Search term cannot be empty",
                        "error", "Please provide a valid name to search"
                ));
            }
            
            List<Student> students = studentService.searchStudentsByName(name);
            logger.debug("User {} searching students by name: {}", getCurrentUsername(), name);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Search completed for: " + name,
                    "data", students,
                    "count", students.size(),
                    "searchTerm", name
            ));
        } catch (Exception e) {
            logger.error("Error searching students by name '{}': {}", name, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "success", false,
                    "message", "Error searching students",
                    "error", e.getMessage()
            ));
        }
    }

    /**
     * GET /api/students/rollno/{rollNo}
     * ADMIN/TEACHER can view any student, STUDENT can view only their own
     */
    @PreAuthorize("hasAnyRole('ADMIN','TEACHER','STUDENT')")
    @GetMapping("/rollno/{rollNo}")
    public ResponseEntity<Map<String, Object>> getStudentByRollNo(@PathVariable Integer rollNo) {
        try {
            Optional<Student> student = studentService.getStudentByRollNo(rollNo);

            if (student.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of(
                        "success", false,
                        "message", "Student not found",
                        "error", "No student exists with roll number: " + rollNo
                ));
            }

            // Attribute-based check for STUDENT
            if (hasRole("STUDENT")) {
                Integer userRollNo = getCurrentUserRollNo();
                if (userRollNo == null || !student.get().getRollNo().equals(userRollNo)) {
                    logger.warn("Access denied: Student {} (roll: {}) attempted to access student with roll: {}", 
                               getCurrentUsername(), userRollNo, rollNo);
                    return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                            "success", false,
                            "message", "Access denied",
                            "error", "Students can only access their own record"
                    ));
                }
            }

            logger.debug("User {} accessing student with roll number: {}", getCurrentUsername(), rollNo);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Student found with roll number: " + rollNo,
                    "data", student.get()
            ));
        } catch (Exception e) {
            logger.error("Error retrieving student with roll number {}: {}", rollNo, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "success", false,
                    "message", "Error retrieving student",
                    "error", e.getMessage()
            ));
        }
    }

    /**
     * GET /api/students/branch/{branch}
     * Get students by branch - ADMIN and TEACHER only
     */
    @PreAuthorize("hasAnyRole('ADMIN','TEACHER')")
    @GetMapping("/branch/{branch}")
    public ResponseEntity<Map<String, Object>> getStudentsByBranch(@PathVariable String branch) {
        try {
            List<Student> students = studentService.getStudentsByBranch(branch);
            logger.debug("User {} accessing students by branch: {}", getCurrentUsername(), branch);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Students retrieved for branch: " + branch,
                    "data", students,
                    "count", students.size(),
                    "branch", branch
            ));
        } catch (Exception e) {
            logger.error("Error retrieving students by branch '{}': {}", branch, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "success", false,
                    "message", "Error retrieving students",
                    "error", e.getMessage()
            ));
        }
    }

    /**
     * GET /api/students/course/{course}
     * Get students by course - ADMIN and TEACHER only
     */
    @PreAuthorize("hasAnyRole('ADMIN','TEACHER')")
    @GetMapping("/course/{course}")
    public ResponseEntity<Map<String, Object>> getStudentsByCourse(@PathVariable String course) {
        try {
            List<Student> students = studentService.getStudentsByCourse(course);
            logger.debug("User {} accessing students by course: {}", getCurrentUsername(), course);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Students retrieved for course: " + course,
                    "data", students,
                    "count", students.size(),
                    "course", course
            ));
        } catch (Exception e) {
            logger.error("Error retrieving students by course '{}': {}", course, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "success", false,
                    "message", "Error retrieving students",
                    "error", e.getMessage()
            ));
        }
    }
    
    // Helper method to check if current user has a specific role
    private boolean hasRole(String role) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return false;
        }
        return auth.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals("ROLE_" + role));
    }
    
    // Helper method to get current username
    private String getCurrentUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return "anonymous";
        }
        return auth.getName();
    }
    
    // Helper method to get current user's role
    private String getCurrentUserRole() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return null;
        }
        return auth.getAuthorities().stream()
                .findFirst()
                .map(authority -> authority.getAuthority().replace("ROLE_", ""))
                .orElse(null);
    }
    
    // Helper method to get current user's roll number
    private Integer getCurrentUserRollNo() {
        try {
            return jwtUtil.getCurrentUserRollNo();
        } catch (Exception e) {
            return null;
        }
    }
}
