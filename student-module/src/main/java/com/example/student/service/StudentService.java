// package com.example.student.service;

// import com.example.auth.util.JwtUtil;
// import com.example.student.exception.StudentExceptions.DuplicateRollNumberException;
// import com.example.student.exception.StudentExceptions.InvalidStudentDataException;
// import com.example.student.exception.StudentExceptions.StudentNotFoundException;
// import com.example.student.model.Student;
// import com.example.student.repository.StudentRepository;
// import org.slf4j.Logger;
// import org.slf4j.LoggerFactory;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.security.access.AccessDeniedException;
// import org.springframework.security.access.prepost.PreAuthorize;
// import org.springframework.security.core.Authentication;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.stereotype.Service;

// import java.util.List;
// import java.util.Optional;

// @Service
// public class StudentService {
    
//     private static final Logger logger = LoggerFactory.getLogger(StudentService.class);
    
//     @Autowired
//     private StudentRepository studentRepository;
    
//     @Autowired
//     private JwtUtil jwtUtil;
//     // Save a new student (RBAC: Only admins can create students)
//     @PreAuthorize("hasRole('ADMIN')")
//     public Student saveStudent(Student student) {
//         // Validate student data
//         validateStudentData(student);
        
//         // Check if roll number already exists
//         if (studentRepository.existsByRollNo(student.getRollNo())) {
//             throw new DuplicateRollNumberException(student.getRollNo());
//         }
        
//         logger.info("Admin {} creating new student with roll number: {}", 
//                    getCurrentUsername(), student.getRollNo());
//         return studentRepository.save(student);
//     }
    
//     // Get all students (RBAC: Admins and teachers see all, students see only themselves)
//     @PreAuthorize("hasRole('ADMIN') or hasRole('TEACHER') or hasRole('STUDENT')")
//     public List<Student> getAllStudents() {
//         Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
//         if (hasRole("ADMIN") || hasRole("TEACHER")) {
//             logger.debug("Admin/Teacher {} accessing all students", getCurrentUsername());
//             return studentRepository.findAll();
//         } else if (hasRole("STUDENT")) {
//             // Students can only see their own record
//             Integer userRollNo = getCurrentUserRollNo();
//             if (userRollNo != null) {
//                 logger.debug("Student {} accessing own record with roll number: {}", 
//                            getCurrentUsername(), userRollNo);
//                 Optional<Student> studentOpt = studentRepository.findByRollNo(userRollNo);
//                 return studentOpt.map(List::of).orElse(List.of());
//             }
//         }
        
//         logger.warn("Access denied: User {} attempted to access all students without proper privileges", 
//                    getCurrentUsername());
//         throw new AccessDeniedException("You don't have permission to view all students");
//     }
    
//     // Get student by ID (RBAC: Admins/teachers see all, students see only themselves)
//     @PreAuthorize("hasRole('ADMIN') or hasRole('TEACHER') or hasRole('STUDENT')")
//     public Optional<Student> getStudentById(Long id) {
//         Optional<Student> studentOpt = studentRepository.findById(id);
        
//         if (studentOpt.isPresent()) {
//             Student student = studentOpt.get();
            
//             // If user is student, check if they can access this specific student
//             if (hasRole("STUDENT")) {
//                 Integer userRollNo = getCurrentUserRollNo();
//                 if (userRollNo == null || !student.getRollNo().equals(userRollNo)) {
//                     logger.warn("Access denied: Student {} (roll: {}) attempted to access student {} (roll: {})", 
//                                getCurrentUsername(), userRollNo, id, student.getRollNo());
//                     throw new AccessDeniedException("You don't have permission to view this student's details");
//                 }
//             }
            
//             logger.debug("User {} accessing student {} (roll: {})", 
//                         getCurrentUsername(), id, student.getRollNo());
//         }
        
//         return studentOpt;
//     }
    
//     // Get student by roll number (RBAC: Admins/teachers see all, students see only themselves)
//     @PreAuthorize("hasRole('ADMIN') or hasRole('TEACHER') or hasRole('STUDENT')")
//     public Optional<Student> getStudentByRollNo(Integer rollNo) {
//         // If user is student, check if they can access this specific student
//         if (hasRole("STUDENT")) {
//             Integer userRollNo = getCurrentUserRollNo();
//             if (userRollNo == null || !rollNo.equals(userRollNo)) {
//                 logger.warn("Access denied: Student {} (roll: {}) attempted to access student with roll: {}", 
//                            getCurrentUsername(), userRollNo, rollNo);
//                 throw new AccessDeniedException("You don't have permission to view this student's details");
//             }
//         }
        
//         logger.debug("User {} accessing student with roll number: {}", 
//                     getCurrentUsername(), rollNo);
//         return studentRepository.findByRollNo(rollNo);
//     }
    
//     // Update student (RBAC: Only admins can update students)
//     @PreAuthorize("hasRole('ADMIN')")
//     public Student updateStudent(Long id, Student studentDetails) {
//         // Validate student data
//         validateStudentData(studentDetails);
        
//         Student student = studentRepository.findById(id)
//                 .orElseThrow(() -> new StudentNotFoundException(id));
        
//         // Check if roll number is being changed and if new roll number already exists
//         if (!student.getRollNo().equals(studentDetails.getRollNo()) && 
//             studentRepository.existsByRollNo(studentDetails.getRollNo())) {
//             throw new DuplicateRollNumberException(studentDetails.getRollNo());
//         }
        
//         logger.info("Admin {} updating student {} (roll: {} -> {})", 
//                    getCurrentUsername(), id, student.getRollNo(), studentDetails.getRollNo());
        
//         student.setName(studentDetails.getName());
//         student.setRollNo(studentDetails.getRollNo());
//         student.setBranch(studentDetails.getBranch());
//         student.setCourse(studentDetails.getCourse());
        
//         return studentRepository.save(student);
//     }
    
//     // Delete student by ID (RBAC: Only admins can delete students)
//     @PreAuthorize("hasRole('ADMIN')")
//     public void deleteStudent(Long id) {
//         Student student = studentRepository.findById(id)
//                 .orElseThrow(() -> new StudentNotFoundException(id));
        
//         logger.info("Admin {} deleting student {} (roll: {})", 
//                    getCurrentUsername(), id, student.getRollNo());
//         studentRepository.delete(student);
//     }
    
//     // Get students by branch (RBAC: Only admins/teachers can view by branch)
//     @PreAuthorize("hasRole('ADMIN') or hasRole('TEACHER')")
//     public List<Student> getStudentsByBranch(String branch) {
//         logger.debug("User {} accessing students by branch: {}", 
//                     getCurrentUsername(), branch);
//         return studentRepository.findByBranch(branch);
//     }
    
//     // Get students by course (RBAC: Only admins/teachers can view by course)
//     @PreAuthorize("hasRole('ADMIN') or hasRole('TEACHER')")
//     public List<Student> getStudentsByCourse(String course) {
//         logger.debug("User {} accessing students by course: {}", 
//                     getCurrentUsername(), course);
//         return studentRepository.findByCourse(course);
//     }
    
//     // Search students by name (RBAC: Only admins/teachers can search all students)
//     @PreAuthorize("hasRole('ADMIN') or hasRole('TEACHER')")
//     public List<Student> searchStudentsByName(String name) {
//         logger.debug("User {} searching students by name: {}", 
//                     getCurrentUsername(), name);
//         return studentRepository.findByNameContainingIgnoreCase(name);
//     }
    
//     // Partial update student (PATCH) (RBAC: Only admins can update students)
//     @PreAuthorize("hasRole('ADMIN')")
//     public Student partialUpdateStudent(Long id, Student studentDetails) {
//         Student student = studentRepository.findById(id)
//                 .orElseThrow(() -> new StudentNotFoundException(id));
        
//         // Only update fields that are not null
//         if (studentDetails.getName() != null && !studentDetails.getName().trim().isEmpty()) {
//             student.setName(studentDetails.getName());
//         }
        
//         if (studentDetails.getRollNo() != null) {
//             // Validate roll number
//             if (studentDetails.getRollNo() <= 0) {
//                 throw new InvalidStudentDataException("rollNo", studentDetails.getRollNo(), "Roll number must be positive");
//             }
            
//             // Check if roll number is being changed and if new roll number already exists
//             if (!student.getRollNo().equals(studentDetails.getRollNo()) && 
//                 studentRepository.existsByRollNo(studentDetails.getRollNo())) {
//                 throw new DuplicateRollNumberException(studentDetails.getRollNo());
//             }
//             student.setRollNo(studentDetails.getRollNo());
//         }
        
//         if (studentDetails.getBranch() != null && !studentDetails.getBranch().trim().isEmpty()) {
//             student.setBranch(studentDetails.getBranch());
//         }
        
//         if (studentDetails.getCourse() != null && !studentDetails.getCourse().trim().isEmpty()) {
//             student.setCourse(studentDetails.getCourse());
//         }
        
//         return studentRepository.save(student);
//     }
    
//     // Helper method to check if current user has a specific role
//     private boolean hasRole(String role) {
//         Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//         if (auth == null || !auth.isAuthenticated()) {
//             return false;
//         }
//         return auth.getAuthorities().stream()
//                 .anyMatch(authority -> authority.getAuthority().equals("ROLE_" + role));
//     }
    
//     // Helper method to get current username
//     private String getCurrentUsername() {
//         Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//         if (auth == null || !auth.isAuthenticated()) {
//             return "anonymous";
//         }
//         return auth.getName();
//     }
    
//     // Helper method to get current user's roll number
//     private Integer getCurrentUserRollNo() {
//         try {
//             return jwtUtil.getCurrentUserRollNo();
//         } catch (Exception e) {
//             logger.error("Error getting current user roll number", e);
//             return null;
//         }
//     }
    
//     // Validate student data
//     private void validateStudentData(Student student) {
//         if (student == null) {
//             throw new InvalidStudentDataException("Student data cannot be null");
//         }
        
//         if (student.getName() == null || student.getName().trim().isEmpty()) {
//             throw new InvalidStudentDataException("name", student.getName(), "Name cannot be empty");
//         }
        
//         if (student.getRollNo() == null || student.getRollNo() <= 0) {
//             throw new InvalidStudentDataException("rollNo", student.getRollNo(), "Roll number must be positive");
//         }
        
//         if (student.getBranch() == null || student.getBranch().trim().isEmpty()) {
//             throw new InvalidStudentDataException("branch", student.getBranch(), "Branch cannot be empty");
//         }
        
//         if (student.getCourse() == null || student.getCourse().trim().isEmpty()) {
//             throw new InvalidStudentDataException("course", student.getCourse(), "Course cannot be empty");
//         }
//     }
// }