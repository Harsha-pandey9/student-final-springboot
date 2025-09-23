package com.example.config;

import com.example.auth.model.Role;
import com.example.auth.model.User;
import com.example.auth.repository.authRepo;
import com.example.student.model.Student;
import com.example.student.repository.StudentRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Data initializer to create sample users and students for testing
 */
@Component
public class DataInitializer implements CommandLineRunner {
    
    private static final Logger logger = LoggerFactory.getLogger(DataInitializer.class);
    
    @Autowired(required = false)
    private authRepo userRepository;
    
    @Autowired(required = false)
    private StudentRepository studentRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Override
    public void run(String... args) throws Exception {
        logger.info("🚀 Starting data initialization...");
        
        try {
            initializeUsers();
            initializeStudents();
            logger.info("✅ Data initialization completed successfully!");
        } catch (Exception e) {
            logger.error("❌ Error during data initialization: {}", e.getMessage(), e);
        }
    }
    
    private void initializeUsers() {
        if (userRepository == null) {
            logger.warn("⚠️ UserRepository not available, skipping user initialization");
            return;
        }
        
        try {
            // Check if users already exist
            if (userRepository.count() > 0) {
                logger.info("📊 Users already exist in database, skipping user initialization");
                return;
            }
            
            logger.info("👥 Creating sample users...");
            
            // Create Admin User
            User admin = new User();
            admin.setUsername("admin");
            admin.setEmail("admin@example.com");
            admin.setPassword(passwordEncoder.encode("admin123"));
            admin.setRollNo(1);
            admin.setRole(Role.valueOf("ADMIN"));
            admin.setEnabled(true);
            userRepository.save(admin);
            logger.info("✅ Created admin user: admin/admin123");
            
            // Create Teacher User
            User teacher = new User();
            teacher.setUsername("teacher");
            teacher.setEmail("teacher@example.com");
            teacher.setPassword(passwordEncoder.encode("teacher123"));
            teacher.setRollNo(2);
            teacher.setRole(Role.valueOf("TEACHER"));
            teacher.setEnabled(true);
            userRepository.save(teacher);
            logger.info("✅ Created teacher user: teacher/teacher123");
            
            // Create Student Users
            User student1 = new User();
            student1.setUsername("student1");
            student1.setEmail("student1@example.com");
            student1.setPassword(passwordEncoder.encode("student123"));
            student1.setRollNo(101);
            student1.setRole(Role.valueOf("STUDENT"));
            student1.setEnabled(true);
            userRepository.save(student1);
            logger.info("✅ Created student user: student1/student123 (roll: 101)");
            
            User student2 = new User();
            student2.setUsername("student2");
            student2.setEmail("student2@example.com");
            student2.setPassword(passwordEncoder.encode("student123"));
            student2.setRollNo(102);
            student2.setRole(Role.valueOf("STUDENT"));
            student2.setEnabled(true);
            userRepository.save(student2);
            logger.info("✅ Created student user: student2/student123 (roll: 102)");
            
            logger.info("👥 User initialization completed!");
            
        } catch (Exception e) {
            logger.error("❌ Error initializing users: {}", e.getMessage(), e);
        }
    }
    
    private void initializeStudents() {
        if (studentRepository == null) {
            logger.warn("⚠️ StudentRepository not available, skipping student initialization");
            return;
        }
        
        try {
            // Check if students already exist
            if (studentRepository.count() > 0) {
                logger.info("📊 Students already exist in database, skipping student initialization");
                return;
            }
            
            logger.info("🎓 Creating sample students...");
            
            // Create sample students
            Student student1 = new Student();
            student1.setName("John Doe");
            student1.setRollNo(101);
            student1.setBranch("Computer Science");
            student1.setCourse("B.Tech");
            student1.setEmail("john.doe@example.com");
            student1.setPhone("+1234567890");
            studentRepository.save(student1);
            
            Student student2 = new Student();
            student2.setName("Jane Smith");
            student2.setRollNo(102);
            student2.setBranch("Electronics");
            student2.setCourse("B.Tech");
            student2.setEmail("jane.smith@example.com");
            student2.setPhone("+1234567891");
            studentRepository.save(student2);
            
            Student student3 = new Student();
            student3.setName("Mike Johnson");
            student3.setRollNo(103);
            student3.setBranch("Mechanical");
            student3.setCourse("B.Tech");
            student3.setEmail("mike.johnson@example.com");
            student3.setPhone("+1234567892");
            studentRepository.save(student3);
            
            Student student4 = new Student();
            student4.setName("Sarah Wilson");
            student4.setRollNo(104);
            student4.setBranch("Computer Science");
            student4.setCourse("B.Tech");
            student4.setEmail("sarah.wilson@example.com");
            student4.setPhone("+1234567893");
            studentRepository.save(student4);
            
            Student student5 = new Student();
            student5.setName("David Brown");
            student5.setRollNo(105);
            student5.setBranch("Civil");
            student5.setCourse("B.Tech");
            student5.setEmail("david.brown@example.com");
            student5.setPhone("+1234567894");
            studentRepository.save(student5);
            
            logger.info("✅ Created 5 sample students");
            logger.info("🎓 Student initialization completed!");
            
        } catch (Exception e) {
            logger.error("❌ Error initializing students: {}", e.getMessage(), e);
        }
    }
}