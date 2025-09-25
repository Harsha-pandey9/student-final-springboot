package com.example.student.service;

import com.example.student.exception.StudentExceptions.DuplicateRollNumberException;
import com.example.student.exception.StudentExceptions.InvalidStudentDataException;
import com.example.student.exception.StudentExceptions.StudentNotFoundException;
import com.example.student.model.Student;
import com.example.student.repository.StudentRepository;
import com.example.auth.util.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

@Service
public class StudentCommandService {

    private static final Logger logger = LoggerFactory.getLogger(StudentCommandService.class);

    @Autowired
    private StudentRepository studentRepository;

    @Autowired
    private JwtUtil jwtUtil;

    @PreAuthorize("hasRole('ADMIN')")
    public Student createStudent(Student student) {
        validateStudentData(student);
        if (studentRepository.existsByRollNo(student.getRollNo())) {
            throw new DuplicateRollNumberException(student.getRollNo());
        }
        logger.info("Admin creating new student with roll: {}", student.getRollNo());
        return studentRepository.save(student);
    }

    @PreAuthorize("hasRole('ADMIN')")
    public Student updateStudent(Long id, Student studentDetails) {
        validateStudentData(studentDetails);
        Student student = studentRepository.findById(id)
                .orElseThrow(() -> new StudentNotFoundException(id));

        if (!student.getRollNo().equals(studentDetails.getRollNo()) &&
            studentRepository.existsByRollNo(studentDetails.getRollNo())) {
            throw new DuplicateRollNumberException(studentDetails.getRollNo());
        }

        student.setName(studentDetails.getName());
        student.setRollNo(studentDetails.getRollNo());
        student.setBranch(studentDetails.getBranch());
        student.setCourse(studentDetails.getCourse());

        logger.info("Admin updating student {} (roll: {})", id, student.getRollNo());
        return studentRepository.save(student);
    }

    @PreAuthorize("hasRole('ADMIN')")
    public Student partialUpdateStudent(Long id, Student studentDetails) {
        Student student = studentRepository.findById(id)
                .orElseThrow(() -> new StudentNotFoundException(id));

        if (studentDetails.getName() != null && !studentDetails.getName().trim().isEmpty()) {
            student.setName(studentDetails.getName());
        }

        if (studentDetails.getRollNo() != null) {
            if (studentDetails.getRollNo() <= 0) {
                throw new InvalidStudentDataException("rollNo", studentDetails.getRollNo(), "Roll number must be positive");
            }
            if (!student.getRollNo().equals(studentDetails.getRollNo()) &&
                studentRepository.existsByRollNo(studentDetails.getRollNo())) {
                throw new DuplicateRollNumberException(studentDetails.getRollNo());
            }
            student.setRollNo(studentDetails.getRollNo());
        }

        if (studentDetails.getBranch() != null && !studentDetails.getBranch().trim().isEmpty()) {
            student.setBranch(studentDetails.getBranch());
        }

        if (studentDetails.getCourse() != null && !studentDetails.getCourse().trim().isEmpty()) {
            student.setCourse(studentDetails.getCourse());
        }

        logger.info("Admin partially updating student {} (roll: {})", id, student.getRollNo());
        return studentRepository.save(student);
    }

    @PreAuthorize("hasRole('ADMIN')")
    public void deleteStudent(Long id) {
        Student student = studentRepository.findById(id)
                .orElseThrow(() -> new StudentNotFoundException(id));
        studentRepository.delete(student);
        logger.info("Admin deleted student {} (roll: {})", id, student.getRollNo());
    }

    private void validateStudentData(Student student) {
        if (student == null) throw new InvalidStudentDataException("Student data cannot be null");
        if (student.getName() == null || student.getName().trim().isEmpty())
            throw new InvalidStudentDataException("name", student.getName(), "Name cannot be empty");
        if (student.getRollNo() == null || student.getRollNo() <= 0)
            throw new InvalidStudentDataException("rollNo", student.getRollNo(), "Roll number must be positive");
        if (student.getBranch() == null || student.getBranch().trim().isEmpty())
            throw new InvalidStudentDataException("branch", student.getBranch(), "Branch cannot be empty");
        if (student.getCourse() == null || student.getCourse().trim().isEmpty())
            throw new InvalidStudentDataException("course", student.getCourse(), "Course cannot be empty");
    }
}
