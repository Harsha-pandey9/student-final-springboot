package com.example.student.controller;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.student.model.Student;
import com.example.student.service.StudentQueryService;

@RestController
@RequestMapping("/api/students")
@CrossOrigin(origins = "*")
public class StudentQueryController {

    @Autowired
    private StudentQueryService studentQueryService;

    @PreAuthorize("hasAnyRole('ADMIN','TEACHER','STUDENT')")
    @GetMapping
    public ResponseEntity<List<Student>> getAllStudents() {
        return ResponseEntity.ok(studentQueryService.getAllStudents());
    }

    @PreAuthorize("hasAnyRole('ADMIN','TEACHER','STUDENT')")
    @GetMapping("/{id}")
    public ResponseEntity<Student> getStudentById(@PathVariable Long id) {
        return ResponseEntity.ok(studentQueryService.getStudentById(id));
    }

    @PreAuthorize("hasAnyRole('ADMIN','TEACHER')")
    @GetMapping("/search")
    public ResponseEntity<List<Student>> searchStudents(@RequestParam String name) {
        return ResponseEntity.ok(studentQueryService.searchStudentsByName(name));
    }
    @PreAuthorize("hasAnyRole('ADMIN','TEACHER')")
    @GetMapping("/branch/{branch}")
    public ResponseEntity<List<Student>> getStudentsByBranch(@PathVariable String branch) {
        return ResponseEntity.ok(studentQueryService.getStudentsByBranch(branch));
    }

    @PreAuthorize("hasAnyRole('ADMIN','TEACHER')")
    @GetMapping("/course/{course}")
    public ResponseEntity<List<Student>> getStudentsByCourse(@PathVariable String course) {
        return ResponseEntity.ok(studentQueryService.getStudentsByCourse(course));
    }
}
