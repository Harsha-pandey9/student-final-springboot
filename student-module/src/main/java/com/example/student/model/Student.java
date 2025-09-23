package com.example.student.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

@Entity
@Table(name = "students")
public class Student {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @NotBlank(message = "Name is required")
    @Column(name = "name", nullable = false)
    private String name;
    
    @NotNull(message = "Roll number is required")
    @Positive(message = "Roll number must be positive")
    @Column(name = "roll_no", nullable = false, unique = true)
    private Integer rollNo;
    
    @NotBlank(message = "Branch is required")
    @Column(name = "branch", nullable = false)
    private String branch;
    
    @NotBlank(message = "Course is required")
    @Column(name = "course", nullable = false)
    private String course;
    
    @Column(name = "email")
    private String email;
    
    @Column(name = "phone")
    private String phone;
    
    // Default constructor
    public Student() {}
    
    // Constructor with parameters
    public Student(String name, Integer rollNo, String branch, String course) {
        this.name = name;
        this.rollNo = rollNo;
        this.branch = branch;
        this.course = course;
    }
    
    // Constructor with all parameters including contact info
    public Student(String name, Integer rollNo, String branch, String course, String email, String phone) {
        this.name = name;
        this.rollNo = rollNo;
        this.branch = branch;
        this.course = course;
        this.email = email;
        this.phone = phone;
    }
    
    // Getters & Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public Integer getRollNo() { return rollNo; }
    public void setRollNo(Integer rollNo) { this.rollNo = rollNo; }
    
    public String getBranch() { return branch; }
    public void setBranch(String branch) { this.branch = branch; }
    
    public String getCourse() { return course; }
    public void setCourse(String course) { this.course = course; }
    
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    
    public String getPhone() { return phone; }
    public void setPhone(String phone) { this.phone = phone; }
    
    @Override
    public String toString() {
        return "Student{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", rollNo=" + rollNo +
                ", branch='" + branch + '\'' +
                ", course='" + course + '\'' +
                ", email='" + email + '\'' +
                ", phone='" + phone + '\'' +
                '}';
    }
}