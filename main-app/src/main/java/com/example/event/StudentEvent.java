package com.example.event;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.example.student.model.Student;

import java.time.LocalDateTime;

/**
 * Unified event class for all student-related events
 * Supports REGISTRATION, DELETION, and other event types
 */
public class StudentEvent {
    
    // Event type constants
    public static final String REGISTRATION = "STUDENT_REGISTRATION";
    public static final String DELETION = "STUDENT_DELETION";
    public static final String UPDATE = "STUDENT_UPDATE";
    
    @JsonProperty("eventId")
    private String eventId;
    
    @JsonProperty("eventType")
    private String eventType;
    
    @JsonProperty("timestamp")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime timestamp;
    
    @JsonProperty("studentId")
    private Long studentId;
    
    @JsonProperty("studentName")
    private String studentName;
    
    @JsonProperty("studentEmail")
    private String studentEmail;
    
    @JsonProperty("studentPhone")
    private String studentPhone;
    
    @JsonProperty("rollNo")
    private Integer rollNo;
    
    @JsonProperty("branch")
    private String branch;
    
    @JsonProperty("course")
    private String course;
    
    // Registration-specific fields
    @JsonProperty("welcomeMessage")
    private String welcomeMessage;
    
    @JsonProperty("registrationSource")
    private String registrationSource;
    
    // Deletion-specific fields
    @JsonProperty("deletedBy")
    private String deletedBy;
    
    @JsonProperty("reason")
    private String reason;
    
    // Generic additional data
    @JsonProperty("additionalData")
    private String additionalData;
    
    // Default constructor
    public StudentEvent() {
        this.timestamp = LocalDateTime.now();
        this.eventId = java.util.UUID.randomUUID().toString();
    }
    
    // Constructor with basic student info
    public StudentEvent(String eventType, Long studentId, String studentName, String studentEmail, 
                       String studentPhone, Integer rollNo, String branch, String course) {
        this();
        this.eventType = eventType;
        this.studentId = studentId;
        this.studentName = studentName;
        this.studentEmail = studentEmail;
        this.studentPhone = studentPhone;
        this.rollNo = rollNo;
        this.branch = branch;
        this.course = course;
    }
    
    // Static factory methods for specific event types
    
    /**
     * Create a registration event
     */
    public static StudentEvent createRegistrationEvent(Student student) {
        return createRegistrationEvent(student, "WEB_FORM");
    }
    
    /**
     * Create a registration event with custom source
     */
    public static StudentEvent createRegistrationEvent(Student student, String registrationSource) {
        StudentEvent event = new StudentEvent(REGISTRATION, student.getId(), student.getName(), 
                student.getEmail(), student.getPhone(), student.getRollNo(), 
                student.getBranch(), student.getCourse());
        
        event.setRegistrationSource(registrationSource);
        event.setWelcomeMessage(generateWelcomeMessage(student));
        return event;
    }
    
    /**
     * Create a deletion event
     */
    public static StudentEvent createDeletionEvent(Student student, String deletedBy) {
        return createDeletionEvent(student, deletedBy, "Administrative action");
    }
    
    /**
     * Create a deletion event with custom reason
     */
    public static StudentEvent createDeletionEvent(Student student, String deletedBy, String reason) {
        StudentEvent event = new StudentEvent(DELETION, student.getId(), student.getName(), 
                student.getEmail(), student.getPhone(), student.getRollNo(), 
                student.getBranch(), student.getCourse());
        
        event.setDeletedBy(deletedBy);
        event.setReason(reason);
        return event;
    }
    
    /**
     * Create an update event
     */
    public static StudentEvent createUpdateEvent(Student student, String updatedBy) {
        StudentEvent event = new StudentEvent(UPDATE, student.getId(), student.getName(), 
                student.getEmail(), student.getPhone(), student.getRollNo(), 
                student.getBranch(), student.getCourse());
        
        event.setAdditionalData("Updated by: " + updatedBy);
        return event;
    }
    
    /**
     * Generate welcome message for registration events
     */
    private static String generateWelcomeMessage(Student student) {
        return String.format("Welcome to our institution, %s! Your registration for %s in %s branch has been completed successfully. Your roll number is %d.",
                student.getName(), student.getCourse(), student.getBranch(), student.getRollNo());
    }
    
    // Convenience methods for event type checking
    public boolean isRegistrationEvent() {
        return REGISTRATION.equals(eventType);
    }
    
    public boolean isDeletionEvent() {
        return DELETION.equals(eventType);
    }
    
    public boolean isUpdateEvent() {
        return UPDATE.equals(eventType);
    }
    
    // Getters and Setters
    public String getEventId() { return eventId; }
    public void setEventId(String eventId) { this.eventId = eventId; }
    
    public String getEventType() { return eventType; }
    public void setEventType(String eventType) { this.eventType = eventType; }
    
    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
    
    public Long getStudentId() { return studentId; }
    public void setStudentId(Long studentId) { this.studentId = studentId; }
    
    public String getStudentName() { return studentName; }
    public void setStudentName(String studentName) { this.studentName = studentName; }
    
    public String getStudentEmail() { return studentEmail; }
    public void setStudentEmail(String studentEmail) { this.studentEmail = studentEmail; }
    
    public String getStudentPhone() { return studentPhone; }
    public void setStudentPhone(String studentPhone) { this.studentPhone = studentPhone; }
    
    public Integer getRollNo() { return rollNo; }
    public void setRollNo(Integer rollNo) { this.rollNo = rollNo; }
    
    public String getBranch() { return branch; }
    public void setBranch(String branch) { this.branch = branch; }
    
    public String getCourse() { return course; }
    public void setCourse(String course) { this.course = course; }
    
    public String getWelcomeMessage() { return welcomeMessage; }
    public void setWelcomeMessage(String welcomeMessage) { this.welcomeMessage = welcomeMessage; }
    
    public String getRegistrationSource() { return registrationSource; }
    public void setRegistrationSource(String registrationSource) { this.registrationSource = registrationSource; }
    
    public String getDeletedBy() { return deletedBy; }
    public void setDeletedBy(String deletedBy) { this.deletedBy = deletedBy; }
    
    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }
    
    public String getAdditionalData() { return additionalData; }
    public void setAdditionalData(String additionalData) { this.additionalData = additionalData; }
    
    @Override
    public String toString() {
        return "StudentEvent{" +
                "eventId='" + eventId + '\'' +
                ", eventType='" + eventType + '\'' +
                ", timestamp=" + timestamp +
                ", studentId=" + studentId +
                ", studentName='" + studentName + '\'' +
                ", studentEmail='" + studentEmail + '\'' +
                ", studentPhone='" + studentPhone + '\'' +
                ", rollNo=" + rollNo +
                ", branch='" + branch + '\'' +
                ", course='" + course + '\'' +
                ", welcomeMessage='" + welcomeMessage + '\'' +
                ", registrationSource='" + registrationSource + '\'' +
                ", deletedBy='" + deletedBy + '\'' +
                ", reason='" + reason + '\'' +
                ", additionalData='" + additionalData + '\'' +
                '}';
    }
}