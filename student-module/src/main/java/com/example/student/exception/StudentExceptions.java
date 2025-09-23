package com.example.student.exception;

/**
 * Consolidated Student Exception Classes
 * Contains all custom exceptions related to student operations
 */
public class StudentExceptions {

    /**
     * Custom exception thrown when a student is not found
     */
    public static class StudentNotFoundException extends RuntimeException {
        
        private final Long studentId;
        
        public StudentNotFoundException(Long studentId) {
            super("Student not found with ID: " + studentId);
            this.studentId = studentId;
        }
        
        public StudentNotFoundException(String message) {
            super(message);
            this.studentId = null;
        }
        
        public StudentNotFoundException(String message, Throwable cause) {
            super(message, cause);
            this.studentId = null;
        }
        
        public Long getStudentId() {
            return studentId;
        }
    }

    /**
     * Custom exception thrown when attempting to create/update a student with a duplicate roll number
     */
    public static class DuplicateRollNumberException extends RuntimeException {
        
        private final Integer rollNumber;
        
        public DuplicateRollNumberException(Integer rollNumber) {
            super("Student with roll number " + rollNumber + " already exists");
            this.rollNumber = rollNumber;
        }
        
        public DuplicateRollNumberException(String message) {
            super(message);
            this.rollNumber = null;
        }
        
        public DuplicateRollNumberException(String message, Throwable cause) {
            super(message, cause);
            this.rollNumber = null;
        }
        
        public Integer getRollNumber() {
            return rollNumber;
        }
    }

    /**
     * Custom exception thrown when student data is invalid
     */
    public static class InvalidStudentDataException extends RuntimeException {
        
        private final String field;
        private final Object value;
        
        public InvalidStudentDataException(String message) {
            super(message);
            this.field = null;
            this.value = null;
        }
        
        public InvalidStudentDataException(String field, Object value, String message) {
            super(message);
            this.field = field;
            this.value = value;
        }
        
        public InvalidStudentDataException(String message, Throwable cause) {
            super(message, cause);
            this.field = null;
            this.value = null;
        }
        
        public String getField() {
            return field;
        }
        
        public Object getValue() {
            return value;
        }
    }
}