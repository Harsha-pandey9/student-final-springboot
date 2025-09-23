package com.example.student.exception;

import com.example.student.exception.StudentExceptions.*;

import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.ModelAndView;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Global Exception Handler for the Student Management Application
 * 
 * This class handles all exceptions thrown across the application and provides
 * consistent error responses for both API endpoints and web pages.
 */
@ControllerAdvice
public class GlobalExceptionHandler {
    
    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    
    // ==================== UNIFIED EXCEPTION HANDLERS ====================
    
    /**
     * Handle validation errors
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public Object handleValidationExceptions(
            MethodArgumentNotValidException ex, WebRequest request) {
        
        logger.error("Validation error occurred: {}", ex.getMessage());
        
        if (isApiRequest(request)) {
            Map<String, Object> response = new HashMap<>();
            Map<String, String> fieldErrors = new HashMap<>();
            
            ex.getBindingResult().getFieldErrors().forEach(error -> 
                fieldErrors.put(error.getField(), error.getDefaultMessage())
            );
            
            response.put("success", false);
            response.put("message", "Validation failed");
            response.put("errors", fieldErrors);
            response.put("timestamp", LocalDateTime.now());
            response.put("path", request.getDescription(false));
            
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        } else {
            ModelAndView modelAndView = new ModelAndView("users/error");
            
            StringBuilder errorMessage = new StringBuilder("Validation failed: ");
            ex.getBindingResult().getFieldErrors().forEach(error -> 
                errorMessage.append(error.getField()).append(" - ").append(error.getDefaultMessage()).append("; ")
            );
            
            modelAndView.addObject("error", errorMessage.toString());
            return modelAndView;
        }
    }
    
    /**
     * Handle constraint violation exceptions
     */
    @ExceptionHandler(ConstraintViolationException.class)
    public Object handleConstraintViolationException(
            ConstraintViolationException ex, WebRequest request) {
        
        logger.error("Constraint violation error: {}", ex.getMessage());
        
        if (isApiRequest(request)) {
            Map<String, Object> response = new HashMap<>();
            Map<String, String> violations = new HashMap<>();
            
            ex.getConstraintViolations().forEach(violation -> 
                violations.put(violation.getPropertyPath().toString(), violation.getMessage())
            );
            
            response.put("success", false);
            response.put("message", "Constraint violation");
            response.put("errors", violations);
            response.put("timestamp", LocalDateTime.now());
            response.put("path", request.getDescription(false));
            
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        } else {
            ModelAndView modelAndView = new ModelAndView("users/error");
            modelAndView.addObject("error", "Data validation failed. Please check your input.");
            return modelAndView;
        }
    }
    
    /**
     * Handle data integrity violations
     */
    @ExceptionHandler(DataIntegrityViolationException.class)
    public Object handleDataIntegrityViolationException(
            DataIntegrityViolationException ex, WebRequest request) {
        
        logger.error("Data integrity violation: {}", ex.getMessage());
        
        String message = "Data integrity violation";
        if (ex.getMessage().contains("roll_no")) {
            message = "Roll number already exists";
        } else if (ex.getMessage().contains("Duplicate entry")) {
            message = "Duplicate entry detected";
        }
        
        if (isApiRequest(request)) {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", message);
            response.put("error", "The operation violates data integrity constraints");
            response.put("timestamp", LocalDateTime.now());
            response.put("path", request.getDescription(false));
            
            return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
        } else {
            ModelAndView modelAndView = new ModelAndView("users/error");
            String webMessage = message.equals("Roll number already exists") 
                ? "Roll number already exists. Please use a different roll number."
                : "Duplicate entry detected. Please check your input.";
            modelAndView.addObject("error", webMessage);
            return modelAndView;
        }
    }
    
    /**
     * Handle StudentNotFoundException
     */
    @ExceptionHandler(StudentNotFoundException.class)
    public Object handleStudentNotFoundException(
            StudentNotFoundException ex, WebRequest request) {
        
        logger.error("Student not found: {}", ex.getMessage());
        
        if (isApiRequest(request)) {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Student not found");
            response.put("error", ex.getMessage());
            response.put("studentId", ex.getStudentId());
            response.put("timestamp", LocalDateTime.now());
            response.put("path", request.getDescription(false));
            
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
        } else {
            ModelAndView modelAndView = new ModelAndView("users/error");
            modelAndView.addObject("error", ex.getMessage());
            return modelAndView;
        }
    }
    
    /**
     * Handle DuplicateRollNumberException
     */
    @ExceptionHandler(DuplicateRollNumberException.class)
    public Object handleDuplicateRollNumberException(
            DuplicateRollNumberException ex, WebRequest request) {
        
        logger.error("Duplicate roll number: {}", ex.getMessage());
        
        if (isApiRequest(request)) {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Duplicate roll number");
            response.put("error", ex.getMessage());
            response.put("rollNumber", ex.getRollNumber());
            response.put("timestamp", LocalDateTime.now());
            response.put("path", request.getDescription(false));
            
            return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
        } else {
            ModelAndView modelAndView = new ModelAndView("users/error");
            modelAndView.addObject("error", ex.getMessage());
            return modelAndView;
        }
    }
    
    /**
     * Handle InvalidStudentDataException
     */
    @ExceptionHandler(InvalidStudentDataException.class)
    public Object handleInvalidStudentDataException(
            InvalidStudentDataException ex, WebRequest request) {
        
        logger.error("Invalid student data: {}", ex.getMessage());
        
        if (isApiRequest(request)) {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Invalid student data");
            response.put("error", ex.getMessage());
            response.put("field", ex.getField());
            response.put("value", ex.getValue());
            response.put("timestamp", LocalDateTime.now());
            response.put("path", request.getDescription(false));
            
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        } else {
            ModelAndView modelAndView = new ModelAndView("users/error");
            modelAndView.addObject("error", ex.getMessage());
            return modelAndView;
        }
    }
    
    /**
     * Handle illegal argument exceptions
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public Object handleIllegalArgumentException(
            IllegalArgumentException ex, WebRequest request) {
        
        logger.error("Illegal argument exception: {}", ex.getMessage());
        
        if (isApiRequest(request)) {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Invalid argument provided");
            response.put("error", ex.getMessage());
            response.put("timestamp", LocalDateTime.now());
            response.put("path", request.getDescription(false));
            
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        } else {
            ModelAndView modelAndView = new ModelAndView("users/error");
            modelAndView.addObject("error", "Invalid input provided. Please check your data.");
            return modelAndView;
        }
    }
    
    /**
     * Handle runtime exceptions
     */
    @ExceptionHandler(RuntimeException.class)
    public Object handleRuntimeException(
            RuntimeException ex, WebRequest request) {
        
        logger.error("Runtime exception occurred: {}", ex.getMessage(), ex);
        
        if (isApiRequest(request)) {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Operation failed");
            response.put("error", ex.getMessage());
            response.put("timestamp", LocalDateTime.now());
            response.put("path", request.getDescription(false));
            
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        } else {
            ModelAndView modelAndView = new ModelAndView("users/error");
            modelAndView.addObject("error", ex.getMessage());
            return modelAndView;
        }
    }
    
    /**
     * Handle all other exceptions
     */
    @ExceptionHandler(Exception.class)
    public Object handleGeneralException(
            Exception ex, WebRequest request) {
        
        logger.error("Unexpected exception occurred: {}", ex.getMessage(), ex);
        
        if (isApiRequest(request)) {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "An unexpected error occurred");
            response.put("error", "Internal server error");
            response.put("timestamp", LocalDateTime.now());
            response.put("path", request.getDescription(false));
            
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        } else {
            ModelAndView modelAndView = new ModelAndView("users/error");
            modelAndView.addObject("error", "An unexpected error occurred. Please try again.");
            return modelAndView;
        }
    }
    
    // ==================== UTILITY METHODS ====================
    
    /**
     * Check if the request is an API request (JSON)
     */
    private boolean isApiRequest(WebRequest request) {
        String requestURI = request.getDescription(false);
        return requestURI.contains("/api/") || 
               (request.getHeader("Accept") != null && 
                request.getHeader("Accept").contains("application/json"));
    }
}