//package com.example.controller;
//
//import com.example.model.Message;
////import com.example.service.MessagingService;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.web.bind.annotation.*;
//
//import java.util.HashMap;
//import java.util.List;
//import java.util.Map;
//
///**
// * REST API Controller for Producer-Consumer messaging interface
// */
//@RestController
//@RequestMapping("/api/messages")
//@CrossOrigin(origins = "*")
//public class MessageController {
//
//    private static final Logger logger = LoggerFactory.getLogger(MessageController.class);
//
////    @Autowired
////    private MessagingService messagingService;
//
//    /**
//     * Get all messages
//     */
//    @GetMapping
//    public ResponseEntity<Map<String, Object>> getAllMessages(@RequestParam(defaultValue = "50") int limit) {
//        Map<String, Object> response = new HashMap<>();
//
//        try {
//            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//            String currentUser = auth != null && auth.isAuthenticated() ? auth.getName() : "Anonymous";
//
//            List<Message> messages = messagingService.getLatestMessages(limit);
//
//            response.put("success", true);
//            response.put("messages", messages);
//            response.put("totalCount", messagingService.getMessageCount());
//            response.put("currentUser", currentUser);
//            response.put("timestamp", System.currentTimeMillis());
//
//            return ResponseEntity.ok(response);
//        } catch (Exception e) {
//            response.put("success", false);
//            response.put("error", e.getMessage());
//            return ResponseEntity.internalServerError().body(response);
//        }
//    }
//
//    /**
//     * Send a message via API
//     */
//    @PostMapping("/send")
//    public ResponseEntity<Map<String, Object>> sendMessage(@RequestBody Map<String, String> request) {
//        Map<String, Object> response = new HashMap<>();
//
//        try {
//            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//            String sender = auth != null && auth.isAuthenticated() ? auth.getName() : "API User";
//            String content = request.get("content");
//
//            if (content == null || content.trim().isEmpty()) {
//                response.put("success", false);
//                response.put("error", "Message content cannot be empty");
//                return ResponseEntity.badRequest().body(response);
//            }
//
//            messagingService.sendMessage(content.trim(), sender);
//
//            response.put("success", true);
//            response.put("message", "Message sent successfully");
//            response.put("timestamp", System.currentTimeMillis());
//
//            logger.info("🔗 API: Message sent by [{}]: {}", sender, content);
//            return ResponseEntity.ok(response);
//
//        } catch (Exception e) {
//            response.put("success", false);
//            response.put("error", "Failed to send message: " + e.getMessage());
//            logger.error("🔗 API: Failed to send message: {}", e.getMessage());
//            return ResponseEntity.internalServerError().body(response);
//        }
//    }
//
//
//
//    /**
//     * Send test messages
//     */
//    @PostMapping("/test")
//    public ResponseEntity<Map<String, Object>> sendTestMessages() {
//        Map<String, Object> response = new HashMap<>();
//
//        try {
//            // Send test messages in a separate thread to avoid blocking
//            new Thread(() -> messagingService.sendTestMessages()).start();
//
//            response.put("success", true);
//            response.put("message", "Test messages are being sent!");
//            response.put("timestamp", System.currentTimeMillis());
//
//            logger.info("🧪 TEST: Test messages initiated");
//            return ResponseEntity.ok(response);
//        } catch (Exception e) {
//            response.put("success", false);
//            response.put("error", "Failed to send test messages: " + e.getMessage());
//            logger.error("🧪 TEST: Failed to send test messages: {}", e.getMessage());
//            return ResponseEntity.internalServerError().body(response);
//        }
//    }
//
//    /**
//     * Clear all messages
//     */
//    @DeleteMapping("/clear")
//    public ResponseEntity<Map<String, Object>> clearMessages() {
//        Map<String, Object> response = new HashMap<>();
//
//        try {
//            messagingService.clearMessages();
//
//            response.put("success", true);
//            response.put("message", "All messages cleared!");
//            response.put("timestamp", System.currentTimeMillis());
//
//            logger.info("🗑️ CLEAR: All messages cleared");
//            return ResponseEntity.ok(response);
//        } catch (Exception e) {
//            response.put("success", false);
//            response.put("error", "Failed to clear messages: " + e.getMessage());
//            logger.error("🗑️ CLEAR: Failed to clear messages: {}", e.getMessage());
//            return ResponseEntity.internalServerError().body(response);
//        }
//    }
//}