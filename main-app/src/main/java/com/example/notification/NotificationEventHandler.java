//package com.example.notification;
//
//import com.example.config.KafkaConfig;
//import com.example.event.StudentEvent;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.kafka.annotation.KafkaListener;
//import org.springframework.kafka.support.Acknowledgment;
//import org.springframework.kafka.support.KafkaHeaders;
//import org.springframework.messaging.handler.annotation.Header;
//import org.springframework.messaging.handler.annotation.Payload;
//import org.springframework.stereotype.Service;
//
///**
// * Simplified Kafka consumer for handling student events
// * Only logs notifications for student registration and deletion
// */
//@Service
//public class NotificationEventHandler {
//
//    private static final Logger logger = LoggerFactory.getLogger(NotificationEventHandler.class);
//
//    /**
//     * Handle student events and log notifications
//     */
//    @KafkaListener(topics = KafkaConfig.STUDENT_EVENTS_TOPIC, groupId = "notification-group")
//    public void handleStudentEvent(
//            @Payload StudentEvent event,
//            @Header(KafkaHeaders.RECEIVED_TOPIC) String topic,
//            @Header(KafkaHeaders.RECEIVED_PARTITION) int partition,
//            @Header(KafkaHeaders.OFFSET) long offset,
//            Acknowledgment acknowledgment) {
//
//        logger.info("📨 Received student event [{}] from topic [{}], partition [{}], offset [{}]",
//                event.getEventId(), topic, partition, offset);
//
//        try {
//            // Process the event based on type
//            switch (event.getEventType()) {
//                case StudentEvent.REGISTRATION:
//                    handleRegistrationEvent(event);
//                    break;
//                case StudentEvent.DELETION:
//                    handleDeletionEvent(event);
//                    break;
//                case StudentEvent.UPDATE:
//                    handleUpdateEvent(event);
//                    break;
//                default:
//                    logger.warn("⚠️ Unknown event type: {}", event.getEventType());
//            }
//
//            // Acknowledge the message
//            acknowledgment.acknowledge();
//            logger.info("✅ Successfully processed student event [{}]", event.getEventId());
//
//        } catch (Exception e) {
//            logger.error("❌ Failed to process student event [{}]: {}", event.getEventId(), e.getMessage(), e);
//            // Acknowledge to prevent infinite retries
//            acknowledgment.acknowledge();
//        }
//    }
//
//    /**
//     * Handle student registration event
//     */
//    private void handleRegistrationEvent(StudentEvent event) {
//        logger.info("🎉 STUDENT REGISTERED NOTIFICATION:");
//        logger.info("   📝 Student: {} (ID: {})", event.getStudentName(), event.getStudentId());
//        logger.info("   🎓 Course: {} - {}", event.getCourse(), event.getBranch());
//        logger.info("   📧 Email: {}", event.getStudentEmail());
//        logger.info("   📱 Phone: {}", event.getStudentPhone());
//        logger.info("   🔢 Roll No: {}", event.getRollNo());
//        logger.info("   💬 Message: {}", event.getWelcomeMessage());
//        logger.info("   📍 Source: {}", event.getRegistrationSource());
//        logger.info("   ⏰ Time: {}", event.getTimestamp());
//        logger.info("   🆔 Event ID: {}", event.getEventId());
//    }
//
//    /**
//     * Handle student deletion event
//     */
//    private void handleDeletionEvent(StudentEvent event) {
//        logger.info("🗑️ STUDENT DELETED NOTIFICATION:");
//        logger.info("   📝 Student: {} (ID: {})", event.getStudentName(), event.getStudentId());
//        logger.info("   🎓 Course: {} - {}", event.getCourse(), event.getBranch());
//        logger.info("   📧 Email: {}", event.getStudentEmail());
//        logger.info("   📱 Phone: {}", event.getStudentPhone());
//        logger.info("   🔢 Roll No: {}", event.getRollNo());
//        logger.info("   👤 Deleted by: {}", event.getDeletedBy());
//        logger.info("   📝 Reason: {}", event.getReason());
//        logger.info("   ⏰ Time: {}", event.getTimestamp());
//        logger.info("   🆔 Event ID: {}", event.getEventId());
//    }
//
//    /**
//     * Handle student update event
//     */
//    private void handleUpdateEvent(StudentEvent event) {
//        logger.info("✏️ STUDENT UPDATED NOTIFICATION:");
//        logger.info("   📝 Student: {} (ID: {})", event.getStudentName(), event.getStudentId());
//        logger.info("   🎓 Course: {} - {}", event.getCourse(), event.getBranch());
//        logger.info("   📧 Email: {}", event.getStudentEmail());
//        logger.info("   📱 Phone: {}", event.getStudentPhone());
//        logger.info("   🔢 Roll No: {}", event.getRollNo());
//        logger.info("   📋 Additional Info: {}", event.getAdditionalData());
//        logger.info("   ⏰ Time: {}", event.getTimestamp());
//        logger.info("   🆔 Event ID: {}", event.getEventId());
//    }
//}