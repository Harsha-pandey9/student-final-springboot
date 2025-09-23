//package com.example.config;
//
//import org.apache.kafka.clients.consumer.ConsumerConfig;
//import org.apache.kafka.clients.producer.ProducerConfig;
//import org.apache.kafka.common.serialization.StringDeserializer;
//import org.apache.kafka.common.serialization.StringSerializer;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.kafka.annotation.EnableKafka;
//import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
//import org.springframework.kafka.core.*;
//import org.springframework.kafka.listener.ContainerProperties;
//import org.springframework.kafka.support.serializer.ErrorHandlingDeserializer;
//import org.springframework.kafka.support.serializer.JsonDeserializer;
//import org.springframework.kafka.support.serializer.JsonSerializer;
//
//import java.util.HashMap;
//import java.util.Map;
//
///**
// * Kafka configuration for producers and consumers
// * Only enabled if Kafka is available
// */
//@Configuration
//@EnableKafka
//@ConditionalOnProperty(name = "spring.kafka.enabled", havingValue = "true", matchIfMissing = true)
//public class KafkaConfig {
//
//    @Value("${spring.kafka.bootstrap-servers:localhost:9092}")
//    private String bootstrapServers;
//
//    @Value("${spring.kafka.consumer.group-id:student-group}")
//    private String groupId;
//
//    // Producer Configuration
//    @Bean
//    public ProducerFactory<String, Object> producerFactory() {
//        Map<String, Object> configProps = new HashMap<>();
//        configProps.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
//        configProps.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
//        configProps.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JsonSerializer.class);
//
//        // Additional producer configurations for reliability
//        configProps.put(ProducerConfig.ACKS_CONFIG, "all");
//        configProps.put(ProducerConfig.RETRIES_CONFIG, 3);
//        configProps.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, true);
//        configProps.put(ProducerConfig.MAX_IN_FLIGHT_REQUESTS_PER_CONNECTION, 1);
//
//        return new DefaultKafkaProducerFactory<>(configProps);
//    }
//
//    @Bean
//    public KafkaTemplate<String, Object> kafkaTemplate() {
//        return new KafkaTemplate<>(producerFactory());
//    }
//
//    // Consumer Configuration
//    @Bean
//    public ConsumerFactory<String, Object> consumerFactory() {
//        Map<String, Object> props = new HashMap<>();
//        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
//        props.put(ConsumerConfig.GROUP_ID_CONFIG, groupId);
//        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
//        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, ErrorHandlingDeserializer.class);
//        props.put(ErrorHandlingDeserializer.VALUE_DESERIALIZER_CLASS, JsonDeserializer.class.getName());
//        props.put(JsonDeserializer.TRUSTED_PACKAGES, "com.example.event");
//        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
//
//        // Additional consumer configurations
//        props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, false);
//        props.put(ConsumerConfig.SESSION_TIMEOUT_MS_CONFIG, 30000);
//
//        return new DefaultKafkaConsumerFactory<>(props);
//    }
//
//    @Bean
//    public ConcurrentKafkaListenerContainerFactory<String, Object> kafkaListenerContainerFactory() {
//        ConcurrentKafkaListenerContainerFactory<String, Object> factory = new ConcurrentKafkaListenerContainerFactory<>();
//        factory.setConsumerFactory(consumerFactory());
//
//        // Enable manual acknowledgment
//        factory.getContainerProperties().setAckMode(ContainerProperties.AckMode.MANUAL_IMMEDIATE);
//
//        // Set concurrency level
//        factory.setConcurrency(3);
//
//        return factory;
//    }
//
//    // Topic names
//    public static final String STUDENT_EVENTS_TOPIC = "student-events";
//    public static final String MESSAGES_TOPIC = "messages";
// }