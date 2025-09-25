package com.example.model;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.LocalDateTime;

/**
 * Simple message model for producer-consumer demo
 */
public class Message {

    @JsonProperty("id")
    private String id;

    @JsonProperty("content")
    private String content;

    @JsonProperty("sender")
    private String sender;

    @JsonProperty("timestamp")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime timestamp;

    @JsonProperty("topic")
    private String topic;

    // Default constructor
    public Message() {
        this.timestamp = LocalDateTime.now();
        this.id = java.util.UUID.randomUUID().toString();
    }

    // Constructor with content
    public Message(String content, String sender) {
        this();
        this.content = content;
        this.sender = sender;
        this.topic = "messages";
    }

    // Constructor with all fields
    public Message(String content, String sender, String topic) {
        this();
        this.content = content;
        this.sender = sender;
        this.topic = topic;
    }

    // Getters and Setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }

    public String getSender() { return sender; }
    public void setSender(String sender) { this.sender = sender; }

    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }

    public String getTopic() { return topic; }
    public void setTopic(String topic) { this.topic = topic; }

    @Override
    public String toString() {
        return "Message{" +
                "id='" + id + '\'' +
                ", content='" + content + '\'' +
                ", sender='" + sender + '\'' +
                ", timestamp=" + timestamp +
                ", topic='" + topic + '\'' +
                '}';
    }
}