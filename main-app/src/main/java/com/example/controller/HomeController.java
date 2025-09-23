package com.example.controller;

import com.example.service.KafkaProducerService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RestController
@RequestMapping("/api/kafka")
public class HomeController {

    private final KafkaProducerService producerService;

    public HomeController(KafkaProducerService producerService) {
        this.producerService = producerService;
    }
    @GetMapping("/")
    public String home(Model model) {
        model.addAttribute("title", "Student Management System - API Only");
        return "index";
    }
    @PostMapping("/send")
    public String sendMessage(@RequestParam String msg) {
        producerService.sendMessage("test-topic", msg);
        return "Message sent: " + msg;
    }
}