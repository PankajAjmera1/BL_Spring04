package org.ajmera.greetingapp.controller;



import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/greeting")
public class GreetingController {

    @GetMapping
    public String getGreeting() {
        return "{\"message\": \"Hello, World!\"}";
    }

    @PostMapping
    public String createGreeting() {
        return "{\"message\": \"Greeting Created!\"}";
    }

    @PutMapping
    public String updateGreeting() {
        return "{\"message\": \"Greeting Updated!\"}";
    }

    @DeleteMapping
    public String deleteGreeting() {
        return "{\"message\": \"Greeting Deleted!\"}";
    }
}
