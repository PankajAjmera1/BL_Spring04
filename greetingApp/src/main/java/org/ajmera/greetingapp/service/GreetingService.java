package org.ajmera.greetingapp.service;


import org.springframework.stereotype.Service;

@Service
public class GreetingService {

    public String getGreeting() {
        return "{\"message\": \"Hello, World!\"}";
    }

    public String createGreeting() {
        return "{\"message\": \"Greeting Created!\"}";
    }

    public String updateGreeting() {
        return "{\"message\": \"Greeting Updated!\"}";
    }

    public String deleteGreeting() {
        return "{\"message\": \"Greeting Deleted!\"}";
    }
}
