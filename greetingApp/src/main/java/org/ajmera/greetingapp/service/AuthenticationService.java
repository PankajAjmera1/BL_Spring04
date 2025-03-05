//package org.ajmera.greetingapp.service;
//
//
//import org.ajmera.greetingapp.dto.AuthUserDTO;
//import org.ajmera.greetingapp.model.AuthUser;
//import org.ajmera.greetingapp.repository.AuthUserRepository;
//import org.ajmera.greetingapp.util.JwtUtil;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.stereotype.Service;
//
//@Service
//public class AuthenticationService {
//
//
//    private final AuthUserRepository authUserRepository;
//
//
//    private final AuthenticationManager authManager;
//    private final JwtUtil jwtUtil;
//
//    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
//
//    public AuthenticationService(AuthUserRepository authUserRepository, AuthenticationManager authManager, JwtUtil jwtUtil) {
//        this.authUserRepository = authUserRepository;
//        this.authManager = authManager;
//        this.jwtUtil = jwtUtil;
//    }
//
//    public String register(AuthUserDTO userDTO) {
//        if (authUserRepository.existsByEmail(userDTO.getEmail())) {
//            return "Email is already Registered.";
//        }
//        AuthUser user = new AuthUser();
//        user.setFirstName(userDTO.getFirstName());
//        user.setLastName(userDTO.getLastName());
//        user.setEmail(userDTO.getEmail());
//        user.setPassword(encoder.encode(userDTO.getPassword()));
//
//        authUserRepository.save(user);
//        return "User registered successfully!";
//    }
////    public String login(AuthUserDTO userDTO) {
////        AuthUser user = authUserRepository.findByEmail(userDTO.getEmail());
////        if (user == null) {
////            return "User not found.";
////        }
////        if (!encoder.matches(userDTO.getPassword(), user.getPassword())) {
////            return "Invalid password.";
////        }
////        return "Login successful.";
////    }
//
//    public String login(AuthUserDTO authUserDTO) {
//        Authentication authentication = authManager.authenticate(
//                new UsernamePasswordAuthenticationToken(authUserDTO.getEmail(), authUserDTO.getPassword()));
//
//        if (authentication.isAuthenticated()) {
//            return jwtUtil.generateToken(authUserDTO.getEmail());
//        }
//        return "Authentication failed.";
//    }
//}

//package org.ajmera.greetingapp.service;
//
//import org.ajmera.greetingapp.dto.AuthUserDTO;
//import org.ajmera.greetingapp.model.AuthUser;
//import org.ajmera.greetingapp.repository.AuthUserRepository;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.stereotype.Service;
//
//@Service
//public class AuthenticationService {
//
//    private final AuthUserRepository authUserRepository;
//    private final AuthenticationManager authManager;
//    private final JwtService jwtService;
//    private final BCryptPasswordEncoder encoder;
//
//    @Autowired
//    public AuthenticationService(AuthUserRepository authUserRepository,
//                                 AuthenticationManager authManager, JwtService jwtService,
//
//                                 BCryptPasswordEncoder encoder) {
//        this.authUserRepository = authUserRepository;
//        this.authManager = authManager;
//        this.jwtService = jwtService;
//        this.jwtUtil = jwtUtil;
//        this.encoder = encoder;
//    }
//
//    public String register(AuthUserDTO userDTO) {
//        if (authUserRepository.existsByEmail(userDTO.getEmail())) {
//            return "Email is already Registered.";
//        }
//
//        AuthUser user = new AuthUser();
//        user.setFirstName(userDTO.getFirstName());
//        user.setLastName(userDTO.getLastName());
//        user.setEmail(userDTO.getEmail());
//        user.setPassword(encoder.encode(userDTO.getPassword()));
//
//        authUserRepository.save(user);
//        return "User registered successfully!";
//    }
//
//    public String login(AuthUserDTO authUserDTO) {
//        try {
//            Authentication authentication = authManager.authenticate(
//                    new UsernamePasswordAuthenticationToken(authUserDTO.getUsername(), authUserDTO.getPassword()));
//
//            return jwtService.generateToken(authUserDTO.getUsername);
//        } catch (Exception e) {
//            return "Authentication failed: " + e.getMessage();
//        }
//    }
//}


package org.ajmera.greetingapp.service;

import org.ajmera.greetingapp.dto.AuthUserDTO;
import org.ajmera.greetingapp.model.AuthUser;
import org.ajmera.greetingapp.repository.AuthUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

    private final AuthUserRepository authUserRepository;
    private final AuthenticationManager authManager;
    private final JwtService jwtService;
    private final BCryptPasswordEncoder encoder;

    @Autowired
    public AuthenticationService(AuthUserRepository authUserRepository,
                                 AuthenticationManager authManager, JwtService jwtService,
                                 BCryptPasswordEncoder encoder) {
        this.authUserRepository = authUserRepository;
        this.authManager = authManager;
        this.jwtService = jwtService;
        this.encoder = encoder;
    }

    public String register(AuthUserDTO authUserDTO) {
        if (authUserRepository.findByUsername(authUserDTO.getUsername()).isPresent()) {
            return "Username is already taken.";
        }
        AuthUser user = new AuthUser();
        user.setFirstName(authUserDTO.getFirstName());
        user.setLastName(authUserDTO.getLastName());
        user.setUsername(authUserDTO.getUsername());
        user.setEmail(authUserDTO.getEmail());
        user.setPassword(encoder.encode(authUserDTO.getPassword()));

        authUserRepository.save(user);
        return "User registered successfully!";
    }

    public String login(AuthUserDTO authUserDTO) {
        Authentication authentication = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(authUserDTO.getUsername(), authUserDTO.getPassword())
        );

        if (authentication.isAuthenticated()) {
            // Retrieve UserDetails from the authentication object
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            return jwtService.generateToken(userDetails);
        }
        return "Authentication failed.";
    }


}


