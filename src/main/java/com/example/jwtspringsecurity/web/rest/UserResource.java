package com.example.jwtspringsecurity.web.rest;

import com.example.jwtspringsecurity.domain.User;
import com.example.jwtspringsecurity.repository.UserRepository;
import com.example.jwtspringsecurity.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class UserResource {
    private final UserService userService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserResource(UserService userService, UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/register")
    public ResponseEntity<User> create(@RequestBody User user) {
      //  User resource = userService.save(user);
        String password = passwordEncoder.encode(user.getPassword());
        user.setPassword(password);
        User resource = userRepository.save(user);
        return ResponseEntity.ok(resource);
    }

    @GetMapping("/users")
    public ResponseEntity getUser() {
        return ResponseEntity.ok(userService.findAll());
    }

}
