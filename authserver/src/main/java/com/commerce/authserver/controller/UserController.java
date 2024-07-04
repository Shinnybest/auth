package com.commerce.authserver.controller;

import com.commerce.authserver.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/signup")
    public ResponseEntity signup(@RequestParam("email") String email,
                                 @RequestParam("username") String username,
                                 @RequestParam("password") String password) {
        userService.signup(username, email, password);
        return ResponseEntity.ok().build();
    }
}
