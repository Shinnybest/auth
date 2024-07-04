package com.commerce.authserver.service;

import com.commerce.authserver.model.User;
import com.commerce.authserver.model.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public void signup(String username, String email, String password) {
        var encoded = passwordEncoder.encode(password);
        var user = User.builder()
                .username(username)
                .email(email)
                .password(encoded)
                .build();
        userRepository.save(user);
    }

}
