package com.commerce.authserver.authentication;

import com.commerce.authserver.model.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        var user = userRepository.findByEmail(email);
        if (user.isPresent()) {
            return new CustomUserDetails(email, user.get().getPassword());
        } else {
            throw new RuntimeException("존재하지 않는 사용자입니다.");
        }

    }
}
