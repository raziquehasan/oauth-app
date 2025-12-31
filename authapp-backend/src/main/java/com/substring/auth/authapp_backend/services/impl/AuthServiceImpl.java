package com.substring.auth.authapp_backend.services.impl;

import com.substring.auth.authapp_backend.dtos.UserDto;
import com.substring.auth.authapp_backend.services.AuthService;
import com.substring.auth.authapp_backend.services.UserService;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDto registerUser(UserDto userDto) {

        // password encode
        userDto.setPassword(passwordEncoder.encode(userDto.getPassword()));

        // create user
        return userService.createUser(userDto);
    }
}
