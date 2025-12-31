package com.substring.auth.authapp_backend.services;

import com.substring.auth.authapp_backend.dtos.UserDto;

public interface AuthService {

    UserDto registerUser(UserDto userDto);

}
