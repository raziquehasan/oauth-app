package com.substring.auth.authapp_backend.services.impl;

import com.substring.auth.authapp_backend.dtos.UserDto;
import com.substring.auth.authapp_backend.entities.Provider;
import com.substring.auth.authapp_backend.entities.User;
import com.substring.auth.authapp_backend.exceptions.ResourceNotFoundException;
import com.substring.auth.authapp_backend.helpers.UserHelper;
import com.substring.auth.authapp_backend.repositories.UserRepository;
import com.substring.auth.authapp_backend.services.UserService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final ModelMapper modelMapper;

    @Override
    @Transactional
    public UserDto createUser(UserDto userDto) {

        if (userDto.getEmail() == null || userDto.getEmail().isBlank()) {
            throw new IllegalArgumentException("Email is required");
        }

        if (userRepository.existsByEmail(userDto.getEmail())) {
            throw new IllegalArgumentException("User with given email already exists");
        }

        User user = modelMapper.map(userDto, User.class);

        user.setProvider(
                userDto.getProvider() != null
                        ? userDto.getProvider()
                        : Provider.LOCAL
        );

        // TODO: assign default role (ROLE_USER)

        User savedUser = userRepository.save(user);

        return modelMapper.map(savedUser, UserDto.class);
    }

    @Override
    public UserDto getUserByEmail(String email) {

        User user = userRepository
                .findByEmail(email)
                .orElseThrow(() ->
                        new ResourceNotFoundException("User not found with given email")
                );

        return modelMapper.map(user, UserDto.class);
    }

    @Override
    public UserDto updateUser(UserDto userDto, String userId) {

        UUID uId = UserHelper.parseUUID(userId);

        User existingUser = userRepository
                .findById(uId)
                .orElseThrow(() ->
                        new ResourceNotFoundException("User not found with given id")
                );

        if (userDto.getName() != null)
            existingUser.setName(userDto.getName());

        if (userDto.getImage() != null)
            existingUser.setImage(userDto.getImage());

        if (userDto.getProvider() != null)
            existingUser.setProvider(userDto.getProvider());

        // TODO: password encryption later
        if (userDto.getPassword() != null)
            existingUser.setPassword(userDto.getPassword());

        existingUser.setEnable(userDto.isEnable());
        existingUser.setUpdatedAt(Instant.now());

        User updatedUser = userRepository.save(existingUser);

        return modelMapper.map(updatedUser, UserDto.class);
    }

    @Override
    public void deleteUser(String userId) {

        UUID uId = UserHelper.parseUUID(userId);

        User user = userRepository
                .findById(uId)
                .orElseThrow(() ->
                        new ResourceNotFoundException("User not found with given id")
                );

        userRepository.delete(user);
    }

    @Override
    public UserDto getUserById(String userId) {

        User user = userRepository
                .findById(UserHelper.parseUUID(userId))
                .orElseThrow(() ->
                        new ResourceNotFoundException("User not found with given id")
                );

        return modelMapper.map(user, UserDto.class);
    }

    @Override
    @Transactional
    public Iterable<UserDto> getAllUsers() {

        return userRepository
                .findAll()
                .stream()
                .map(user -> modelMapper.map(user, UserDto.class))
                .toList();
    }
}
