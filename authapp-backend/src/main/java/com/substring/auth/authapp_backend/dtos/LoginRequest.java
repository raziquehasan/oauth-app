package com.substring.auth.authapp_backend.dtos;

public record LoginRequest(
        String email,
        String password
) {
}
