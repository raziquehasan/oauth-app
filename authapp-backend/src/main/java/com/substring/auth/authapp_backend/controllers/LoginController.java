package com.substring.auth.authapp_backend.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    @GetMapping("/login/success")
    public String loginSuccess() {
        return "LOGIN SUCCESSFUL";
    }

    @GetMapping("/login/failure")
    public String loginFailure() {
        return "LOGIN FAILED";
    }
}
