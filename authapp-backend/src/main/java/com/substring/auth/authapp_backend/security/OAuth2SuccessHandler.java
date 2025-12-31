package com.substring.auth.authapp_backend.security;

import com.substring.auth.authapp_backend.entities.Provider;
import com.substring.auth.authapp_backend.entities.RefreshToken;
import com.substring.auth.authapp_backend.entities.User;
import com.substring.auth.authapp_backend.repositories.RefreshTokenRepository;
import com.substring.auth.authapp_backend.repositories.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final CookieService cookieService;
    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${app.auth.frontend.success-redirect}")
    private String frontEndSuccessUrl;

    @Override
    @Transactional
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {

        logger.info("OAuth2 Login Success");

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        String registrationId = "unknown";
        if (authentication instanceof OAuth2AuthenticationToken token) {
            registrationId = token.getAuthorizedClientRegistrationId();
        }

        logger.info("Provider : {}", registrationId);
        logger.debug("User attributes : {}", oAuth2User.getAttributes());

        User user;

        /* ================= USER SAVE / UPDATE ================= */

        switch (registrationId) {

            case "google" -> {
                String googleId = oAuth2User.getAttribute("sub");
                String email = oAuth2User.getAttribute("email");
                String name = oAuth2User.getAttribute("name");
                String picture = oAuth2User.getAttribute("picture");

                User newUser = User.builder()
                        .email(email)
                        .name(name)
                        .image(picture)
                        .enable(true)
                        .provider(Provider.GOOGLE)
                        .providerId(googleId)
                        .build();

                user = userRepository.findByEmail(email)
                        .orElseGet(() -> userRepository.save(newUser));
            }

            case "github" -> {
                String githubId = String.valueOf(oAuth2User.getAttribute("id"));
                String name = oAuth2User.getAttribute("login");
                String image = oAuth2User.getAttribute("avatar_url");
                String email = oAuth2User.getAttribute("email");

                if (email == null || email.isBlank()) {
                    email = githubId + "@users.noreply.github.com";
                }


                User newUser = User.builder()
                        .email(email)
                        .name(name)
                        .image(image)
                        .enable(true)
                        .provider(Provider.GITHUB)
                        .providerId(githubId)
                        .build();

                user = userRepository.findByEmail(email)
                        .orElseGet(() -> userRepository.save(newUser));
            }

            default -> throw new RuntimeException("Unsupported OAuth2 provider");
        }

        /* ================= ACCESS TOKEN ================= */

        String accessToken = jwtService.generateAccessToken(user);

        /* ================= REFRESH TOKEN ================= */

        String jti = UUID.randomUUID().toString();

        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .jti(jti)
                .user(user)
                .revoked(false)
                .createdAt(Instant.now())
                .expiresAt(
                        Instant.now().plusSeconds(
                                jwtService.getRefreshTtlSeconds()
                        )
                )
                .build();

        refreshTokenRepository.save(refreshTokenEntity);

        String refreshToken = jwtService.generateRefreshToken(user, jti);

        cookieService.attachRefreshCookie(
                response,
                refreshToken,
                (int) jwtService.getRefreshTtlSeconds()
        );

        /* ================= SEND ACCESS TOKEN ================= */

        // Option 1️⃣: Access token in response header (RECOMMENDED)
        response.setHeader("Authorization", "Bearer " + accessToken);

        // Option 2️⃣: Access token as URL param (easy frontend handling)
        String redirectUrl = frontEndSuccessUrl + "?token=" + accessToken;

        logger.info("Redirecting to frontend: {}", redirectUrl);

        response.sendRedirect(redirectUrl);
    }
}
