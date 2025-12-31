package com.substring.auth.authapp_backend.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.substring.auth.authapp_backend.dtos.ApiError;
import com.substring.auth.authapp_backend.security.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(
            JwtAuthenticationFilter jwtAuthenticationFilter
    ) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                // ❌ CSRF disabled (JWT based)
                .csrf(AbstractHttpConfigurer::disable)

                // 🌐 CORS
                .cors(Customizer.withDefaults())

                // ✅ OAuth2 ko session chahiye
                .sessionManagement(sm ->
                        sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                )

                // 🔐 Authorization rules
                .authorizeHttpRequests(auth -> auth
                        // 🌐 Public & OAuth2 endpoints
                        .requestMatchers(
                                "/",
                                "/login",
                                "/login/**",
                                "/oauth2/**",
                                "/login/oauth2/**",
                                "/error",
                                "/api/v1/auth/**"
                        ).permitAll()

                        // 🔒 Baaki sab secured
                        .anyRequest().authenticated()
                )

                // 🔑 OAuth2 Login (default Spring behaviour)
                .oauth2Login(oauth2 -> oauth2
                        // ✅ SUCCESS ke baad yahin bhejo
                        .defaultSuccessUrl("/login/success", true)

                        // ✅ FAILURE ke baad yahin bhejo
                        .failureUrl("/login/failure")
                )

                // ❌ Logout disable (JWT based)
                .logout(AbstractHttpConfigurer::disable)

                // ❗ Custom 401 ONLY for API requests (OAuth2 ke beech nahi)
                .exceptionHandling(ex -> ex.authenticationEntryPoint((request, response, e) -> {

                    String path = request.getRequestURI();

                    // 🔥 OAuth2 ke liye DEFAULT Spring flow
                    if (path.startsWith("/oauth2")
                            || path.startsWith("/login/oauth2")) {
                        response.sendError(HttpStatus.UNAUTHORIZED.value());
                        return;
                    }

                    // 🔐 API ke liye JSON response
                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                    response.setContentType("application/json");

                    ApiError apiError = ApiError.of(
                            HttpStatus.UNAUTHORIZED.value(),
                            "Unauthorized",
                            e.getMessage(),
                            path,
                            true
                    );

                    ObjectMapper mapper = new ObjectMapper();
                    response.getWriter()
                            .write(mapper.writeValueAsString(apiError));
                }))

                // 🪪 JWT Filter (OAuth2 se pehle SKIP ho chuka hai via shouldNotFilter)
                .addFilterBefore(
                        jwtAuthenticationFilter,
                        UsernamePasswordAuthenticationFilter.class
                );

        return http.build();
    }

    // 🔐 Password Encoder
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 🔑 Authentication Manager
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration configuration
    ) throws Exception {
        return configuration.getAuthenticationManager();
    }

    // 🌍 CORS Configuration
    @Bean
    public CorsConfigurationSource corsConfigurationSource(
            @Value("${app.cors.front-end-url}") String corsUrls
    ) {

        String[] urls = corsUrls.trim().split(",");

        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Arrays.asList(urls));
        config.setAllowedMethods(List.of(
                "GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"
        ));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source =
                new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return source;
    }
}
