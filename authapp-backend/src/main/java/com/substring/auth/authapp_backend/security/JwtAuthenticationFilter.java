package com.substring.auth.authapp_backend.security;

import com.substring.auth.authapp_backend.helpers.UserHelper;
import com.substring.auth.authapp_backend.repositories.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    private static final Logger logger =
            LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String header = request.getHeader("Authorization");

        // ✅ Agar token hi nahi hai, simply next filter
        if (header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = header.substring(7);

        try {
            // ✅ Sirf ACCESS token allow
            if (!jwtService.isAccessToken(token)) {
                filterChain.doFilter(request, response);
                return;
            }

            // ✅ Parse JWT
            Jws<Claims> parsed = jwtService.parse(token);
            Claims claims = parsed.getBody();

            UUID userId = UserHelper.parseUUID(claims.getSubject());

            // ✅ Authenticate user
            userRepository.findById(userId).ifPresent(user -> {

                if (!user.isEnable()) {
                    return;
                }

                if (SecurityContextHolder.getContext()
                        .getAuthentication() != null) {
                    return;
                }

                List<GrantedAuthority> authorities =
                        user.getRoles() == null
                                ? List.of()
                                : user.getRoles()
                                .stream()
                                .map(role ->
                                        new SimpleGrantedAuthority(
                                                role.getName()
                                        )
                                )
                                .collect(Collectors.toList());

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                user.getEmail(),
                                null,
                                authorities
                        );

                authentication.setDetails(
                        new WebAuthenticationDetailsSource()
                                .buildDetails(request)
                );

                SecurityContextHolder.getContext()
                        .setAuthentication(authentication);
            });

        } catch (ExpiredJwtException e) {
            logger.warn("JWT expired");
            request.setAttribute("error", "Token Expired");
        } catch (Exception e) {
            logger.warn("JWT invalid");
            request.setAttribute("error", "Invalid Token");
        }

        filterChain.doFilter(request, response);
    }

    /**
     * 🔥 MOST IMPORTANT METHOD
     * OAuth2 & public endpoints ko JWT filter se completely exclude karta hai
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {

        String path = request.getRequestURI();

        return
                // 🔐 OAuth2 endpoints
                path.startsWith("/oauth2/")
                        || path.startsWith("/login/oauth2/")

                        // 🌐 Public / auth APIs
                        || path.startsWith("/api/v1/auth")

                        // 🧯 Error & login
                        || path.startsWith("/error")
                        || path.equals("/login")
                        || path.equals("/");
    }
}
