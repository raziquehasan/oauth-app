package com.substring.auth.authapp_backend.security;

import com.substring.auth.authapp_backend.entities.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
@Getter
public class JwtService {

    private final SecretKey key;
    private final long accessTtlSeconds;
    private final long refreshTtlSeconds;
    private final String issuer;

    // ✅ FIXED PROPERTY PATHS
    public JwtService(
            @Value("${spring.security.jwt.secret}") String secret,
            @Value("${spring.security.jwt.access-ttl-seconds}") long accessTtlSeconds,
            @Value("${spring.security.jwt.refresh-ttl-seconds}") long refreshTtlSeconds,
            @Value("${spring.security.jwt.issuer}") String issuer
    ) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTtlSeconds = accessTtlSeconds;
        this.refreshTtlSeconds = refreshTtlSeconds;
        this.issuer = issuer;
    }

    // 🔐 ACCESS TOKEN
    public String generateAccessToken(User user) {
        Instant now = Instant.now();

        return Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setSubject(user.getId().toString())
                .setIssuer(issuer)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusSeconds(accessTtlSeconds)))
                .claim("email", user.getEmail())
                .claim("typ", "access")
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    // 🔄 REFRESH TOKEN
    public String generateRefreshToken(User user, String jti) {
        Instant now = Instant.now();

        return Jwts.builder()
                .setId(jti)
                .setSubject(user.getId().toString())
                .setIssuer(issuer)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusSeconds(refreshTtlSeconds)))
                .claim("typ", "refresh")
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    // 📦 PARSE TOKEN
    public Jws<Claims> parse(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token);
    }

    public boolean isAccessToken(String token) {
        return "access".equals(parse(token).getBody().get("typ"));
    }

    public boolean isRefreshToken(String token) {
        return "refresh".equals(parse(token).getBody().get("typ"));
    }

    public UUID getUserId(String token) {
        return UUID.fromString(parse(token).getBody().getSubject());
    }

    public String getJti(String token) {
        return parse(token).getBody().getId();
    }
}
