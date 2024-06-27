package com.dgmf.security.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

@Controller
public class JwtUtils {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtUtils.class);
    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;
    @Value("${spring.app.jwtExpirationMs}")
    private Integer jwtExpirationMs;

    public String getJwtFromHeader(HttpServletRequest request) {
        // Retrieve "Authorization" Header
        String bearerToken = request.getHeader("Authorization");

        // Extract and Retrieve Bearer Token
        LOGGER.debug("Authorization Header : {}", bearerToken);
        if(bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7); // Remove Bearer Prefix
        }

        return null;
    }

    public String generateTokenFromUsername(UserDetails userDetails) {
        String username = userDetails.getUsername();

        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(key())
                .compact();
    }

    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    public Boolean validateJwtToken(String authToken) {
        try {
            System.out.println("Validate");
            Jwts.parser()
                    .verifyWith((SecretKey) key())
                    .build()
                    .parseSignedClaims(authToken)
                    .getPayload()
                    .getSubject();

            return true;

        } catch(MalformedJwtException e) {
            LOGGER.error("Invalid Jwt Token : {}", e.getMessage());
        } catch(ExpiredJwtException e) {
            LOGGER.error("Jwt Token is Expired : {}", e.getMessage());
        } catch(UnsupportedJwtException e) {
            LOGGER.error("Jwt Token is Unsupported : {}", e.getMessage());
        } catch(IllegalArgumentException e) {
            LOGGER.error("Jwt Claims String is Empty : {}", e.getMessage());
        }

        return false;
    }
}
